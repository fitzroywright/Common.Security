namespace Common.Security.Plugin.ActiveDirectory;

using Common.Security.Abstractions;
using Common.Security.Models;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Diagnostics;
using System.Text;

public sealed class ActiveDirectoryDirectoryProfileProvider(
    ActiveDirectoryAuthenticationOptions options) : IDirectoryProfileProvider
{
    private readonly string[] servers = options.Servers
        .Where(value => !string.IsNullOrWhiteSpace(value))
        .Select(value => value.Trim())
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();

    public Task<IReadOnlyDictionary<string, DirectoryUserProfile>> GetByLoginNamesAsync(
        IEnumerable<string> loginNames,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        string[] requested = loginNames
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(NormalizeLoginName)
            .Where(value => value.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (requested.Length == 0)
            return Task.FromResult<IReadOnlyDictionary<string, DirectoryUserProfile>>(
                new Dictionary<string, DirectoryUserProfile>(StringComparer.OrdinalIgnoreCase));

        Exception? lastException = null;
        foreach (string server in servers)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return Task.FromResult<IReadOnlyDictionary<string, DirectoryUserProfile>>(
                    ReadFromServer(server, requested));
            }
            catch (Exception exception) when (exception is LdapException or DirectoryOperationException or InvalidOperationException)
            {
                lastException = exception;
            }
        }

        throw new InvalidOperationException(
            "Unable to query the configured directory provider.",
            lastException);
    }

    private IReadOnlyDictionary<string, DirectoryUserProfile> ReadFromServer(
        string server,
        IReadOnlyCollection<string> loginNames)
    {
        if (OperatingSystem.IsLinux())
            return ReadFromLinuxLdapSearch(server, loginNames);

        LdapDirectoryIdentifier identifier = new(server, options.Port, true, false);
        // Linux has no Windows logon token to supply as DefaultNetworkCredentials.
        // Use the service's Kerberos ticket cache (KRB5CCNAME) for SASL/GSSAPI.
        // Preserve Windows integrated Negotiate authentication.
        using LdapConnection connection = OperatingSystem.IsWindows()
            ? new LdapConnection(identifier, CredentialCache.DefaultNetworkCredentials, AuthType.Negotiate)
            : new LdapConnection(identifier) { AuthType = AuthType.Kerberos };
        connection.Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds);
        connection.SessionOptions.ProtocolVersion = 3;
        connection.SessionOptions.SecureSocketLayer = true;
        // Do not set SessionOptions.Signing/Sealing on Linux: OpenLDAP rejects
        // those options with LDAP_SERVER_DOWN before bind. SASL security-layer
        // negotiation is configured through OpenLDAP's SASL_SECPROPS setting
        // (for LDAPS, maxssf=0), not these .NET session properties.
        connection.Bind();

        string filter = BuildSearchFilter(loginNames);

        SearchRequest request = new(
            options.SearchBase,
            filter,
            SearchScope.Subtree,
            "sAMAccountName",
            "displayName",
            "mail",
            "department",
            "ipPhone",
            "telephoneNumber",
            "manager",
            "memberOf");

        SearchResponse response = (SearchResponse)connection.SendRequest(request);
        Dictionary<string, DirectoryUserProfile> result = new(StringComparer.OrdinalIgnoreCase);

        foreach (SearchResultEntry entry in response.Entries)
        {
            string loginName = ReadString(entry, "sAMAccountName");
            if (loginName.Length == 0) continue;

            string normalized = NormalizeLoginName(loginName);
            string extension = FirstNonBlank(ReadString(entry, "ipPhone"), ReadString(entry, "telephoneNumber"));
            string manager = ResolveManagerDisplayName(connection, ReadString(entry, "manager"));
            string[] groups = ReadStrings(entry, "memberOf")
                .Select(GetGroupName)
                .Where(value => value.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            result[normalized] = new DirectoryUserProfile(
                normalized,
                ReadString(entry, "displayName"),
                ReadString(entry, "mail"),
                ReadString(entry, "department"),
                extension,
                manager,
                groups);
        }

        return result;
    }


    // The native .NET LDAP client can negotiate a GSSAPI security layer on Linux
    // that is incompatible with the LDAPS response stream. Use the same tested
    // OpenLDAP GSSAPI/maxssf=0 path as the service account's ldapsearch probe.
    // ProcessStartInfo.ArgumentList avoids shell interpretation of LDAP filters.
    private IReadOnlyDictionary<string, DirectoryUserProfile> ReadFromLinuxLdapSearch(
        string server, IReadOnlyCollection<string> loginNames)
    {
        string filter = BuildSearchFilter(loginNames);
        List<string> args = new()
        {
            "-LLL", "-o", "ldif-wrap=no", "-Y", "GSSAPI",
            "-O", "maxssf=0", "-H", $"ldaps://{server}:{options.Port}",
            "-b", options.SearchBase, filter,
            "sAMAccountName", "displayName", "mail", "department",
            "ipPhone", "telephoneNumber", "manager", "memberOf"
        };
        string output = RunLdapSearch(args);
        Dictionary<string, DirectoryUserProfile> result = new(StringComparer.OrdinalIgnoreCase);
        foreach (Dictionary<string, List<string>> attributes in ParseLdif(output))
        {
            string loginName = Value(attributes, "sAMAccountName");
            if (loginName.Length == 0) continue;
            string normalized = NormalizeLoginName(loginName);
            string manager = Value(attributes, "manager");
            string managerName = string.Empty;
            if (manager.Length > 0)
            {
                try
                {
                    string managerOutput = RunLdapSearch(new List<string>
                    {
                        "-LLL", "-o", "ldif-wrap=no", "-Y", "GSSAPI",
                        "-O", "maxssf=0", "-H", $"ldaps://{server}:{options.Port}",
                        "-b", manager, "-s", "base", "(objectClass=*)", "displayName"
                    });
                    managerName = ParseLdif(managerOutput)
                        .Select(entry => Value(entry, "displayName"))
                        .FirstOrDefault() ?? string.Empty;
                }
                catch (InvalidOperationException)
                {
                    // Manager metadata is optional; retain the employee record.
                }
            }

            string[] groups = attributes.GetValueOrDefault("memberOf", new List<string>())
                .Select(GetGroupName)
                .Where(value => value.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            result[normalized] = new DirectoryUserProfile(
                normalized,
                Value(attributes, "displayName"),
                Value(attributes, "mail"),
                Value(attributes, "department"),
                FirstNonBlank(Value(attributes, "ipPhone"), Value(attributes, "telephoneNumber")),
                managerName, groups);
        }
        return result;
    }

    private string RunLdapSearch(IReadOnlyList<string> arguments)
    {
        using Process process = new();
        process.StartInfo = new ProcessStartInfo("ldapsearch")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (string argument in arguments)
            process.StartInfo.ArgumentList.Add(argument);
        try
        {
            process.Start();
            Task<string> stdout = process.StandardOutput.ReadToEndAsync();
            Task<string> stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(checked(options.TimeoutSeconds * 1000)))
            {
                process.Kill(entireProcessTree: true);
                throw new InvalidOperationException("LDAP search timed out.");
            }
            string output = stdout.GetAwaiter().GetResult();
            string error = stderr.GetAwaiter().GetResult();
            if (process.ExitCode != 0)
                throw new InvalidOperationException(
                    $"LDAP search exited with code {process.ExitCode}: {error.Trim()}");
            return output;
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            throw new InvalidOperationException(
                "The Linux LDAP profile provider requires the ldapsearch executable (ldap-utils).", ex);
        }
    }

    internal static IReadOnlyList<Dictionary<string, List<string>>> ParseLdif(string ldif)
    {
        List<Dictionary<string, List<string>>> entries = new();
        Dictionary<string, List<string>> current = new(StringComparer.OrdinalIgnoreCase);
        string? previousKey = null;
        foreach (string line in ldif.Replace("\r\n", "\n").Split('\n'))
        {
            if (line.Length == 0)
            {
                if (current.Count > 0) entries.Add(current);
                current = new(StringComparer.OrdinalIgnoreCase);
                previousKey = null;
                continue;
            }
            if (line[0] == ' ' && previousKey != null &&
                current.TryGetValue(previousKey, out List<string>? values) && values.Count > 0)
            {
                values[^1] += line[1..];
                continue;
            }
            if (line[0] == '#') continue;
            int separator = line.IndexOf(':');
            if (separator <= 0) continue;
            string key = line[..separator];
            bool base64 = separator + 1 < line.Length && line[separator + 1] == ':';
            string value = line[(separator + (base64 ? 2 : 1))..].TrimStart(' ');
            if (base64) value = Encoding.UTF8.GetString(Convert.FromBase64String(value));
            if (!current.TryGetValue(key, out List<string>? list))
                current[key] = list = new List<string>();
            list.Add(value);
            previousKey = key;
        }
        if (current.Count > 0) entries.Add(current);
        return entries;
    }

    private static string Value(Dictionary<string, List<string>> attributes, string key)
        => attributes.TryGetValue(key, out List<string>? values)
            ? values.FirstOrDefault() ?? string.Empty : string.Empty;

    internal static string BuildSearchFilter(IReadOnlyCollection<string> loginNames)
    {
        ArgumentNullException.ThrowIfNull(loginNames);
        if (loginNames.Count == 0)
            throw new ArgumentException("At least one login name is required.", nameof(loginNames));

        return loginNames.Count == 1
            ? $"(&(objectCategory=person)(objectClass=user)(sAMAccountName={LdapFilterEscaper.Escape(loginNames.Single())}))"
            : $"(&(objectCategory=person)(objectClass=user)(|{string.Concat(loginNames.Select(value => $"(sAMAccountName={LdapFilterEscaper.Escape(value)})"))}))";
    }

    private static string ResolveManagerDisplayName(LdapConnection connection, string distinguishedName)
    {
        if (string.IsNullOrWhiteSpace(distinguishedName)) return string.Empty;
        try
        {
            SearchRequest request = new(distinguishedName, "(objectClass=*)", SearchScope.Base, "displayName");
            SearchResponse response = (SearchResponse)connection.SendRequest(request);
            return response.Entries.Count == 0 ? string.Empty : ReadString(response.Entries[0], "displayName");
        }
        catch (LdapException)
        {
            return string.Empty;
        }
    }

    private static string ReadString(SearchResultEntry entry, string attributeName)
        => ReadStrings(entry, attributeName).FirstOrDefault() ?? string.Empty;

    private static IEnumerable<string> ReadStrings(SearchResultEntry entry, string attributeName)
    {
        if (!entry.Attributes.Contains(attributeName)) yield break;
        foreach (object value in entry.Attributes[attributeName])
        {
            string text = value switch
            {
                byte[] bytes => System.Text.Encoding.UTF8.GetString(bytes),
                _ => Convert.ToString(value) ?? string.Empty
            };
            if (!string.IsNullOrWhiteSpace(text)) yield return text.Trim();
        }
    }

    private static string GetGroupName(string distinguishedName)
    {
        try
        {
            return Rfc4514Parser.Parse(distinguishedName)
                .GetValues("CN")
                .FirstOrDefault()?.Trim() ?? string.Empty;
        }
        catch (FormatException)
        {
            return string.Empty;
        }
    }

    private static string NormalizeLoginName(string value)
    {
        string loginName = value.Trim();
        int slash = loginName.LastIndexOf('\\');
        if (slash >= 0 && slash < loginName.Length - 1) loginName = loginName[(slash + 1)..];
        int at = loginName.IndexOf('@');
        if (at > 0) loginName = loginName[..at];
        return loginName.Trim().ToLowerInvariant();
    }

    private static string FirstNonBlank(string first, string second)
        => string.IsNullOrWhiteSpace(first) ? second : first;
}
