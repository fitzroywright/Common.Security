namespace Common.Security.Plugin.ActiveDirectory;

using Common.Security.Abstractions;
using Common.Security.Models;
using System.DirectoryServices.Protocols;
using System.Net;

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
        LdapDirectoryIdentifier identifier = new(server, options.Port, true, false);
        using LdapConnection connection = new(identifier, CredentialCache.DefaultNetworkCredentials, AuthType.Negotiate)
        {
            Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds)
        };
        connection.SessionOptions.ProtocolVersion = 3;
        connection.SessionOptions.SecureSocketLayer = true;
        connection.Bind();

        string filter = loginNames.Count == 1
            ? $"(&(objectCategory=person)(objectClass=user)(sAMAccountName={LdapFilterEscaper.Escape(loginNames.Single())}))"
            : $"(&(objectCategory=person)(objectClass=user)(|{string.Concat(loginNames.Select(value => $"(sAMAccountName={LdapFilterEscaper.Escape(value)}"))}))";

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
