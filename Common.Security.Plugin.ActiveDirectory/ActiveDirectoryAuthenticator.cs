namespace Common.Security.Plugin.ActiveDirectory;

using Common.Security.Abstractions;
using Common.Security.Models;
using Common.Security.Services.Functions;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.Net;

public sealed class ActiveDirectoryAuthenticator : IAuthenticator
{
    private static readonly string[] AuthenticationAttributes =
    [
        "title", "displayName", "department", "mail", "manager", "telephoneNumber",
        "otherTelephone", "mobile", "otherMobile", "thumbnailPhoto", "userAccountControl", "memberOf"
    ];

    private readonly ActiveDirectoryAuthenticationOptions options;
    private readonly string[] servers;
    private readonly string[] administrativeGroupPatterns;
    private volatile string? preferredServer;

    public ActiveDirectoryAuthenticator(ActiveDirectoryAuthenticationOptions options)
    {
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        Validate(options);
        servers = options.Servers.Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        administrativeGroupPatterns = options.AdministrativeGroups.Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => $"CN={x.Trim()},").Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public AuthenticationResult Authenticate(string loginName, string password)
    {
        if (string.IsNullOrWhiteSpace(loginName) || string.IsNullOrWhiteSpace(password))
            return Failed();

        string userName = UserNameNormalizer.GetUserNameWithoutDomain(loginName);
        if (string.IsNullOrWhiteSpace(userName)) return Failed();

        using LdapConnection? connection = GetConnection(userName, password);
        if (connection is null) return Failed();

        SearchResultEntry? userEntry = SearchDirectory(connection, options.SearchBase, userName, AuthenticationAttributes);
        if (userEntry is null) return Failed();

        ApplicationUserInfo userInfo = new();
        PopulateUserInfo(userEntry, userInfo);
        return new AuthenticationResult
        {
            IsAuthenticated = true,
            IsAdministrative = IsAdministrative(userEntry),
            UserInfo = userInfo,
            GroupNames = GetGroupNames(userEntry)
        };
    }

    private LdapConnection? GetConnection(string loginName, string password)
    {
        string userName = UserNameNormalizer.GetUserNameWithoutDomain(loginName);
        string upn = $"{userName}@{options.Domain}";
        string? previous = preferredServer;

        foreach (string server in PreferredServers())
        {
            LdapConnection? connection = null;
            try
            {
                LdapDirectoryIdentifier identifier = new(server, options.Port, true, false);
                connection = new LdapConnection(identifier, new NetworkCredential(upn, password), AuthType.Basic)
                {
                    Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds)
                };
                connection.SessionOptions.ProtocolVersion = 3;
                connection.SessionOptions.SecureSocketLayer = true;
                connection.Bind();

                if (!string.IsNullOrWhiteSpace(previous) && !server.Equals(previous, StringComparison.OrdinalIgnoreCase))
                    Trace.TraceWarning("Active Directory failover occurred. PreviousServer={0}, ActiveServer={1}", previous, server);

                preferredServer = server;
                return connection;
            }
            catch (LdapException ex) when (ex.ErrorCode == 49)
            {
                connection?.Dispose();
                return null;
            }
            catch (Exception ex) when (ex is LdapException or TimeoutException)
            {
                connection?.Dispose();
                Trace.TraceWarning("Active Directory server failed. Server={0}. Trying next configured server. {1}", server, ex);
            }
        }
        return null;
    }

    private IEnumerable<string> PreferredServers()
    {
        string? preferred = preferredServer;
        if (!string.IsNullOrWhiteSpace(preferred))
        {
            string? configured = servers.FirstOrDefault(x => x.Equals(preferred, StringComparison.OrdinalIgnoreCase));
            if (configured is not null) yield return configured;
        }
        foreach (string server in servers)
            if (!server.Equals(preferred, StringComparison.OrdinalIgnoreCase)) yield return server;
    }

    private static SearchResultEntry? SearchDirectory(LdapConnection connection, string searchBase, string loginName, string[] attributes)
    {
        string escaped = LdapFilterEscaper.Escape(UserNameNormalizer.GetUserNameWithoutDomain(loginName));
        try
        {
            SearchRequest request = new(searchBase, $"(sAMAccountName={escaped})", SearchScope.Subtree, attributes);
            SearchResponse response = (SearchResponse)connection.SendRequest(request);
            return response.Entries.Count == 0 ? null : response.Entries[0];
        }
        catch (Exception ex) when (ex is LdapException or DirectoryOperationException)
        {
            Trace.TraceError("Active Directory LDAP search failed. UserName={0}. {1}", loginName, ex);
            return null;
        }
    }

    private bool IsAdministrative(SearchResultEntry entry)
    {
        if (administrativeGroupPatterns.Length == 0 || !entry.Attributes.Contains("memberOf")) return false;
        IEnumerable<string> memberOf = entry.Attributes["memberOf"].GetValues(typeof(string)).Cast<string>();
        return memberOf.Any(groupDn => administrativeGroupPatterns.Any(pattern =>
            groupDn.StartsWith(pattern, StringComparison.OrdinalIgnoreCase)));
    }

    private static IReadOnlyList<string> GetGroupNames(SearchResultEntry entry)
    {
        if (!entry.Attributes.Contains("memberOf")) return [];
        return entry.Attributes["memberOf"].GetValues(typeof(string)).Cast<string>()
            .Select(GetGroupCn).Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static string GetGroupCn(string distinguishedName)
    {
        try { return Rfc4514Parser.Parse(distinguishedName).GetValues("CN").FirstOrDefault()?.Trim() ?? string.Empty; }
        catch (FormatException) { return string.Empty; }
    }

    private static void PopulateUserInfo(SearchResultEntry entry, ApplicationUserInfo user)
    {
        foreach (string attributeName in entry.Attributes.AttributeNames)
        {
            DirectoryAttribute attribute = entry.Attributes[attributeName];
            if (attributeName.Equals("thumbnailPhoto", StringComparison.OrdinalIgnoreCase))
            {
                user.Photo = attribute.GetValues(typeof(byte[])).Cast<byte[]>().FirstOrDefault();
                continue;
            }
            string? value = attribute.GetValues(typeof(string)).Cast<string>().FirstOrDefault();
            if (string.IsNullOrWhiteSpace(value)) continue;
            switch (attributeName.ToLowerInvariant())
            {
                case "department": user.Department = value; break;
                case "displayname": user.DisplayName = value; break;
                case "mail": user.Mail = value; break;
                case "manager":
                    try { user.Manager = Rfc4514Parser.Parse(value).GetValues("CN").FirstOrDefault()?.Trim() ?? string.Empty; }
                    catch (FormatException) { user.Manager = string.Empty; }
                    break;
                case "mobile": user.Mobile = value; break;
                case "othermobile": user.OtherMobile = value; break;
                case "othertelephone": user.OtherTelephoneNumber = value; break;
                case "telephonenumber": user.TelephoneNumber = value; break;
                case "title": user.Title = value; break;
                case "useraccountcontrol": user.UserAccountControl = long.TryParse(value, out long parsed) ? parsed : 0; break;
            }
        }
    }

    private static void Validate(ActiveDirectoryAuthenticationOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.Domain)) throw new ArgumentException("Domain must be configured.", nameof(options));
        if (string.IsNullOrWhiteSpace(options.SearchBase)) throw new ArgumentException("SearchBase must be configured.", nameof(options));
        if (options.Servers is null || options.Servers.Count == 0 || options.Servers.All(string.IsNullOrWhiteSpace))
            throw new ArgumentException("At least one directory server must be configured.", nameof(options));
        if (options.Port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(options.Port));
        if (options.TimeoutSeconds <= 0) throw new ArgumentOutOfRangeException(nameof(options.TimeoutSeconds));
    }

    private static AuthenticationResult Failed() => new()
    {
        IsAuthenticated = false,
        IsAdministrative = false,
        UserInfo = null,
        GroupNames = []
    };
}
