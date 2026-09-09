namespace Common.Security.Authenticators
{
    using Common.Security.Abstractions;
    using Common.Security.Models;
    using Common.Security.Options;
    using Common.Security.Services.Extensions;
    using Common.Security.Services.Functions;
    using System.Diagnostics;
    using System.DirectoryServices.Protocols;
    using System.Net;

    public sealed class ActiveDirectory : IAuthenticator
    {
        private static readonly string[] ADAuthenticationAttributes = ["title", "displayName", "department", "mail", "manager", "telephoneNumber", "otherTelephone", "mobile", "otherMobile", "thumbnailPhoto", "userAccountControl", "memberOf"];
        private readonly ActiveDirectoryAuthenticationOptions options;
        private readonly string[] servers;
        private readonly string[] administrativeGroupPatterns;
        private volatile string? preferredServer;

        public ActiveDirectory(ActiveDirectoryAuthenticationOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);
            ValidateOptions(options);
            this.options = options;
            servers = options.Servers.Where(server => !string.IsNullOrWhiteSpace(server)).Select(server => server.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            administrativeGroupPatterns = options.AdministrativeGroups.Where(group => !string.IsNullOrWhiteSpace(group)).Select(CreateGroupDnPattern).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }

        public AuthenticationResult Authenticate(string loginName, string password)
        {
            if (string.IsNullOrWhiteSpace(loginName) || string.IsNullOrWhiteSpace(password)) return AuthenticationFailed();
            string userName = UserNameNormalizer.GetUserNameWithoutDomain(loginName);
            if (string.IsNullOrWhiteSpace(userName)) return AuthenticationFailed();
            using LdapConnection? connection = GetLdapConnection(userName, password);
            if (connection == null) return AuthenticationFailed();
            return BuildAuthenticationResult(connection, userName);
        }

        private AuthenticationResult BuildAuthenticationResult(LdapConnection connection, string userName)
        {
            SearchResultEntry? userEntry = SearchDirectory(connection, options.SearchBase, userName, ADAuthenticationAttributes);
            if (userEntry == null) return AuthenticationFailed();
            var userInfo = new ApplicationUserInfo();
            PopulateUserInfo(userEntry, userInfo);
            bool isAdministrative = IsAdministrative(userEntry);
            IReadOnlyList<string> groupNames = GetGroupNames(userEntry);
            return new AuthenticationResult
            {
                IsAuthenticated = true,
                IsAdministrative = isAdministrative,
                UserInfo = userInfo,
                GroupNames = groupNames
            };
        }

        private LdapConnection? GetLdapConnection(string loginName, string password)
        {
            string userName = UserNameNormalizer.GetUserNameWithoutDomain(loginName);
            string userPrincipalName = $"{userName}@{options.Domain}";
            string? previousPreferredServer = preferredServer;
            foreach (string server in GetServersInPreferredOrder())
            {
                LdapConnection? connection = null;
                try
                {
                    connection = CreateConnection(server, userPrincipalName, password);
                    connection.Bind();
                    if (!string.IsNullOrWhiteSpace(previousPreferredServer) && !server.Equals(previousPreferredServer, StringComparison.OrdinalIgnoreCase))
                        Trace.TraceWarning("Active Directory failover occurred. PreviousServer={0}, ActiveServer={1}", previousPreferredServer, server);
                    preferredServer = server;
                    return connection;
                }
                catch (LdapException exception) when (IsInvalidCredentials(exception))
                {
                    connection?.Dispose();
                    return null;
                }
                catch (LdapException exception)
                {
                    connection?.Dispose();
                    Trace.TraceWarning("Active Directory server failed. Server={0}. Trying next configured server. {1}", server, exception);
                }
                catch (TimeoutException exception)
                {
                    connection?.Dispose();
                    Trace.TraceWarning("Active Directory server timed out. Server={0}. Trying next configured server. {1}", server, exception);
                }
                catch { connection?.Dispose(); throw; }
            }
            return null;
        }

        private LdapConnection CreateConnection(string server, string userPrincipalName, string password)
        {
            var identifier = new LdapDirectoryIdentifier(server, options.Port, fullyQualifiedDnsHostName: true, connectionless: false);
            var credential = new NetworkCredential(userPrincipalName, password);
            var connection = new LdapConnection(identifier, credential, AuthType.Basic) { Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds) };
            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.SecureSocketLayer = true;
            return connection;
        }

        private IEnumerable<string> GetServersInPreferredOrder()
        {
            string? preferred = preferredServer;
            if (!string.IsNullOrWhiteSpace(preferred))
            {
                string? configuredPreferred = servers.FirstOrDefault(server => server.Equals(preferred, StringComparison.OrdinalIgnoreCase));
                if (configuredPreferred != null) yield return configuredPreferred;
            }
            foreach (string server in servers) if (!server.Equals(preferred, StringComparison.OrdinalIgnoreCase)) yield return server;
        }

        private SearchResultEntry? SearchDirectory(LdapConnection connection, string searchBase, string loginName, string[] attributes)
        {
            string userName = UserNameNormalizer.GetUserNameWithoutDomain(loginName);
            string escapedUserName = LdapFilterEscaper.Escape(userName);
            try
            {
                var request = new SearchRequest(searchBase, $"(sAMAccountName={escapedUserName})", SearchScope.Subtree, attributes);
                var response = (SearchResponse)connection.SendRequest(request);
                return response.Entries.Count == 0 ? null : response.Entries[0];
            }
            catch (LdapException exception) { Trace.TraceError("Active Directory LDAP search failed. UserName={0}. {1}", userName, exception); return null; }
            catch (DirectoryOperationException exception) { Trace.TraceError("Active Directory directory operation failed. UserName={0}. {1}", userName, exception); return null; }
        }

        private bool IsAdministrative(SearchResultEntry userEntry)
        {
            if (administrativeGroupPatterns.Length == 0 || !userEntry.Attributes.Contains("memberOf")) return false;
            IEnumerable<string> memberOf = userEntry.Attributes["memberOf"].GetValues(typeof(string)).Cast<string>();
            return memberOf.Any(groupDn => administrativeGroupPatterns.Any(pattern => groupDn.StartsWith(pattern, StringComparison.OrdinalIgnoreCase)));
        }

        private static IReadOnlyList<string> GetGroupNames(SearchResultEntry userEntry)
        {
            if (!userEntry.Attributes.Contains("memberOf")) return [];

            return userEntry.Attributes["memberOf"]
                .GetValues(typeof(string))
                .Cast<string>()
                .Select(GetGroupCn)
                .Where(group => !string.IsNullOrWhiteSpace(group))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(group => group, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        private static string GetGroupCn(string distinguishedName)
        {
            if (string.IsNullOrWhiteSpace(distinguishedName)) return string.Empty;
            try
            {
                return Rfc4514Parser.Parse(distinguishedName).GetValues("CN").FirstOrDefault()?.Trim() ?? string.Empty;
            }
            catch (FormatException)
            {
                return string.Empty;
            }
        }

        private static void PopulateUserInfo(SearchResultEntry userEntry, ApplicationUserInfo user)
        {
            foreach (string attributeName in userEntry.Attributes.AttributeNames)
            {
                DirectoryAttribute attribute = userEntry.Attributes[attributeName];
                if (attributeName.Equals("thumbnailPhoto", StringComparison.OrdinalIgnoreCase)) { user.Photo = attribute.GetValues(typeof(byte[])).Cast<byte[]>().FirstOrDefault(); continue; }
                string? value = attribute.GetValues(typeof(string)).Cast<string>().FirstOrDefault();
                if (string.IsNullOrWhiteSpace(value)) continue;
                switch (attributeName.ToLowerInvariant())
                {
                    case "department": user.Department = value; break;
                    case "displayname": user.DisplayName = value; break;
                    case "mail": user.Mail = value; break;
                    case "manager": user.Manager = GetManagerCn(value).NormalizeWhitespace(); break;
                    case "mobile": user.Mobile = value; break;
                    case "othermobile": user.OtherMobile = value; break;
                    case "othertelephone": user.OtherTelephoneNumber = value; break;
                    case "telephonenumber": user.TelephoneNumber = value; break;
                    case "title": user.Title = value; break;
                    case "useraccountcontrol": user.UserAccountControl = long.TryParse(value, out long parsed) ? parsed : 0; break;
                }
            }
        }

        private static string GetManagerCn(string managerValue)
        {
            if (string.IsNullOrWhiteSpace(managerValue)) return string.Empty;
            try { return Rfc4514Parser.Parse(managerValue).GetValues("CN").FirstOrDefault()?.Trim() ?? string.Empty; }
            catch (FormatException) { return string.Empty; }
        }

        private static string CreateGroupDnPattern(string groupName) => $"CN={groupName.Trim()},";
        private static bool IsInvalidCredentials(LdapException exception) => exception.ErrorCode == 49;
        private static AuthenticationResult AuthenticationFailed() => new() { IsAuthenticated = false, IsAdministrative = false, UserInfo = null, GroupNames = [] };

        private static void ValidateOptions(ActiveDirectoryAuthenticationOptions options)
        {
            if (string.IsNullOrWhiteSpace(options.Domain)) throw new ArgumentException("Active Directory domain must be configured.", nameof(options));
            if (string.IsNullOrWhiteSpace(options.SearchBase)) throw new ArgumentException("Active Directory search base must be configured.", nameof(options));
            if (options.Servers is null || options.Servers.Count == 0 || options.Servers.All(string.IsNullOrWhiteSpace)) throw new ArgumentException("At least one valid Active Directory server must be configured.", nameof(options));
            if (options.Port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(options), options.Port, "Active Directory port must be between 1 and 65535.");
            if (options.TimeoutSeconds <= 0) throw new ArgumentOutOfRangeException(nameof(options), options.TimeoutSeconds, "Active Directory timeout must be greater than zero.");
            if (options.AdministrativeGroups is null) throw new ArgumentException("AdministrativeGroups must not be null.", nameof(options));
        }
    }
}
