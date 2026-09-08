namespace Common.Security.Services;

using Common.Security.Abstractions;
using Common.Security.Models;
using Common.Security.Options;
using Common.Security.Services.Functions;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.Net;

public sealed class ActiveDirectoryUserLookup : IDirectoryUserLookup
{
    private readonly ActiveDirectoryAuthenticationOptions options;
    private readonly string[] servers;
    private volatile string? preferredServer;

    public ActiveDirectoryUserLookup(ActiveDirectoryAuthenticationOptions options)
    {
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        this.servers = options.Servers
            .Where(server => !string.IsNullOrWhiteSpace(server))
            .Select(server => server.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (string.IsNullOrWhiteSpace(options.SearchBase) || this.servers.Length == 0)
        {
            throw new ArgumentException("Active Directory search base and at least one server are required.", nameof(options));
        }
    }

    public DirectoryUserInfo? FindByLoginName(string loginName)
    {
        string userName = UserNameNormalizer.GetUserNameWithoutDomain(loginName);
        if (string.IsNullOrWhiteSpace(userName))
        {
            return null;
        }

        string escapedUserName = LdapFilterEscaper.Escape(userName);
        foreach (string server in GetServersInPreferredOrder())
        {
            try
            {
                using LdapConnection connection = CreateConnection(server);
                connection.Bind();

                SearchRequest request = new
                (
                      options.SearchBase
                    , $"(sAMAccountName={escapedUserName})"
                    , SearchScope.Subtree
                    , "sAMAccountName"
                    , "displayName"
                    , "mail"
                );
                SearchResponse response = (SearchResponse)connection.SendRequest(request);
                if (response.Entries.Count == 0)
                {
                    return null;
                }

                preferredServer = server;
                SearchResultEntry entry = response.Entries[0];
                return new DirectoryUserInfo
                (
                      GetString(entry, "sAMAccountName") ?? userName
                    , GetString(entry, "displayName")
                    , GetString(entry, "mail")
                );
            }
            catch (LdapException exception)
            {
                Trace.TraceWarning("Active Directory lookup failed. Server={0}, User={1}. Trying next configured server. {2}", server, userName, exception);
            }
            catch (DirectoryOperationException exception)
            {
                Trace.TraceWarning("Active Directory lookup operation failed. Server={0}, User={1}. Trying next configured server. {2}", server, userName, exception);
            }
        }

        return null;
    }

    private LdapConnection CreateConnection(string server)
    {
        LdapDirectoryIdentifier identifier = new(server, options.Port, fullyQualifiedDnsHostName: true, connectionless: false);
        LdapConnection connection = new(identifier, CredentialCache.DefaultNetworkCredentials, AuthType.Negotiate)
        {
            Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds)
        };
        connection.SessionOptions.ProtocolVersion = 3;
        connection.SessionOptions.SecureSocketLayer = true;
        return connection;
    }

    private IEnumerable<string> GetServersInPreferredOrder()
    {
        string? preferred = preferredServer;
        if (!string.IsNullOrWhiteSpace(preferred) && servers.Contains(preferred, StringComparer.OrdinalIgnoreCase))
        {
            yield return preferred;
        }

        foreach (string server in servers)
        {
            if (!server.Equals(preferred, StringComparison.OrdinalIgnoreCase))
            {
                yield return server;
            }
        }
    }

    private static string? GetString(SearchResultEntry entry, string attributeName)
    {
        if (!entry.Attributes.Contains(attributeName))
        {
            return null;
        }

        string? value = entry.Attributes[attributeName]
            .GetValues(typeof(string))
            .Cast<string>()
            .FirstOrDefault();
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }
}
