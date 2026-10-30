namespace Common.Security.Authenticators;

using System.Security.Cryptography;
using System.Text;
using Common.Security.Abstractions;
using Common.Security.Models;
using Common.Security.Options;

public static class MockEnvironmentPolicy
{
    public static bool IsPermitted(bool enabled, string environmentName, bool isolationConfirmed)
        => enabled && isolationConfirmed && (environmentName.Equals("Development", StringComparison.OrdinalIgnoreCase)
            || environmentName.Equals("Demo", StringComparison.OrdinalIgnoreCase));
}

public sealed class MockAuthenticator : IAuthenticator
{
    private readonly MockAuthenticationOptions options;
    private readonly IReadOnlyDictionary<string, MockIdentityDefinition> identities;
    private readonly TimeProvider clock;

    public MockAuthenticator(MockAuthenticationOptions options, TimeProvider? timeProvider = null)
    {
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        clock = timeProvider ?? TimeProvider.System;
        ArgumentException.ThrowIfNullOrWhiteSpace(options.ApplicationId);
        identities = options.Identities.ToDictionary(x => x.LoginName, StringComparer.OrdinalIgnoreCase);
        if (options.Identities.Any(x => string.IsNullOrWhiteSpace(x.LoginName) || string.IsNullOrWhiteSpace(x.SubjectId)) ||
            options.Identities.Select(x => x.SubjectId).Distinct(StringComparer.Ordinal).Count() != options.Identities.Count)
            throw new ArgumentException("Mock identities require unique server-controlled login names and subjects.");
    }

    public AuthenticationResult Authenticate(string loginName, string password)
    {
        if (!MockEnvironmentPolicy.IsPermitted(options.Enabled, options.EnvironmentName, options.IsolationConfirmed))
            return AuthenticationResult.Failed(AuthenticationFailure.Prohibited);
        if (string.IsNullOrWhiteSpace(loginName) || !identities.TryGetValue(loginName.Trim(), out MockIdentityDefinition? definition))
            return AuthenticationResult.Failed();
        byte[] expected = SHA256.HashData(Encoding.UTF8.GetBytes(options.Password));
        byte[] supplied = SHA256.HashData(Encoding.UTF8.GetBytes(password ?? string.Empty));
        if (!CryptographicOperations.FixedTimeEquals(expected, supplied)) return AuthenticationResult.Failed();
        var identity = new VerifiedIdentity(new ExternalIdentityKey("mock", options.ApplicationId, definition.SubjectId),
            AuthenticationProviderKind.Mock, definition.LoginName, definition.DisplayName, clock.GetUtcNow(),
            "isolated-mock", groups: definition.Groups);
        return AuthenticationResult.Succeeded(identity, new ApplicationUserInfo
        {
            DisplayName = definition.DisplayName, Mail = definition.Email,
            Department = "Isolated demonstration", Title = "Mock identity", LastSync = clock.GetUtcNow().UtcDateTime
        });
    }
}
