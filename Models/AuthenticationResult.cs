namespace Common.Security.Models;

public enum AuthenticationFailure { InvalidCredentials, Disabled, LockedOut, ProviderUnavailable, Prohibited }

/// <summary>Authentication proves identity only; applications decide access separately.</summary>
public sealed class AuthenticationResult
{
    public VerifiedIdentity? Identity { get; }
    public bool IsAuthenticated => Identity is not null;
    public ApplicationUserInfo? UserInfo { get; }
    public IReadOnlyList<string> GroupNames => Identity?.GroupNames ?? [];
    public AuthenticationFailure? Failure { get; }

    private AuthenticationResult(VerifiedIdentity? identity, ApplicationUserInfo? profile, AuthenticationFailure? failure)
    { Identity = identity; UserInfo = profile; Failure = failure; }

    public static AuthenticationResult Succeeded(VerifiedIdentity identity, ApplicationUserInfo? profile = null)
        => new(identity ?? throw new ArgumentNullException(nameof(identity)), profile, null);

    public static AuthenticationResult Failed(AuthenticationFailure failure = AuthenticationFailure.InvalidCredentials)
        => new(null, null, failure);
}
