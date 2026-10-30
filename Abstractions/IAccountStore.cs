namespace Common.Security.Abstractions;

using Common.Security.Models;

public enum AccountPopulation { Staff, PublicApplicant, Operator, Administrator }
public enum SecurityAccountStatus { PendingAccess, Active, Suspended, Disabled }

public sealed record SecurityAccount(string Id, string LoginName, string DisplayName,
    AuthenticationProviderKind ProviderKind, AccountPopulation Population,
    SecurityAccountStatus Status, long SessionVersion);

public sealed record AccountResolution(SecurityAccount Account, bool Created);
public sealed record LinkedAuthenticationIdentity(ExternalIdentityKey Key, AuthenticationProviderKind ProviderKind);

public sealed record AccountCreation(string Id, string LoginName, string DisplayName,
    AuthenticationProviderKind ProviderKind, AccountPopulation Population,
    SecurityAccountStatus Status = SecurityAccountStatus.PendingAccess,
    ExternalIdentityKey? Identity = null,
    IReadOnlyList<ExternalIdentityKey>? AdditionalIdentities = null);

/// <summary>
/// Application-scoped storage. Each write and its audit event must commit atomically.
/// Identity uniqueness and first-login resolution must be enforced by the database.
/// Implementations must never resolve or link an identity by email or login alias alone.
/// </summary>
public interface IAccountStore
{
    AccountResolution Resolve(VerifiedIdentity identity, AccountPopulation population, bool allowAutomaticCreation);
    SecurityAccount Create(AccountCreation account, string actorId, string? initialLocalPassword = null);
    SecurityAccount? Find(string accountId);
    IReadOnlyList<SecurityAccount> List();
    IReadOnlyList<LinkedAuthenticationIdentity> GetIdentities(string accountId);
    void SetStatus(string accountId, SecurityAccountStatus status, string actorId);
    void RevokeSessions(string accountId, string actorId);
    void Link(string accountId, VerifiedIdentity identity, string actorId);
    void Unlink(string accountId, ExternalIdentityKey identity, string actorId);
}

public sealed class IdentityEnrollmentRequiredException() : InvalidOperationException(
    "An account already has this login name. An administrator must approve its immutable provider binding.");

public sealed class IdentityAlreadyLinkedException() : InvalidOperationException(
    "This provider identity is already linked to another account.");
