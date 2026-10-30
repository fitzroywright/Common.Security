namespace Common.Security.Services;

using Common.Security.Abstractions;
using Common.Security.Models;

public sealed class AccountProvisioningService(IAccountStore store, TimeProvider? timeProvider = null)
{
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    public AccountResolution Provision(VerifiedIdentity identity, AccountPopulation population,
        bool allowAutomaticCreation = true)
    {
        ArgumentNullException.ThrowIfNull(identity);
        if (identity.AuthenticatedAt > clock.GetUtcNow().AddMinutes(2) ||
            identity.AuthenticatedAt < clock.GetUtcNow().AddMinutes(-10))
            throw new InvalidOperationException("Fresh authentication is required for provisioning.");
        return store.Resolve(identity, population, allowAutomaticCreation);
    }

    public bool IsCurrentSession(string accountId, long sessionVersion, bool requireActive = true)
    {
        SecurityAccount? account = store.Find(accountId);
        return account is not null && account.SessionVersion == sessionVersion &&
            (requireActive ? account.Status == SecurityAccountStatus.Active :
                account.Status is SecurityAccountStatus.Active or SecurityAccountStatus.PendingAccess);
    }
}
