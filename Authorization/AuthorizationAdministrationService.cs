using Common.Security.Abstractions;

namespace Common.Security.Authorization;

public sealed class AuthorizationAdministrationService
{
    private readonly IAuthorizationAdministrationStore store;
    private readonly IAuthorizationAuditStore? auditStore;

    public AuthorizationAdministrationService(
        IAuthorizationAdministrationStore store,
        IAuthorizationAuditStore? auditStore = null)
    {
        this.store = store ?? throw new ArgumentNullException(nameof(store));
        this.auditStore = auditStore;
    }

    public Task<AuthorizationAdministrationSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default)
        => store.GetSnapshotAsync(cancellationToken);

    public async Task UpsertRoleAsync(RoleDefinition role, string actor, string? reason = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(role);
        ValidateKey(role.Key, nameof(role.Key));
        ArgumentException.ThrowIfNullOrWhiteSpace(role.Name);
        ValidateActor(actor);

        RoleDefinition normalized = new(
            role.Key.Trim(),
            role.Name.Trim(),
            role.Permissions.Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => p.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
        await store.UpsertRoleAsync(normalized, actor.Trim(), reason, cancellationToken).ConfigureAwait(false);
        await AuditAsync(actor, "Role.Upsert", "Succeeded", roleKey: normalized.Key, reason: reason, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteRoleAsync(string roleKey, string actor, string? reason = null, CancellationToken cancellationToken = default)
    {
        ValidateKey(roleKey, nameof(roleKey));
        ValidateActor(actor);
        await store.DeleteRoleAsync(roleKey.Trim(), actor.Trim(), reason, cancellationToken).ConfigureAwait(false);
        await AuditAsync(actor, "Role.Delete", "Succeeded", roleKey: roleKey.Trim(), reason: reason, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    public async Task AssignRoleAsync(string subjectId, string roleKey, string actor, string? reason = null, CancellationToken cancellationToken = default)
    {
        ValidateKey(subjectId, nameof(subjectId));
        ValidateKey(roleKey, nameof(roleKey));
        ValidateActor(actor);
        RoleAssignment assignment = new(subjectId.Trim(), roleKey.Trim());
        await store.AssignRoleAsync(assignment, actor.Trim(), reason, cancellationToken).ConfigureAwait(false);
        await AuditAsync(actor, "Role.Assign", "Succeeded", subjectId.Trim(), roleKey.Trim(), reason: reason, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    public async Task RevokeRoleAsync(string subjectId, string roleKey, string actor, string? reason = null, CancellationToken cancellationToken = default)
    {
        ValidateKey(subjectId, nameof(subjectId));
        ValidateKey(roleKey, nameof(roleKey));
        ValidateActor(actor);
        RoleAssignment assignment = new(subjectId.Trim(), roleKey.Trim());
        await store.RevokeRoleAsync(assignment, actor.Trim(), reason, cancellationToken).ConfigureAwait(false);
        await AuditAsync(actor, "Role.Revoke", "Succeeded", subjectId.Trim(), roleKey.Trim(), reason: reason, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    public async Task MapGroupAsync(string groupName, string roleKey, string actor, string? reason = null, CancellationToken cancellationToken = default)
    {
        ValidateKey(groupName, nameof(groupName));
        ValidateKey(roleKey, nameof(roleKey));
        ValidateActor(actor);
        GroupRoleMapping mapping = new(groupName.Trim(), roleKey.Trim());
        await store.MapGroupAsync(mapping, actor.Trim(), reason, cancellationToken).ConfigureAwait(false);
        await AuditAsync(actor, "GroupRole.Map", "Succeeded", roleKey: roleKey.Trim(), reason: reason, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    public async Task UnmapGroupAsync(string groupName, string roleKey, string actor, string? reason = null, CancellationToken cancellationToken = default)
    {
        ValidateKey(groupName, nameof(groupName));
        ValidateKey(roleKey, nameof(roleKey));
        ValidateActor(actor);
        GroupRoleMapping mapping = new(groupName.Trim(), roleKey.Trim());
        await store.UnmapGroupAsync(mapping, actor.Trim(), reason, cancellationToken).ConfigureAwait(false);
        await AuditAsync(actor, "GroupRole.Unmap", "Succeeded", roleKey: roleKey.Trim(), reason: reason, cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    public async Task<TimeBoundRoleAssignment> GrantTimeBoundRoleAsync(
        ITimeBoundAuthorizationStore timeBoundStore,
        string subjectId,
        string roleKey,
        DateTimeOffset validFrom,
        DateTimeOffset? validUntil,
        string actor,
        string? reason = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(timeBoundStore);
        ValidateKey(subjectId, nameof(subjectId));
        ValidateKey(roleKey, nameof(roleKey));
        ValidateActor(actor);
        if (validUntil.HasValue && validUntil.Value <= validFrom)
        {
            throw new ArgumentException("ValidUntil must be later than ValidFrom.", nameof(validUntil));
        }

        TimeBoundRoleAssignment assignment = await timeBoundStore.GrantTimeBoundRoleAsync(
            subjectId.Trim(), roleKey.Trim(), validFrom, validUntil, actor.Trim(), reason, cancellationToken).ConfigureAwait(false);
        await AuditAsync(actor, "Role.GrantTemporary", "Succeeded", subjectId.Trim(), roleKey.Trim(), reason: reason, cancellationToken: cancellationToken).ConfigureAwait(false);
        return assignment;
    }

    private async Task AuditAsync(
        string actor,
        string action,
        string outcome,
        string? subjectId = null,
        string? roleKey = null,
        string? permission = null,
        string? reason = null,
        CancellationToken cancellationToken = default)
    {
        if (auditStore is null) return;
        await auditStore.AppendAsync(new AuthorizationAuditEvent(
            Guid.NewGuid(), DateTimeOffset.UtcNow, actor.Trim(), action, outcome, subjectId, roleKey, permission, reason), cancellationToken).ConfigureAwait(false);
    }

    private static void ValidateKey(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value)) throw new ArgumentException("Value is required.", parameterName);
    }

    private static void ValidateActor(string actor) => ValidateKey(actor, nameof(actor));
}
