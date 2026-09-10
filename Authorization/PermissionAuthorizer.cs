using Common.Security.Abstractions;

namespace Common.Security.Authorization;

public sealed class PermissionAuthorizer : IPermissionAuthorizer
{
    public const string AllPermissions = "*";

    private readonly IAuthorizationStore authorizationStore;
    private readonly ITimeBoundAuthorizationStore? timeBoundStore;
    private readonly IAuthorizationAuditStore? auditStore;

    public PermissionAuthorizer(
        IAuthorizationStore authorizationStore,
        ITimeBoundAuthorizationStore? timeBoundStore = null,
        IAuthorizationAuditStore? auditStore = null)
    {
        this.authorizationStore = authorizationStore ?? throw new ArgumentNullException(nameof(authorizationStore));
        this.timeBoundStore = timeBoundStore;
        this.auditStore = auditStore;
    }

    public async Task<bool> CanAsync(
        AuthorizationSubject subject,
        string permission,
        CancellationToken cancellationToken = default)
        => (await AuthorizeAsync(subject, permission, cancellationToken).ConfigureAwait(false)).Allowed;

    public async Task<AuthorizationDecision> AuthorizeAsync(
        AuthorizationSubject subject,
        string permission,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);

        string normalizedPermission = permission.Trim();
        IReadOnlyCollection<string> directRoles = await authorizationStore
            .GetDirectRoleKeysAsync(subject.SubjectId, cancellationToken)
            .ConfigureAwait(false);

        IReadOnlyCollection<string> groupRoles = subject.GroupNames.Count == 0
            ? Array.Empty<string>()
            : await authorizationStore
                .GetRoleKeysForGroupsAsync(subject.GroupNames, cancellationToken)
                .ConfigureAwait(false);

        IReadOnlyCollection<string> timeBoundRoles = Array.Empty<string>();
        if (timeBoundStore is not null)
        {
            IReadOnlyCollection<TimeBoundRoleAssignment> assignments = await timeBoundStore
                .GetActiveRoleAssignmentsAsync(subject.SubjectId, DateTimeOffset.UtcNow, cancellationToken)
                .ConfigureAwait(false);
            timeBoundRoles = assignments
                .Where(assignment => assignment.IsActive(DateTimeOffset.UtcNow))
                .Select(assignment => assignment.RoleKey)
                .ToArray();
        }

        string[] effectiveRoleKeys = directRoles
            .Concat(groupRoles)
            .Concat(timeBoundRoles)
            .Where(role => !string.IsNullOrWhiteSpace(role))
            .Select(role => role.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        AuthorizationDecision decision;
        if (effectiveRoleKeys.Length == 0)
        {
            decision = new AuthorizationDecision(
                false,
                normalizedPermission,
                effectiveRoleKeys,
                "No application role is assigned to the subject or any of its mapped directory groups.");
        }
        else
        {
            IReadOnlyCollection<RoleDefinition> roles = await authorizationStore
                .GetRolesAsync(effectiveRoleKeys, cancellationToken)
                .ConfigureAwait(false);

            bool allowed = roles.Any(role => role.Permissions.Any(granted =>
                string.Equals(granted, normalizedPermission, StringComparison.OrdinalIgnoreCase)
                || string.Equals(granted, AllPermissions, StringComparison.OrdinalIgnoreCase)));

            decision = new AuthorizationDecision(
                allowed,
                normalizedPermission,
                effectiveRoleKeys,
                allowed
                    ? "Permission granted by an application role."
                    : "None of the effective application roles grants the requested permission.");
        }

        await AuditDecisionAsync(subject, decision, cancellationToken).ConfigureAwait(false);
        return decision;
    }

    private async Task AuditDecisionAsync(
        AuthorizationSubject subject,
        AuthorizationDecision decision,
        CancellationToken cancellationToken)
    {
        if (auditStore is null)
        {
            return;
        }

        await auditStore.AppendAsync(
            new AuthorizationAuditEvent(
                Guid.NewGuid(),
                DateTimeOffset.UtcNow,
                subject.SubjectId,
                "Authorize",
                decision.Allowed ? "Allowed" : "Denied",
                SubjectId: subject.SubjectId,
                Permission: decision.Permission,
                Reason: decision.Reason),
            cancellationToken).ConfigureAwait(false);
    }
}
