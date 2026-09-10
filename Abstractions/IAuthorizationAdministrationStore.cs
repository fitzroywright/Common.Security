using Common.Security.Authorization;

namespace Common.Security.Abstractions;

public interface IAuthorizationAdministrationStore
{
    Task<AuthorizationAdministrationSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default);

    Task UpsertRoleAsync(RoleDefinition role, string actor, string? reason = null, CancellationToken cancellationToken = default);
    Task DeleteRoleAsync(string roleKey, string actor, string? reason = null, CancellationToken cancellationToken = default);

    Task AssignRoleAsync(RoleAssignment assignment, string actor, string? reason = null, CancellationToken cancellationToken = default);
    Task RevokeRoleAsync(RoleAssignment assignment, string actor, string? reason = null, CancellationToken cancellationToken = default);

    Task MapGroupAsync(GroupRoleMapping mapping, string actor, string? reason = null, CancellationToken cancellationToken = default);
    Task UnmapGroupAsync(GroupRoleMapping mapping, string actor, string? reason = null, CancellationToken cancellationToken = default);
}

public interface ITimeBoundAuthorizationStore
{
    Task<IReadOnlyCollection<TimeBoundRoleAssignment>> GetActiveRoleAssignmentsAsync(
        string subjectId,
        DateTimeOffset at,
        CancellationToken cancellationToken = default);

    Task<TimeBoundRoleAssignment> GrantTimeBoundRoleAsync(
        string subjectId,
        string roleKey,
        DateTimeOffset validFrom,
        DateTimeOffset? validUntil,
        string actor,
        string? reason = null,
        CancellationToken cancellationToken = default);

    Task<bool> RevokeTimeBoundRoleAsync(
        Guid assignmentId,
        string actor,
        string? reason = null,
        CancellationToken cancellationToken = default);
}

public interface IAuthorizationAuditStore
{
    Task AppendAsync(AuthorizationAuditEvent auditEvent, CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<AuthorizationAuditEvent>> QueryAsync(
        AuthorizationAuditQuery query,
        CancellationToken cancellationToken = default);
}
