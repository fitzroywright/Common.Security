namespace Common.Security.Authorization;

public sealed record TimeBoundRoleAssignment(
    Guid AssignmentId,
    string SubjectId,
    string RoleKey,
    DateTimeOffset ValidFrom,
    DateTimeOffset? ValidUntil,
    string GrantedBy,
    string? Reason = null,
    DateTimeOffset? RevokedAt = null,
    string? RevokedBy = null)
{
    public bool IsActive(DateTimeOffset at)
        => RevokedAt is null
            && ValidFrom <= at
            && (!ValidUntil.HasValue || at < ValidUntil.Value);
}

public sealed record AuthorizationAuditEvent(
    Guid EventId,
    DateTimeOffset Timestamp,
    string Actor,
    string Action,
    string Outcome,
    string? SubjectId = null,
    string? RoleKey = null,
    string? Permission = null,
    string? Reason = null,
    string? CorrelationId = null);

public sealed record AuthorizationAuditQuery(
    string? SubjectId = null,
    string? Actor = null,
    string? Action = null,
    DateTimeOffset? From = null,
    DateTimeOffset? To = null,
    int Take = 100);

public sealed record AuthorizationAdministrationSnapshot(
    IReadOnlyCollection<PermissionDefinition> Permissions,
    IReadOnlyCollection<RoleDefinition> Roles,
    IReadOnlyCollection<RoleAssignment> DirectAssignments,
    IReadOnlyCollection<GroupRoleMapping> GroupMappings,
    IReadOnlyCollection<TimeBoundRoleAssignment> TimeBoundAssignments);
