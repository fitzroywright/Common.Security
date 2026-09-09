namespace Common.Security.Authorization;

public sealed record PermissionDefinition(string Key, string Description);

public sealed record RoleDefinition(string Key, string Name, IReadOnlyCollection<string> Permissions);

public sealed record RoleAssignment(string SubjectId, string RoleKey);

public sealed record GroupRoleMapping(string GroupName, string RoleKey);

public sealed record AuthorizationDecision(
    bool Allowed,
    string Permission,
    IReadOnlyCollection<string> EffectiveRoles,
    string Reason);
