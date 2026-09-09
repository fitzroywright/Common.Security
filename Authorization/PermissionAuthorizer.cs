using Common.Security.Abstractions;

namespace Common.Security.Authorization;

public sealed class PermissionAuthorizer : IPermissionAuthorizer
{
    public const string AllPermissions = "*";

    private readonly IAuthorizationStore authorizationStore;

    public PermissionAuthorizer(IAuthorizationStore authorizationStore)
    {
        this.authorizationStore = authorizationStore ?? throw new ArgumentNullException(nameof(authorizationStore));
    }

    public async Task<AuthorizationDecision> AuthorizeAsync(
        AuthorizationSubject subject,
        string permission,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);

        IReadOnlyCollection<string> directRoles = await authorizationStore
            .GetDirectRoleKeysAsync(subject.SubjectId, cancellationToken)
            .ConfigureAwait(false);

        IReadOnlyCollection<string> groupRoles = subject.GroupNames.Count == 0
            ? Array.Empty<string>()
            : await authorizationStore
                .GetRoleKeysForGroupsAsync(subject.GroupNames, cancellationToken)
                .ConfigureAwait(false);

        string[] effectiveRoleKeys = directRoles
            .Concat(groupRoles)
            .Where(role => !string.IsNullOrWhiteSpace(role))
            .Select(role => role.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (effectiveRoleKeys.Length == 0)
        {
            return new AuthorizationDecision(
                false,
                permission.Trim(),
                effectiveRoleKeys,
                "No application role is assigned to the subject or any of its mapped directory groups.");
        }

        IReadOnlyCollection<RoleDefinition> roles = await authorizationStore
            .GetRolesAsync(effectiveRoleKeys, cancellationToken)
            .ConfigureAwait(false);

        bool allowed = roles.Any(role => role.Permissions.Any(granted =>
            string.Equals(granted, permission, StringComparison.OrdinalIgnoreCase)
            || string.Equals(granted, AllPermissions, StringComparison.OrdinalIgnoreCase)));

        return new AuthorizationDecision(
            allowed,
            permission.Trim(),
            effectiveRoleKeys,
            allowed
                ? "Permission granted by an application role."
                : "None of the effective application roles grants the requested permission.");
    }
}
