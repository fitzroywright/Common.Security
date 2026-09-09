using Common.Security.Authorization;

namespace Common.Security.Abstractions;

public interface IAuthorizationStore
{
    Task<IReadOnlyCollection<string>> GetDirectRoleKeysAsync(
        string subjectId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<string>> GetRoleKeysForGroupsAsync(
        IReadOnlyCollection<string> groupNames,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<RoleDefinition>> GetRolesAsync(
        IReadOnlyCollection<string> roleKeys,
        CancellationToken cancellationToken = default);
}
