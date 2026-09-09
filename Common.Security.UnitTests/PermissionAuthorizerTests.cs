using Common.Security.Abstractions;
using Common.Security.Authorization;
using Xunit;

namespace Common.Security.UnitTests;

public sealed class PermissionAuthorizerTests
{
    [Fact]
    public async Task DirectRoleGrantsPermission()
    {
        FakeAuthorizationStore store = new(
            directRoles: new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["alice"] = ["manager"]
            },
            groupRoles: new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase),
            roles:
            [
                new RoleDefinition("manager", "Manager", ["orders.approve"])
            ]);

        PermissionAuthorizer authorizer = new(store);
        AuthorizationDecision decision = await authorizer.AuthorizeAsync(
            AuthorizationSubject.Create("alice"),
            "orders.approve");

        Assert.True(decision.Allowed);
        Assert.Contains(decision.EffectiveRoles, role => string.Equals(role, "manager", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task DirectoryGroupMustMapToApplicationRoleBeforePermissionIsGranted()
    {
        FakeAuthorizationStore store = new(
            directRoles: new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase),
            groupRoles: new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["FFP-Managers"] = ["manager"]
            },
            roles:
            [
                new RoleDefinition("manager", "Manager", ["orders.approve"])
            ]);

        PermissionAuthorizer authorizer = new(store);

        AuthorizationDecision mapped = await authorizer.AuthorizeAsync(
            AuthorizationSubject.Create("alice", ["FFP-Managers"]),
            "orders.approve");
        AuthorizationDecision unmapped = await authorizer.AuthorizeAsync(
            AuthorizationSubject.Create("bob", ["Some-Other-AD-Group"]),
            "orders.approve");

        Assert.True(mapped.Allowed);
        Assert.False(unmapped.Allowed);
    }

    [Fact]
    public async Task WildcardRoleExplicitlyGrantsAllPermissions()
    {
        FakeAuthorizationStore store = new(
            directRoles: new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                ["admin"] = ["administrator"]
            },
            groupRoles: new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase),
            roles:
            [
                new RoleDefinition("administrator", "Administrator", [PermissionAuthorizer.AllPermissions])
            ]);

        PermissionAuthorizer authorizer = new(store);
        Assert.True(await authorizer.CanAsync(
            AuthorizationSubject.Create("admin"),
            "anything.at.all"));
    }

    private sealed class FakeAuthorizationStore : IAuthorizationStore
    {
        private readonly IReadOnlyDictionary<string, string[]> directRoles;
        private readonly IReadOnlyDictionary<string, string[]> groupRoles;
        private readonly IReadOnlyCollection<RoleDefinition> roles;

        public FakeAuthorizationStore(
            IReadOnlyDictionary<string, string[]> directRoles,
            IReadOnlyDictionary<string, string[]> groupRoles,
            IReadOnlyCollection<RoleDefinition> roles)
        {
            this.directRoles = directRoles;
            this.groupRoles = groupRoles;
            this.roles = roles;
        }

        public Task<IReadOnlyCollection<string>> GetDirectRoleKeysAsync(string subjectId, CancellationToken cancellationToken = default)
        {
            IReadOnlyCollection<string> result = directRoles.TryGetValue(subjectId, out string[]? values)
                ? values
                : Array.Empty<string>();
            return Task.FromResult(result);
        }

        public Task<IReadOnlyCollection<string>> GetRoleKeysForGroupsAsync(IReadOnlyCollection<string> groupNames, CancellationToken cancellationToken = default)
        {
            string[] result = groupNames
                .SelectMany(group => groupRoles.TryGetValue(group, out string[]? values) ? values : Array.Empty<string>())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            return Task.FromResult<IReadOnlyCollection<string>>(result);
        }

        public Task<IReadOnlyCollection<RoleDefinition>> GetRolesAsync(IReadOnlyCollection<string> roleKeys, CancellationToken cancellationToken = default)
        {
            HashSet<string> keys = roleKeys.ToHashSet(StringComparer.OrdinalIgnoreCase);
            RoleDefinition[] result = roles.Where(role => keys.Contains(role.Key)).ToArray();
            return Task.FromResult<IReadOnlyCollection<RoleDefinition>>(result);
        }
    }
}
