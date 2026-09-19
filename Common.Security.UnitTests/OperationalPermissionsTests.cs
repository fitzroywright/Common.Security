using Xunit;
using Common.Security.Authorization;
using Common.Security.Constants;

namespace Common.Security.UnitTests;

public sealed class OperationalPermissionsTests
{
    [Fact]
    public void Operational_permission_keys_are_unique()
    {
        Assert.Equal(
            OperationalPermissions.All.Count,
            OperationalPermissions.All.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void Operational_permissions_are_capabilities_not_job_titles()
    {
        Assert.All(OperationalPermissions.All, permission =>
        {
            Assert.Contains(".", permission, StringComparison.Ordinal);
            Assert.DoesNotContain("Manager", permission, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Administrator", permission, StringComparison.OrdinalIgnoreCase);
        });
    }

    [Fact]
    public async Task Permission_authorizer_denies_ungranted_operational_capability()
    {
        var store = new TestAuthorizationStore(
            roles:
            [
                new RoleDefinition(
                    "operator",
                    "Operator",
                    [OperationalPermissions.DiagnosticsView])
            ],
            directRoles: ["operator"]);

        var authorizer = new PermissionAuthorizer(store);
        var subject = new AuthorizationSubject("user-1", []);

        AuthorizationDecision decision =
            await authorizer.AuthorizeAsync(subject, OperationalPermissions.AlertsResolve);

        Assert.False(decision.Allowed);
        Assert.Equal(OperationalPermissions.AlertsResolve, decision.Permission);
    }

    private sealed class TestAuthorizationStore(
        IReadOnlyCollection<RoleDefinition> roles,
        IReadOnlyCollection<string> directRoles) : Common.Security.Abstractions.IAuthorizationStore
    {
        public Task<IReadOnlyCollection<RoleDefinition>> GetRolesAsync(
            IReadOnlyCollection<string> roleKeys,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyCollection<RoleDefinition>>(
                roles.Where(x => roleKeys.Contains(x.Key, StringComparer.OrdinalIgnoreCase)).ToArray());

        public Task<IReadOnlyCollection<string>> GetDirectRoleKeysAsync(
            string subjectId,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(directRoles);

        public Task<IReadOnlyCollection<string>> GetRoleKeysForGroupsAsync(
            IReadOnlyCollection<string> groupNames,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyCollection<string>>([]);
    }
}
