using Common.Security.Abstractions;
using Common.Security.Authorization;
using Xunit;

namespace Common.Security.UnitTests;

public sealed class TimeBoundAuthorizationTests
{
    [Fact]
    public async Task ActiveTimeBoundRoleGrantsPermissionAndAuditsDecision()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        FakeStore store = new(
            [new RoleDefinition("approver", "Approver", ["requests.approve"])],
            [new TimeBoundRoleAssignment(Guid.NewGuid(), "alice", "approver", now.AddMinutes(-5), now.AddMinutes(30), "admin", "coverage")]);

        PermissionAuthorizer authorizer = new(store, store, store);
        AuthorizationDecision decision = await authorizer.AuthorizeAsync(
            AuthorizationSubject.Create("alice"),
            "requests.approve");

        Assert.True(decision.Allowed);
        AuthorizationAuditEvent audit = Assert.Single(store.Audit);
        Assert.Equal("Allowed", audit.Outcome);
        Assert.Equal("requests.approve", audit.Permission);
    }

    [Fact]
    public async Task ExpiredTimeBoundRoleDoesNotGrantPermission()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        FakeStore store = new(
            [new RoleDefinition("approver", "Approver", ["requests.approve"])],
            [new TimeBoundRoleAssignment(Guid.NewGuid(), "alice", "approver", now.AddHours(-2), now.AddHours(-1), "admin")]);

        PermissionAuthorizer authorizer = new(store, store, store);
        AuthorizationDecision decision = await authorizer.AuthorizeAsync(
            AuthorizationSubject.Create("alice"),
            "requests.approve");

        Assert.False(decision.Allowed);
        Assert.Empty(decision.EffectiveRoles);
        Assert.Equal("Denied", Assert.Single(store.Audit).Outcome);
    }

    [Fact]
    public async Task RevokedTimeBoundRoleDoesNotGrantPermission()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        FakeStore store = new(
            [new RoleDefinition("approver", "Approver", ["requests.approve"])],
            [new TimeBoundRoleAssignment(Guid.NewGuid(), "alice", "approver", now.AddMinutes(-5), now.AddMinutes(30), "admin", RevokedAt: now, RevokedBy: "admin")]);

        PermissionAuthorizer authorizer = new(store, store, store);
        Assert.False(await authorizer.CanAsync(AuthorizationSubject.Create("alice"), "requests.approve"));
    }

    private sealed class FakeStore : IAuthorizationStore, ITimeBoundAuthorizationStore, IAuthorizationAuditStore
    {
        private readonly IReadOnlyCollection<RoleDefinition> roles;
        private readonly IReadOnlyCollection<TimeBoundRoleAssignment> assignments;

        public FakeStore(IReadOnlyCollection<RoleDefinition> roles, IReadOnlyCollection<TimeBoundRoleAssignment> assignments)
        {
            this.roles = roles;
            this.assignments = assignments;
        }

        public List<AuthorizationAuditEvent> Audit { get; } = [];

        public Task<IReadOnlyCollection<string>> GetDirectRoleKeysAsync(string subjectId, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyCollection<string>>(Array.Empty<string>());

        public Task<IReadOnlyCollection<string>> GetRoleKeysForGroupsAsync(IReadOnlyCollection<string> groupNames, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyCollection<string>>(Array.Empty<string>());

        public Task<IReadOnlyCollection<RoleDefinition>> GetRolesAsync(IReadOnlyCollection<string> roleKeys, CancellationToken cancellationToken = default)
        {
            HashSet<string> keys = roleKeys.ToHashSet(StringComparer.OrdinalIgnoreCase);
            return Task.FromResult<IReadOnlyCollection<RoleDefinition>>(roles.Where(role => keys.Contains(role.Key)).ToArray());
        }

        public Task<IReadOnlyCollection<TimeBoundRoleAssignment>> GetActiveRoleAssignmentsAsync(string subjectId, DateTimeOffset at, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyCollection<TimeBoundRoleAssignment>>(assignments.Where(a => a.SubjectId.Equals(subjectId, StringComparison.OrdinalIgnoreCase) && a.IsActive(at)).ToArray());

        public Task<TimeBoundRoleAssignment> GrantTimeBoundRoleAsync(string subjectId, string roleKey, DateTimeOffset validFrom, DateTimeOffset? validUntil, string actor, string? reason = null, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<bool> RevokeTimeBoundRoleAsync(Guid assignmentId, string actor, string? reason = null, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task AppendAsync(AuthorizationAuditEvent auditEvent, CancellationToken cancellationToken = default)
        {
            Audit.Add(auditEvent);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyCollection<AuthorizationAuditEvent>> QueryAsync(AuthorizationAuditQuery query, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyCollection<AuthorizationAuditEvent>>(Audit.ToArray());
    }
}
