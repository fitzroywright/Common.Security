using Common.Security.Abstractions;
using Common.Security.Authorization;
using Xunit;

namespace Common.Security.UnitTests;

public sealed class AuthorizationAdministrationServiceTests
{
    [Fact]
    public async Task UpsertRole_NormalizesPermissionsAndWritesAudit()
    {
        RecordingAuthorizationStore store = new();
        AuthorizationAdministrationService service = new(store, store);

        await service.UpsertRoleAsync(
            new RoleDefinition(" Manager ", " Managers ", [" Reports.View ", "reports.view", " ", "Users.Edit"]),
            " admin ",
            "initial setup");

        RoleDefinition role = Assert.Single(store.Roles);
        Assert.Equal("Manager", role.Key);
        Assert.Equal("Managers", role.Name);
        Assert.Equal(2, role.Permissions.Count);
        Assert.Contains(role.Permissions, permission => permission.Equals("Reports.View", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(role.Permissions, permission => permission.Equals("Users.Edit", StringComparison.OrdinalIgnoreCase));

        AuthorizationAuditEvent audit = Assert.Single(store.AuditEvents);
        Assert.Equal("admin", audit.Actor);
        Assert.Equal("Role.Upsert", audit.Action);
        Assert.Equal("Succeeded", audit.Outcome);
        Assert.Equal("Manager", audit.RoleKey);
        Assert.Equal("initial setup", audit.Reason);
    }

    [Fact]
    public async Task AssignAndRevokeRole_UseNormalizedIdentifiersAndAuditEachMutation()
    {
        RecordingAuthorizationStore store = new();
        AuthorizationAdministrationService service = new(store, store);

        await service.AssignRoleAsync(" user-1 ", " Manager ", " admin ", "grant");
        await service.RevokeRoleAsync(" user-1 ", " Manager ", " admin ", "remove");

        Assert.Equal(new RoleAssignment("user-1", "Manager"), Assert.Single(store.AssignmentsAdded));
        Assert.Equal(new RoleAssignment("user-1", "Manager"), Assert.Single(store.AssignmentsRevoked));
        Assert.Collection(
            store.AuditEvents,
            audit => Assert.Equal("Role.Assign", audit.Action),
            audit => Assert.Equal("Role.Revoke", audit.Action));
    }

    [Fact]
    public async Task GroupMapAndUnmap_AreAudited()
    {
        RecordingAuthorizationStore store = new();
        AuthorizationAdministrationService service = new(store, store);

        await service.MapGroupAsync(" FFTPJ-App-Managers ", " Manager ", " admin ");
        await service.UnmapGroupAsync(" FFTPJ-App-Managers ", " Manager ", " admin ");

        Assert.Equal(new GroupRoleMapping("FFTPJ-App-Managers", "Manager"), Assert.Single(store.GroupMappingsAdded));
        Assert.Equal(new GroupRoleMapping("FFTPJ-App-Managers", "Manager"), Assert.Single(store.GroupMappingsRemoved));
        Assert.Contains(store.AuditEvents, audit => audit.Action == "GroupRole.Map");
        Assert.Contains(store.AuditEvents, audit => audit.Action == "GroupRole.Unmap");
    }

    [Fact]
    public async Task GrantTimeBoundRole_RejectsInvalidWindowBeforeCallingStore()
    {
        RecordingAuthorizationStore store = new();
        AuthorizationAdministrationService service = new(store, store);
        DateTimeOffset start = DateTimeOffset.UtcNow;

        await Assert.ThrowsAsync<ArgumentException>(() => service.GrantTimeBoundRoleAsync(
            store,
            "user-1",
            "Manager",
            start,
            start,
            "admin"));

        Assert.Empty(store.TimeBoundAssignments);
        Assert.Empty(store.AuditEvents);
    }

    [Fact]
    public async Task GrantTimeBoundRole_PersistsAndAuditsValidAssignment()
    {
        RecordingAuthorizationStore store = new();
        AuthorizationAdministrationService service = new(store, store);
        DateTimeOffset start = DateTimeOffset.UtcNow;
        DateTimeOffset end = start.AddHours(2);

        TimeBoundRoleAssignment assignment = await service.GrantTimeBoundRoleAsync(
            store,
            " user-1 ",
            " Manager ",
            start,
            end,
            " admin ",
            "temporary support");

        Assert.Equal("user-1", assignment.SubjectId);
        Assert.Equal("Manager", assignment.RoleKey);
        Assert.Equal(end, assignment.ValidUntil);
        AuthorizationAuditEvent audit = Assert.Single(store.AuditEvents);
        Assert.Equal("Role.GrantTemporary", audit.Action);
        Assert.Equal("user-1", audit.SubjectId);
        Assert.Equal("Manager", audit.RoleKey);
    }

    private sealed class RecordingAuthorizationStore :
        IAuthorizationAdministrationStore,
        IAuthorizationAuditStore,
        ITimeBoundAuthorizationStore
    {
        public List<RoleDefinition> Roles { get; } = [];
        public List<RoleAssignment> AssignmentsAdded { get; } = [];
        public List<RoleAssignment> AssignmentsRevoked { get; } = [];
        public List<GroupRoleMapping> GroupMappingsAdded { get; } = [];
        public List<GroupRoleMapping> GroupMappingsRemoved { get; } = [];
        public List<TimeBoundRoleAssignment> TimeBoundAssignments { get; } = [];
        public List<AuthorizationAuditEvent> AuditEvents { get; } = [];

        public Task<AuthorizationAdministrationSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(new AuthorizationAdministrationSnapshot([], Roles, AssignmentsAdded, GroupMappingsAdded, TimeBoundAssignments));

        public Task UpsertRoleAsync(RoleDefinition role, string actor, string? reason = null, CancellationToken cancellationToken = default)
        {
            Roles.Add(role);
            return Task.CompletedTask;
        }

        public Task DeleteRoleAsync(string roleKey, string actor, string? reason = null, CancellationToken cancellationToken = default)
        {
            Roles.RemoveAll(role => role.Key.Equals(roleKey, StringComparison.OrdinalIgnoreCase));
            return Task.CompletedTask;
        }

        public Task AssignRoleAsync(RoleAssignment assignment, string actor, string? reason = null, CancellationToken cancellationToken = default)
        {
            AssignmentsAdded.Add(assignment);
            return Task.CompletedTask;
        }

        public Task RevokeRoleAsync(RoleAssignment assignment, string actor, string? reason = null, CancellationToken cancellationToken = default)
        {
            AssignmentsRevoked.Add(assignment);
            return Task.CompletedTask;
        }

        public Task MapGroupAsync(GroupRoleMapping mapping, string actor, string? reason = null, CancellationToken cancellationToken = default)
        {
            GroupMappingsAdded.Add(mapping);
            return Task.CompletedTask;
        }

        public Task UnmapGroupAsync(GroupRoleMapping mapping, string actor, string? reason = null, CancellationToken cancellationToken = default)
        {
            GroupMappingsRemoved.Add(mapping);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyCollection<TimeBoundRoleAssignment>> GetActiveRoleAssignmentsAsync(
            string subjectId,
            DateTimeOffset at,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyCollection<TimeBoundRoleAssignment>>(
                TimeBoundAssignments.Where(assignment => assignment.SubjectId == subjectId && assignment.IsActive(at)).ToArray());

        public Task<TimeBoundRoleAssignment> GrantTimeBoundRoleAsync(
            string subjectId,
            string roleKey,
            DateTimeOffset validFrom,
            DateTimeOffset? validUntil,
            string actor,
            string? reason = null,
            CancellationToken cancellationToken = default)
        {
            TimeBoundRoleAssignment assignment = new(
                Guid.NewGuid(),
                subjectId,
                roleKey,
                validFrom,
                validUntil,
                actor,
                reason);
            TimeBoundAssignments.Add(assignment);
            return Task.FromResult(assignment);
        }

        public Task<bool> RevokeTimeBoundRoleAsync(
            Guid assignmentId,
            string actor,
            string? reason = null,
            CancellationToken cancellationToken = default)
            => Task.FromResult(false);

        public Task AppendAsync(AuthorizationAuditEvent auditEvent, CancellationToken cancellationToken = default)
        {
            AuditEvents.Add(auditEvent);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyCollection<AuthorizationAuditEvent>> QueryAsync(
            AuthorizationAuditQuery query,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyCollection<AuthorizationAuditEvent>>(AuditEvents.ToArray());
    }
}
