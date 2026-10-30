namespace Common.Security.UnitTests;

using Common.Security.Abstractions;
using Common.Security.Integration;
using Common.Security.Models;
using Common.Security.Services;
using Microsoft.Data.Sqlite;
using Xunit;

public sealed class AccountProvisioningTests
{
    [Fact]
    public void StaffFirstLoginIsPendingWithoutOperationalAccess()
    {
        using var db = new Database();
        var service = new AccountProvisioningService(db.Store);
        var result = service.Provision(Identity(), AccountPopulation.Staff);
        Assert.True(result.Created);
        Assert.Equal(SecurityAccountStatus.PendingAccess, result.Account.Status);
        Assert.False(service.IsCurrentSession(result.Account.Id, result.Account.SessionVersion));
        Assert.True(service.IsCurrentSession(result.Account.Id, result.Account.SessionVersion, requireActive: false));
    }

    [Fact]
    public void PublicApplicantDoesNotWaitForStaffApproval()
    {
        using var db = new Database();
        Assert.Equal(SecurityAccountStatus.Active, db.Store.Resolve(Identity(), AccountPopulation.PublicApplicant, true).Account.Status);
    }

    [Fact]
    public async Task ConcurrentFirstLoginCreatesExactlyOneAccountAndAuditEvent()
    {
        using var db = new Database();
        AccountResolution[] results = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => Task.Run(() =>
            db.Store.Resolve(Identity(), AccountPopulation.Staff, true))));
        Assert.Single(results.Select(x => x.Account.Id).Distinct());
        Assert.Single(results, x => x.Created);
        Assert.Single(db.Store.List());
        Assert.Equal(1L, db.Scalar("SELECT COUNT(*) FROM common_security_account_events"));
    }

    [Fact]
    public void AdministratorCreatedImmutableBindingPreservesExistingBusinessIdentifierAndAlias()
    {
        using var db = new Database();
        db.Store.Create(new AccountCreation("existing-business-id", "legacy-login", "Existing staff",
            AuthenticationProviderKind.ActiveDirectory, AccountPopulation.Staff, SecurityAccountStatus.Active, Identity().Key), "administrator");
        var result = db.Store.Resolve(Identity(login: "renamed-directory-login"), AccountPopulation.Staff, true);
        Assert.False(result.Created);
        Assert.Equal("existing-business-id", result.Account.Id);
        Assert.Equal("legacy-login", result.Account.LoginName);
        Assert.Equal(SecurityAccountStatus.Active, result.Account.Status);
    }

    [Fact]
    public void LoginAliasAloneCannotClaimAPrecreatedAccount()
    {
        using var db = new Database();
        db.Store.Create(new AccountCreation("existing", "alice", "Alice", AuthenticationProviderKind.ActiveDirectory,
            AccountPopulation.Staff), "administrator");
        Assert.Throws<IdentityEnrollmentRequiredException>(() => db.Store.Resolve(Identity(), AccountPopulation.Staff, true));
        Assert.Single(db.Store.List());
    }

    [Fact]
    public void MatchingEmailCannotLinkDifferentProviderSubjects()
    {
        using var db = new Database();
        var first = db.Store.Resolve(Identity(email: "same@example.test"), AccountPopulation.Staff, true);
        var second = db.Store.Resolve(Identity("second-subject", "second-login", email: "same@example.test"), AccountPopulation.Staff, true);
        Assert.NotEqual(first.Account.Id, second.Account.Id);
    }

    [Fact]
    public void ProviderScopeAndSubjectAreCaseSensitive()
    {
        using var db = new Database();
        var first = db.Store.Resolve(Identity("subject", "one"), AccountPopulation.Staff, true);
        var second = db.Store.Resolve(Identity("SUBJECT", "two"), AccountPopulation.Staff, true);
        Assert.NotEqual(first.Account.Id, second.Account.Id);
    }

    [Fact]
    public void ApplicationNamespacesAreIsolatedInTheSameDatabase()
    {
        using var db = new Database();
        var other = db.OtherApplication("another-application");
        var first = db.Store.Resolve(Identity(), AccountPopulation.Staff, true);
        var second = other.Resolve(Identity(), AccountPopulation.Staff, true);
        Assert.NotEqual(first.Account.Id, second.Account.Id);
        Assert.Null(other.Find(first.Account.Id));
    }

    [Fact]
    public void DisablingAnAccountImmediatelyInvalidatesItsSessionStamp()
    {
        using var db = new Database();
        var account = db.Store.Resolve(Identity(), AccountPopulation.Staff, true).Account;
        db.Store.SetStatus(account.Id, SecurityAccountStatus.Active, "administrator");
        long stamp = db.Store.Find(account.Id)!.SessionVersion;
        var service = new AccountProvisioningService(db.Store);
        Assert.True(service.IsCurrentSession(account.Id, stamp));
        db.Store.SetStatus(account.Id, SecurityAccountStatus.Disabled, "administrator");
        Assert.False(service.IsCurrentSession(account.Id, stamp));
        Assert.False(service.IsCurrentSession(account.Id, stamp, requireActive: false));
    }

    [Fact]
    public void RevokingSessionsCannotBeUndoneByReenablingAnAccount()
    {
        using var db = new Database();
        var account = db.Store.Resolve(Identity(), AccountPopulation.PublicApplicant, true).Account;
        db.Store.RevokeSessions(account.Id, "administrator");
        db.Store.SetStatus(account.Id, SecurityAccountStatus.Active, "administrator");
        Assert.False(new AccountProvisioningService(db.Store).IsCurrentSession(account.Id, account.SessionVersion));
    }

    [Fact]
    public void IdentityLinkingCannotTakeOverAnotherAccount()
    {
        using var db = new Database();
        var first = db.Store.Resolve(Identity(), AccountPopulation.Staff, true).Account;
        var second = db.Store.Resolve(Identity("second", "bob"), AccountPopulation.Staff, true).Account;
        Assert.Throws<IdentityAlreadyLinkedException>(() => db.Store.Link(second.Id, Identity(), "administrator"));
        Assert.Equal(first.Id, db.Store.Resolve(Identity(), AccountPopulation.Staff, true).Account.Id);
    }

    [Fact]
    public void LinkingAndUnlinkingAreAuditedAndInvalidateSessions()
    {
        using var db = new Database();
        var account = db.Store.Resolve(Identity(), AccountPopulation.Staff, true).Account;
        VerifiedIdentity alternate = Identity("alternate", "alias");
        db.Store.Link(account.Id, alternate, "administrator");
        Assert.Equal(account.Id, db.Store.Resolve(alternate, AccountPopulation.Staff, true).Account.Id);
        Assert.Equal(account.SessionVersion + 1, db.Store.Find(account.Id)!.SessionVersion);
        db.Store.Unlink(account.Id, alternate.Key, "administrator");
        Assert.Equal(account.SessionVersion + 2, db.Store.Find(account.Id)!.SessionVersion);
        Assert.Equal(3L, db.Scalar("SELECT COUNT(*) FROM common_security_account_events"));
    }

    [Fact]
    public void StaffAndApplicantPopulationsCannotBeImplicitlyConverted()
    {
        using var db = new Database();
        db.Store.Resolve(Identity(), AccountPopulation.PublicApplicant, true);
        Assert.Throws<InvalidOperationException>(() => db.Store.Resolve(Identity(), AccountPopulation.Staff, true));
    }

    [Fact]
    public void ProvisioningRollsBackIfItsAuditCannotBeWritten()
    {
        using var db = new Database();
        db.Execute("CREATE TRIGGER reject_security_audit BEFORE INSERT ON common_security_account_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;");
        Assert.Throws<SqliteException>(() => db.Store.Resolve(Identity(), AccountPopulation.Staff, true));
        Assert.Empty(db.Store.List());
        Assert.Equal(0L, db.Scalar("SELECT COUNT(*) FROM common_security_identities"));
    }

    [Fact]
    public void SchemaInitializationIsIdempotentAndPreservesUnrelatedBusinessRecords()
    {
        using var db = new Database();
        db.Execute("CREATE TABLE business_records(id TEXT PRIMARY KEY,balance INTEGER);INSERT INTO business_records VALUES('existing',12345);");
        db.Store.EnsureSchema(); db.Store.EnsureSchema();
        Assert.Equal(12345L, db.Scalar("SELECT balance FROM business_records WHERE id='existing'"));
    }

    [Fact]
    public void DisabledAutomaticProvisioningDoesNotWriteAnAccount()
    {
        using var db = new Database();
        Assert.Throws<InvalidOperationException>(() => db.Store.Resolve(Identity(), AccountPopulation.Staff, false));
        Assert.Empty(db.Store.List());
    }

    [Fact]
    public void ActiveExternalAccountCannotBeCreatedWithoutItsApprovedIdentity()
    {
        using var db = new Database();
        Assert.Throws<ArgumentException>(() => db.Store.Create(new AccountCreation("id", "alice", "Alice",
            AuthenticationProviderKind.ActiveDirectory, AccountPopulation.Staff, SecurityAccountStatus.Active), "administrator"));
    }

    [Fact]
    public void StaleAuthenticationCannotProvisionAnAccount()
    {
        using var db = new Database();
        var old = new VerifiedIdentity(new ExternalIdentityKey("provider", "tenant", "id"), AuthenticationProviderKind.EntraId,
            "alice", "Alice", DateTimeOffset.UtcNow.AddHours(-1), "oidc");
        Assert.Throws<InvalidOperationException>(() => new AccountProvisioningService(db.Store).Provision(old, AccountPopulation.Staff));
    }

    internal static VerifiedIdentity Identity(string subject = "immutable-guid", string login = "alice", string? email = null)
        => new(new ExternalIdentityKey("directory", "immutable-directory", subject), AuthenticationProviderKind.ActiveDirectory,
            login, login, DateTimeOffset.UtcNow, "ldaps-password", email);

    internal sealed class Database : IDisposable
    {
        private readonly string path = Path.Combine(Path.GetTempPath(), "common-security-" + Guid.NewGuid().ToString("N") + ".db");
        internal RelationalAccountStore Store { get; }
        internal Database(TimeProvider? clock = null)
        {
            Store = new RelationalAccountStore(Connection, "test-application", clock);
            Store.EnsureSchema();
        }
        internal SqliteConnection Connection() => new($"Data Source={path};Pooling=False;Default Timeout=30;Foreign Keys=True");
        internal RelationalAccountStore OtherApplication(string application) => new(Connection, application);
        internal void Execute(string sql) { using var c = Connection(); c.Open(); using var q = c.CreateCommand(); q.CommandText = sql; q.ExecuteNonQuery(); }
        internal object? Scalar(string sql) { using var c = Connection(); c.Open(); using var q = c.CreateCommand(); q.CommandText = sql; return q.ExecuteScalar(); }
        public void Dispose() { File.Delete(path); }
    }
}
