namespace Common.Security.UnitTests;

using Common.Security.Abstractions;
using Common.Security.Models;
using Common.Security.Services;
using Xunit;

public sealed class IdentityMigrationTests
{
    [Fact]
    public void ApprovedMigrationPreservesIdentifiersAndDoesNotReactivateDisabledAccountsOnReapplication()
    {
        using var db = new AccountProvisioningTests.Database();
        AccountCreation row = Row("existing-id", "existing-alias", "directory-guid");
        db.Store.ImportApprovedAccounts([row], "migration:approved-001");
        db.Store.SetStatus(row.Id, SecurityAccountStatus.Disabled, "administrator");
        long version = db.Store.Find(row.Id)!.SessionVersion;
        var repeated = Assert.Single(db.Store.ImportApprovedAccounts([row], "migration:approved-001"));
        Assert.Equal(row.Id, repeated.Id);
        Assert.Equal(row.LoginName, repeated.LoginName);
        Assert.Equal(SecurityAccountStatus.Disabled, repeated.Status);
        Assert.Equal(version, repeated.SessionVersion);
        Assert.Equal(2L, db.Scalar("SELECT COUNT(*) FROM common_security_account_events"));
    }

    [Fact]
    public void ConflictingBindingRollsBackTheEntireMigrationBatch()
    {
        using var db = new AccountProvisioningTests.Database();
        db.Store.Create(Row("reserved", "reserved-alias", "reserved-subject"), "administrator");
        Assert.Throws<IdentityAlreadyLinkedException>(() => db.Store.ImportApprovedAccounts([
            Row("new-one", "new-alias", "new-subject"), Row("conflict", "another-alias", "reserved-subject")], "migration:invalid"));
        Assert.Single(db.Store.List());
        Assert.Null(db.Store.Find("new-one"));
        Assert.Equal(1L, db.Scalar("SELECT COUNT(*) FROM common_security_account_events"));
    }

    [Fact]
    public void AuthorizationChangesAndSessionRevocationShareTheSameTransaction()
    {
        using var db = new AccountProvisioningTests.Database();
        db.Store.Create(Row("existing", "existing", "subject"), "administrator");
        db.Execute("CREATE TABLE application_roles(account_id TEXT,role TEXT)");
        long version = db.Store.Find("existing")!.SessionVersion;
        Assert.Throws<InvalidOperationException>(() => db.Store.ChangeAuthorization("existing", "administrator", (c,t) =>
        {
            using var q = c.CreateCommand();q.Transaction=t;q.CommandText="INSERT INTO application_roles VALUES('existing','Manager')";q.ExecuteNonQuery();
            throw new InvalidOperationException("Role persistence failed");
        }));
        Assert.Equal(0L, db.Scalar("SELECT COUNT(*) FROM application_roles"));
        Assert.Equal(version, db.Store.Find("existing")!.SessionVersion);
        db.Store.ChangeAuthorization("existing", "administrator", (c,t) =>
        { using var q=c.CreateCommand();q.Transaction=t;q.CommandText="INSERT INTO application_roles VALUES('existing','Manager')";q.ExecuteNonQuery(); });
        Assert.Equal(1L, db.Scalar("SELECT COUNT(*) FROM application_roles"));
        Assert.False(new AccountProvisioningService(db.Store).IsCurrentSession("existing", version));
    }

    [Fact]
    public async Task HandoffProofCanOnlyBeConsumedOnceAcrossConcurrentRequests()
    {
        using var db = new AccountProvisioningTests.Database();
        string id = Guid.NewGuid().ToString("D");
        bool[] consumed = await Task.WhenAll(Enumerable.Range(0,12).Select(_ => Task.Run(() =>
            db.Store.ConsumeHandoff(id, DateTimeOffset.UtcNow.AddSeconds(45)))));
        Assert.Single(consumed, x => x);
    }

    private static AccountCreation Row(string id, string login, string subject) => new(id, login, login,
        AuthenticationProviderKind.ActiveDirectory, AccountPopulation.Staff, SecurityAccountStatus.Active,
        new ExternalIdentityKey("active-directory", "directory-scope", subject));
}
