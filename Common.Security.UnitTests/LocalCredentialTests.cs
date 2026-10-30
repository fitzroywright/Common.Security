namespace Common.Security.UnitTests;

using Common.Security.Abstractions;
using Common.Security.Models;
using Common.Security.Services;
using Xunit;

public sealed class LocalCredentialTests
{
    private const string Password = "A strong test passphrase 123";
    private const string Replacement = "A different test passphrase 456";

    [Fact]
    public void PasswordHashUsesIndependentSaltsAndRejectsWrongOrMalformedCredentials()
    {
        string one = PasswordHasher.Hash(Password), two = PasswordHasher.Hash(Password);
        Assert.NotEqual(one, two);
        Assert.True(PasswordHasher.Verify(Password, one));
        Assert.False(PasswordHasher.Verify("incorrect", one));
        Assert.False(PasswordHasher.Verify(Password, "pbkdf2-sha256$2147483647$a$b"));
        Assert.False(PasswordHasher.Verify(Password, "pbkdf2-sha256$600000$invalid$invalid"));
        Assert.Throws<ArgumentException>(() => PasswordHasher.Hash("short"));
    }

    [Fact]
    public void LocalIdentityIsApplicationScopedAndDoesNotContainPrivileges()
    {
        using var db = new AccountProvisioningTests.Database();
        CreateLocal(db);
        var result = db.Store.AuthenticateLocal("local.user", Password);
        Assert.True(result.IsAuthenticated);
        Assert.Equal(AuthenticationProviderKind.LocalDatabase, result.Identity!.ProviderKind);
        Assert.Equal("test-application", result.Identity.Key.ScopeId);
        Assert.Equal("local-id", result.Identity.Key.SubjectId);
        Assert.Empty(result.GroupNames);
        Assert.False(db.Store.AuthenticateLocal("missing-user", Password).IsAuthenticated);
        Assert.False(db.Store.AuthenticateLocal("local.user", "wrong password").IsAuthenticated);
    }

    [Fact]
    public async Task ConcurrentFailuresCannotBypassPersistentLockout()
    {
        var clock = new TestClock();
        using var db = new AccountProvisioningTests.Database(clock);
        CreateLocal(db);
        await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => Task.Run(() => db.Store.AuthenticateLocal("local.user", "incorrect"))));
        Assert.Equal(AuthenticationFailure.LockedOut, db.Store.AuthenticateLocal("local.user", Password).Failure);
        clock.Advance(TimeSpan.FromMinutes(16));
        Assert.True(db.Store.AuthenticateLocal("local.user", Password).IsAuthenticated);
    }

    [Fact]
    public void DisabledLocalAccountCannotAuthenticateOrRecover()
    {
        using var db = new AccountProvisioningTests.Database();
        CreateLocal(db);
        string recovery = db.Store.IssueRecovery("local-id", "administrator");
        db.Store.SetStatus("local-id", SecurityAccountStatus.Disabled, "administrator");
        Assert.False(db.Store.AuthenticateLocal("local.user", Password).IsAuthenticated);
        Assert.False(db.Store.Recover(recovery, Replacement));
        Assert.Throws<InvalidOperationException>(() => db.Store.IssueRecovery("local-id", "administrator"));
    }

    [Fact]
    public void RecoveryIsSingleUseAndRevokesEveryExistingSession()
    {
        using var db = new AccountProvisioningTests.Database();
        CreateLocal(db);
        long oldVersion = db.Store.Find("local-id")!.SessionVersion;
        string recovery = db.Store.IssueRecovery("local-id", "administrator");
        Assert.False(db.Store.Recover(recovery[..^1] + (recovery[^1] == 'X' ? "Y" : "X"), Replacement));
        Assert.True(db.Store.Recover(recovery, Replacement));
        Assert.False(db.Store.Recover(recovery, Password));
        Assert.False(db.Store.AuthenticateLocal("local.user", Password).IsAuthenticated);
        Assert.True(db.Store.AuthenticateLocal("local.user", Replacement).IsAuthenticated);
        Assert.False(new AccountProvisioningService(db.Store).IsCurrentSession("local-id", oldVersion));
    }

    [Fact]
    public void NewRecoveryReplacesEarlierRecoveryAndExpires()
    {
        var clock = new TestClock();
        using var db = new AccountProvisioningTests.Database(clock);
        CreateLocal(db);
        string first = db.Store.IssueRecovery("local-id", "administrator");
        string second = db.Store.IssueRecovery("local-id", "administrator");
        Assert.False(db.Store.Recover(first, Replacement));
        clock.Advance(TimeSpan.FromMinutes(16));
        Assert.False(db.Store.Recover(second, Replacement));
    }

    [Fact]
    public void PasswordAndRecoveryProofAreNotStoredInPlaintext()
    {
        using var db = new AccountProvisioningTests.Database();
        CreateLocal(db);
        string token = db.Store.IssueRecovery("local-id", "administrator");
        string stored = (string)db.Scalar("SELECT password_hash FROM common_security_local_credentials")!;
        string recovery = (string)db.Scalar("SELECT secret_hash FROM common_security_recovery")!;
        Assert.StartsWith("pbkdf2-sha256$600000$", stored);
        Assert.DoesNotContain(Password, stored);
        Assert.DoesNotContain(token.Split('.')[1], recovery);
        Assert.Equal(64, recovery.Length);
    }

    [Fact]
    public void ExternalAccountCannotSilentlyBecomeLocal()
    {
        using var db = new AccountProvisioningTests.Database();
        var account = db.Store.Resolve(AccountProvisioningTests.Identity(), AccountPopulation.Staff, true).Account;
        Assert.Throws<InvalidOperationException>(() => db.Store.SetLocalPassword(account.Id, Password, "administrator"));
    }

    private static void CreateLocal(AccountProvisioningTests.Database db)
    {
        db.Store.Create(new AccountCreation("local-id", "local.user", "Local user", AuthenticationProviderKind.LocalDatabase,
            AccountPopulation.Staff, SecurityAccountStatus.Active), "administrator");
        db.Store.SetLocalPassword("local-id", Password, "administrator");
    }

    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => now;
        public void Advance(TimeSpan duration) => now += duration;
    }
}
