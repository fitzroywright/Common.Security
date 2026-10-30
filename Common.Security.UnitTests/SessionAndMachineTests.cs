namespace Common.Security.UnitTests;

using Common.Security.Services;
using Xunit;

public sealed class SessionAndMachineTests
{
    [Fact]
    public void SessionRequiresCorrectAudiencePurposeAndCurrentVersion()
    {
        var protector = new SessionTicketProtector(new byte[32]);
        string token = protector.Create("account", "application", 3, TimeSpan.FromMinutes(5));
        Assert.NotNull(protector.Validate(token, "application", "session", x => x.SessionVersion == 3));
        Assert.Null(protector.Validate(token, "another-application", "session", _ => true));
        Assert.Null(protector.Validate(token, "application", "handoff", _ => true));
        Assert.Null(protector.Validate(token, "application", "session", x => x.SessionVersion == 4));
        Assert.Null(protector.Validate(token + "tampered", "application", "session", _ => true));
    }

    [Fact]
    public void SessionExpiryIsEnforcedAndSigningKeyIsCopied()
    {
        var clock = new Clock();
        byte[] key = new byte[32];
        var protector = new SessionTicketProtector(key, clock);
        string token = protector.Create("account", "application", 1, TimeSpan.FromMinutes(1));
        key[0] = 1;
        Assert.NotNull(protector.Validate(token, "application", "session", _ => true));
        clock.Advance(TimeSpan.FromMinutes(1));
        Assert.Null(protector.Validate(token, "application", "session", _ => true));
    }

    [Fact]
    public void WeakSigningKeysAndLongLivedHandoffsAreRejected()
    {
        Assert.Throws<ArgumentException>(() => new SessionTicketProtector(new byte[8]));
        Assert.Throws<ArgumentException>(() => new SessionTicketProtector(new byte[32]).Create(
            "account", "app", 1, TimeSpan.FromMinutes(2), "handoff"));
    }

    [Fact]
    public void MachineProofRequiresCredentialAndExactScopeAndIdentity()
    {
        var secret = MachineCredentialVerifier.GenerateSecret();
        var store = new MachineStore(new("credential", "app", "instance", secret.Digest,
            ["diagnostics.publish"], DateTimeOffset.UtcNow.AddHours(1)));
        var verifier = new MachineCredentialVerifier(store);
        Assert.NotNull(verifier.Verify("credential", secret.Secret, "app", "instance", "diagnostics.publish"));
        Assert.Null(verifier.Verify("credential", "invalid", "app", "instance", "diagnostics.publish"));
        Assert.Null(verifier.Verify("credential", secret.Secret, "another-app", "instance", "diagnostics.publish"));
        Assert.Null(verifier.Verify("credential", secret.Secret, "app", "another-instance", "diagnostics.publish"));
        Assert.Null(verifier.Verify("credential", secret.Secret, "app", "instance", "configuration.write"));
        Assert.Null(verifier.Verify("credential", "", "app", "instance", "diagnostics.publish"));
    }

    [Fact]
    public void MachineRevocationAndRotationAreConsultedOnEveryVerification()
    {
        var secret = MachineCredentialVerifier.GenerateSecret();
        var store = new MachineStore(new("credential", "app", "instance", secret.Digest,
            ["publish"], DateTimeOffset.UtcNow.AddHours(1)));
        var verifier = new MachineCredentialVerifier(store);
        Assert.NotNull(verifier.Verify("credential", secret.Secret, "app", "instance", "publish"));
        store.Value = store.Value with { RevokedAt = DateTimeOffset.UtcNow };
        Assert.Null(verifier.Verify("credential", secret.Secret, "app", "instance", "publish"));
        var rotated = MachineCredentialVerifier.GenerateSecret();
        store.Value = store.Value with { RevokedAt = null, SecretHash = rotated.Digest };
        Assert.Null(verifier.Verify("credential", secret.Secret, "app", "instance", "publish"));
        Assert.NotNull(verifier.Verify("credential", rotated.Secret, "app", "instance", "publish"));
    }

    [Fact]
    public void ExpiredMachineCredentialCannotAuthenticate()
    {
        var secret = MachineCredentialVerifier.GenerateSecret();
        var store = new MachineStore(new("credential", "app", "instance", secret.Digest,
            ["publish"], DateTimeOffset.UtcNow.AddSeconds(-1)));
        Assert.Null(new MachineCredentialVerifier(store).Verify("credential", secret.Secret, "app", "instance", "publish"));
    }

    private sealed class MachineStore(MachineCredential value) : IMachineCredentialStore
    {
        public MachineCredential Value { get; set; } = value;
        public MachineCredential? FindCredential(string id) => id == Value.CredentialId ? Value : null;
    }
    private sealed class Clock : TimeProvider
    {
        private DateTimeOffset now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => now;
        public void Advance(TimeSpan duration) => now += duration;
    }
}
