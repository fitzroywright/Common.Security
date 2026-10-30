namespace Common.Security.Services;

using System.Security.Cryptography;
using System.Text;

public sealed record MachineCredential(string CredentialId, string ApplicationId, string InstanceId,
    string SecretHash, IReadOnlyCollection<string> Scopes, DateTimeOffset ExpiresAt, DateTimeOffset? RevokedAt = null);

public interface IMachineCredentialStore
{
    MachineCredential? FindCredential(string credentialId);
}

public sealed record VerifiedMachineIdentity(string CredentialId, string ApplicationId, string InstanceId,
    IReadOnlyCollection<string> Scopes);

public sealed class MachineCredentialVerifier(IMachineCredentialStore store, TimeProvider? timeProvider = null)
{
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    public VerifiedMachineIdentity? Verify(string credentialId, string secret, string applicationId,
        string instanceId, string requiredScope)
    {
        if (string.IsNullOrWhiteSpace(credentialId) || string.IsNullOrWhiteSpace(secret) || secret.Length > 1024 ||
            string.IsNullOrWhiteSpace(requiredScope)) return null;
        MachineCredential? credential = store.FindCredential(credentialId);
        if (credential is null || credential.RevokedAt.HasValue || credential.ExpiresAt <= clock.GetUtcNow() ||
            credential.ApplicationId != applicationId || credential.InstanceId != instanceId ||
            !credential.Scopes.Contains(requiredScope, StringComparer.Ordinal)) return null;
        if (!MachineCredentialProof.Verify(credential.SecretHash,secret)) return null;
        return new VerifiedMachineIdentity(credential.CredentialId, credential.ApplicationId, credential.InstanceId,
            Array.AsReadOnly(credential.Scopes.ToArray()));
    }

    /// <summary>Provision high-entropy credentials once, store only this digest, and deliver the secret through Common.Secrets.</summary>
    public static (string Secret, string Digest) GenerateSecret()
    {
        string secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        return (secret, MachineCredentialProof.Hash(secret));
    }
}
