namespace Common.Security.Integration;

using System.Data.Common;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Common.Security.Abstractions;
using Common.Security.Models;
using Common.Security.Services;

public sealed partial class RelationalAccountStore
{
    private static readonly string UnknownAccountHash = PasswordHasher.Hash("Unknown account timing verification only");

    public AuthenticationResult AuthenticateLocal(string loginName, string password)
    {
        if (string.IsNullOrWhiteSpace(loginName) || string.IsNullOrEmpty(password) || password.Length > PasswordHasher.MaximumLength)
            return AuthenticationResult.Failed();
        return Write((c, t) =>
        {
            SecurityAccount? account = FindLogin(c, t, loginName);
            if (account is null)
            {
                _ = PasswordHasher.Verify(password, UnknownAccountHash);
                return AuthenticationResult.Failed();
            }
            string? hash = null;
            int failures = 0;
            DateTimeOffset? lockedUntil = null;
            using (DbCommand q = Command(c, t, "SELECT password_hash,failures,locked_until FROM common_security_local_credentials " +
                "WHERE application_id=@app AND account_id=@id", ("app", applicationId), ("id", account.Id)))
            using (DbDataReader r = q.ExecuteReader())
            {
                if (r.Read())
                {
                    hash = r.GetString(0); failures = r.GetInt32(1);
                    if (!r.IsDBNull(2)) lockedUntil = DateTimeOffset.Parse(r.GetString(2), CultureInfo.InvariantCulture);
                }
            }
            if (hash is null || account.Status is SecurityAccountStatus.Disabled or SecurityAccountStatus.Suspended)
            {
                _ = PasswordHasher.Verify(password, UnknownAccountHash);
                Audit(c, t, account.Id, account.Id, "LocalAuthenticationDenied");
                return AuthenticationResult.Failed();
            }
            if (lockedUntil > clock.GetUtcNow())
                return AuthenticationResult.Failed(AuthenticationFailure.LockedOut);
            if (lockedUntil.HasValue) failures = 0;

            bool valid = PasswordHasher.Verify(password, hash);
            int updatedFailures = valid ? 0 : failures + 1;
            string? newLock = updatedFailures >= 5 ? clock.GetUtcNow().AddMinutes(15).ToString("O") : null;
            Execute(c, t, "UPDATE common_security_local_credentials SET failures=@failures,locked_until=@locked " +
                "WHERE application_id=@app AND account_id=@id", ("failures", updatedFailures),
                ("locked", (object?)newLock ?? DBNull.Value), ("app", applicationId), ("id", account.Id));
            Audit(c, t, account.Id, account.Id, valid ? "LocalAuthenticationSucceeded" : "LocalAuthenticationDenied");
            if (!valid) return AuthenticationResult.Failed();

            var identity = new VerifiedIdentity(new ExternalIdentityKey("local", applicationId, account.Id),
                AuthenticationProviderKind.LocalDatabase, account.LoginName, account.DisplayName,
                clock.GetUtcNow(), "password");
            if (FindIdentity(c, t, identity)?.Id != account.Id)
                return AuthenticationResult.Failed(AuthenticationFailure.Prohibited);
            return AuthenticationResult.Succeeded(identity, new ApplicationUserInfo { DisplayName = account.DisplayName });
        });
    }

    /// <summary>Host must authorize the actor or require fresh current-password proof.</summary>
    public void SetLocalPassword(string accountId, string newPassword, string actorId)
    {
        ValidateActor(actorId);
        string hash = PasswordHasher.Hash(newPassword);
        Write((c, t) =>
        {
            SecurityAccount account = RequireAccount(c, t, accountId);
            var identity = new VerifiedIdentity(new ExternalIdentityKey("local", applicationId, accountId),
                AuthenticationProviderKind.LocalDatabase, account.LoginName, account.DisplayName, clock.GetUtcNow(), "password");
            if (FindIdentity(c, t, identity)?.Id != accountId)
                throw new InvalidOperationException("Explicit local identity enrollment is required before setting a password.");
            StorePassword(c, t, accountId, hash);
            Execute(c, t, "UPDATE common_security_recovery SET consumed=1 WHERE application_id=@app AND account_id=@id",
                ("app", applicationId), ("id", accountId));
            BumpVersion(c, t, accountId);
            Audit(c, t, accountId, actorId, "LocalPasswordChanged");
            return 0;
        });
    }

    public string IssueRecovery(string accountId, string actorId)
    {
        ValidateActor(actorId);
        return Write((c, t) =>
        {
            SecurityAccount account = RequireAccount(c, t, accountId);
            if (account.Status is SecurityAccountStatus.Disabled or SecurityAccountStatus.Suspended)
                throw new InvalidOperationException("A disabled account cannot be recovered.");
            using (DbCommand q = Command(c, t, "SELECT 1 FROM common_security_local_credentials WHERE application_id=@app AND account_id=@id",
                ("app", applicationId), ("id", accountId)))
                if (q.ExecuteScalar() is null) throw new InvalidOperationException("Local credentials are not enrolled.");
            string id = Guid.NewGuid().ToString("D");
            string secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            Execute(c, t, "UPDATE common_security_recovery SET consumed=1 WHERE application_id=@app AND account_id=@id",
                ("app", applicationId), ("id", accountId));
            Execute(c, t, "INSERT INTO common_security_recovery " +
                "(application_id,token_id,account_id,secret_hash,expires_at,consumed) VALUES (@app,@token,@id,@hash,@expires,0)",
                ("app", applicationId), ("token", id), ("id", accountId), ("hash", Fingerprint(secret)),
                ("expires", clock.GetUtcNow().AddMinutes(15).ToString("O")));
            Audit(c, t, accountId, actorId, "LocalRecoveryIssued");
            return id + "." + secret;
        });
    }

    public bool Recover(string token, string newPassword)
    {
        if (string.IsNullOrWhiteSpace(token) || token.Length > 150) return false;
        string[] parts = token.Split('.');
        if (parts.Length != 2 || !Guid.TryParseExact(parts[0], "D", out _) || parts[1].Length != 43) return false;
        string hash = PasswordHasher.Hash(newPassword);
        return Write((c, t) =>
        {
            string? accountId = null;
            using (DbCommand q = Command(c, t, "SELECT account_id,secret_hash,expires_at,consumed FROM common_security_recovery " +
                "WHERE application_id=@app AND token_id=@token", ("app", applicationId), ("token", parts[0])))
            using (DbDataReader r = q.ExecuteReader())
            {
                if (!r.Read() || r.GetInt32(3) != 0 ||
                    DateTimeOffset.Parse(r.GetString(2), CultureInfo.InvariantCulture) <= clock.GetUtcNow() ||
                    !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(r.GetString(1)),
                        Encoding.UTF8.GetBytes(Fingerprint(parts[1])))) return false;
                accountId = r.GetString(0);
            }
            SecurityAccount account = RequireAccount(c, t, accountId);
            if (account.Status is SecurityAccountStatus.Disabled or SecurityAccountStatus.Suspended) return false;
            int consumed = Execute(c, t, "UPDATE common_security_recovery SET consumed=1 WHERE application_id=@app AND token_id=@token AND consumed=0",
                ("app", applicationId), ("token", parts[0]));
            if (consumed != 1) return false;
            StorePassword(c, t, accountId, hash);
            BumpVersion(c, t, accountId);
            Audit(c, t, accountId, accountId, "LocalAccountRecovered");
            return true;
        });
    }

    private void StorePassword(DbConnection c, DbTransaction t, string accountId, string hash)
        => Execute(c, t, "INSERT INTO common_security_local_credentials (application_id,account_id,password_hash,failures,locked_until) " +
            "VALUES (@app,@id,@hash,0,NULL) ON CONFLICT(application_id,account_id) DO UPDATE SET password_hash=excluded.password_hash,failures=0,locked_until=NULL",
            ("app", applicationId), ("id", accountId), ("hash", hash));

    private static string Fingerprint(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
