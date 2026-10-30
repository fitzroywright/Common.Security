namespace Common.Security.Integration;

using System.Data;
using System.Data.Common;
using Common.Security.Abstractions;
using Common.Security.Models;

/// <summary>
/// Shared storage mechanism for application-owned SQLite or PostgreSQL databases.
/// The host supplies its connection factory and application namespace. Business tables
/// and role assignments are deliberately outside this schema.
/// </summary>
public sealed partial class RelationalAccountStore : IAccountStore, ILocalCredentialStore
{
    private readonly Func<DbConnection> connectionFactory;
    private readonly string applicationId;
    private readonly TimeProvider clock;
    private readonly Action<DbConnection, DbTransaction, SecurityAccount, VerifiedIdentity?>? provisionApplicationRecord;

    public RelationalAccountStore(Func<DbConnection> connectionFactory, string applicationId,
        TimeProvider? timeProvider = null,
        Action<DbConnection, DbTransaction, SecurityAccount, VerifiedIdentity?>? provisionApplicationRecord = null)
    {
        this.connectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));
        ArgumentException.ThrowIfNullOrWhiteSpace(applicationId);
        this.applicationId = applicationId;
        clock = timeProvider ?? TimeProvider.System;
        this.provisionApplicationRecord = provisionApplicationRecord;
    }

    public void EnsureSchema() => Write((c, t) =>
    {
        Execute(c, t, """
            CREATE TABLE IF NOT EXISTS common_security_accounts (
                application_id text NOT NULL, account_id text NOT NULL,
                login_name text NOT NULL, login_key text NOT NULL, display_name text NOT NULL,
                provider_kind integer NOT NULL, population integer NOT NULL, status integer NOT NULL,
                session_version bigint NOT NULL DEFAULT 1,
                PRIMARY KEY(application_id,account_id), UNIQUE(application_id,login_key));
            CREATE TABLE IF NOT EXISTS common_security_identities (
                application_id text NOT NULL, provider_id text NOT NULL,
                scope_id text NOT NULL, subject_id text NOT NULL,
                provider_kind integer NOT NULL, account_id text NOT NULL,
                PRIMARY KEY(application_id,provider_id,scope_id,subject_id),
                FOREIGN KEY(application_id,account_id)
                    REFERENCES common_security_accounts(application_id,account_id));
            CREATE TABLE IF NOT EXISTS common_security_revoked_identities (
                application_id text NOT NULL, provider_id text NOT NULL, scope_id text NOT NULL, subject_id text NOT NULL,
                PRIMARY KEY(application_id,provider_id,scope_id,subject_id));
            CREATE TABLE IF NOT EXISTS common_security_account_events (
                application_id text NOT NULL, event_id text NOT NULL, account_id text NOT NULL,
                actor_id text NOT NULL, action text NOT NULL, occurred_at text NOT NULL,
                PRIMARY KEY(application_id,event_id));
            CREATE TABLE IF NOT EXISTS common_security_local_credentials (
                application_id text NOT NULL, account_id text NOT NULL, password_hash text NOT NULL,
                failures integer NOT NULL DEFAULT 0, locked_until text NULL,
                PRIMARY KEY(application_id,account_id),
                FOREIGN KEY(application_id,account_id)
                    REFERENCES common_security_accounts(application_id,account_id));
            CREATE TABLE IF NOT EXISTS common_security_recovery (
                application_id text NOT NULL, token_id text NOT NULL, account_id text NOT NULL,
                secret_hash text NOT NULL, expires_at text NOT NULL, consumed integer NOT NULL DEFAULT 0,
                PRIMARY KEY(application_id,token_id),
                FOREIGN KEY(application_id,account_id)
                    REFERENCES common_security_accounts(application_id,account_id));
            CREATE TABLE IF NOT EXISTS common_security_consumed_handoffs (
                application_id text NOT NULL, ticket_id text NOT NULL, expires_at text NOT NULL,
                PRIMARY KEY(application_id,ticket_id));
            """);
        return 0;
    });

    public AccountResolution Resolve(VerifiedIdentity identity, AccountPopulation population,
        bool allowAutomaticCreation)
    {
        ArgumentNullException.ThrowIfNull(identity);
        if (!Enum.IsDefined(population)) throw new ArgumentOutOfRangeException(nameof(population));
        return Write((c, t) =>
        {
            SecurityAccount? linked = FindIdentity(c, t, identity);
            if (linked is not null)
            {
                if (linked.Population != population)
                    throw new InvalidOperationException("The identity belongs to a different account population.");
                return new AccountResolution(linked, false);
            }
            if (IsRevoked(c,t,identity.Key)) throw new InvalidOperationException("This external identity requires administrator reenrollment.");
            if (!allowAutomaticCreation)
                throw new InvalidOperationException("Automatic provisioning is disabled.");
            if (FindLogin(c, t, identity.LoginName) is not null)
                throw new IdentityEnrollmentRequiredException();

            SecurityAccountStatus status = population == AccountPopulation.PublicApplicant
                ? SecurityAccountStatus.Active : SecurityAccountStatus.PendingAccess;
            var creation = new AccountCreation(Guid.NewGuid().ToString("D"), identity.LoginName,
                identity.DisplayName, identity.ProviderKind, population, status, identity.Key);
            SecurityAccount created = Insert(c, t, creation, retryContention: true);
            provisionApplicationRecord?.Invoke(c, t, created, identity);
            Audit(c, t, created.Id, "provider:" + identity.Key.ProviderId, "AccountAutomaticallyProvisioned");
            return new AccountResolution(created, true);
        });
    }

    public SecurityAccount Create(AccountCreation account, string actorId, string? initialLocalPassword = null)
    {
        ValidateActor(actorId);
        ArgumentNullException.ThrowIfNull(account);
        ArgumentException.ThrowIfNullOrWhiteSpace(account.Id);
        ArgumentException.ThrowIfNullOrWhiteSpace(account.LoginName);
        ArgumentException.ThrowIfNullOrWhiteSpace(account.DisplayName);
        if (account.Id.Length > 500 || account.LoginName.Length > 500 || account.DisplayName.Length > 500)
            throw new ArgumentException("Account fields exceed their maximum length.");
        if (initialLocalPassword is not null && account.ProviderKind != AuthenticationProviderKind.LocalDatabase)
            throw new ArgumentException("Passwords can only be enrolled for local accounts.");
        string? initialHash = initialLocalPassword is null ? null : Common.Security.Services.PasswordHasher.Hash(initialLocalPassword);
        if (!Enum.IsDefined(account.Status) || !Enum.IsDefined(account.ProviderKind) || !Enum.IsDefined(account.Population))
            throw new ArgumentException("Invalid account state, provider or population.");
        if (account.ProviderKind == AuthenticationProviderKind.LocalDatabase && account.Identity is not null &&
            account.Identity != new ExternalIdentityKey("local", applicationId, account.Id))
            throw new ArgumentException("Local identities use the application account identifier.");
        if (account.AdditionalIdentities?.Count > 0 && account.ProviderKind == AuthenticationProviderKind.LocalDatabase)
            throw new ArgumentException("Local enrollment does not accept external bindings.");
        if (account.Status == SecurityAccountStatus.Active && account.Identity is null &&
            account.ProviderKind != AuthenticationProviderKind.LocalDatabase)
            throw new ArgumentException("An active external account requires an approved immutable identity binding.");
        return Write((c, t) =>
        {
            if (FindLogin(c, t, account.LoginName) is not null)
                throw new IdentityEnrollmentRequiredException();
            if (account.Identity is not null && IdentityExists(c, t, account.Identity))
                throw new IdentityAlreadyLinkedException();
            SecurityAccount created = Insert(c, t, account);
            provisionApplicationRecord?.Invoke(c, t, created, null);
            if (initialHash is not null) StorePassword(c, t, created.Id, initialHash);
            Audit(c, t, created.Id, actorId, "AccountAdministrativelyProvisioned");
            return created;
        });
    }

    public SecurityAccount? Find(string accountId)
    {
        using DbConnection c = Open();
        return FindAccount(c, null, accountId);
    }

    /// <summary>Approved immutable bindings only. The batch is atomic and reapplication never overwrites lifecycle changes.</summary>
    public IReadOnlyList<SecurityAccount> ImportApprovedAccounts(IEnumerable<AccountCreation> source, string actorId)
    {
        ValidateActor(actorId);
        AccountCreation[] rows = source.ToArray();
        if (rows.Length == 0 || rows.Any(x => x.Identity is null || x.ProviderKind == AuthenticationProviderKind.LocalDatabase ||
            string.IsNullOrWhiteSpace(x.Id) || string.IsNullOrWhiteSpace(x.LoginName) || string.IsNullOrWhiteSpace(x.DisplayName) ||
            !Enum.IsDefined(x.ProviderKind) || !Enum.IsDefined(x.Population) || !Enum.IsDefined(x.Status)))
            throw new ArgumentException("Every imported account requires its existing identifier, alias and approved immutable external binding.");
        if (rows.Select(x => x.Id).Distinct(StringComparer.Ordinal).Count() != rows.Length ||
            rows.Select(x => x.LoginName.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).Count() != rows.Length ||
            rows.SelectMany(Bindings).Distinct().Count() != rows.Sum(x => Bindings(x).Count()))
            throw new ArgumentException("The import contains conflicting account identifiers, aliases or identities.");
        return Write((c, t) =>
        {
            List<SecurityAccount> imported = [];
            foreach (AccountCreation row in rows)
            {
                var proof = new VerifiedIdentity(row.Identity!, row.ProviderKind, row.LoginName, row.DisplayName,
                    clock.GetUtcNow(), "approved-identity-migration");
                SecurityAccount? existing = FindAccount(c, t, row.Id);
                SecurityAccount? bound = FindIdentity(c, t, proof);
                var allBound = Bindings(row).Select(key => FindIdentity(c,t,new VerifiedIdentity(key,row.ProviderKind,row.LoginName,row.DisplayName,clock.GetUtcNow(),"approved-identity-migration"))).ToArray();
                if (existing is not null)
                {
                    if (allBound.Any(x => x?.Id != row.Id) || existing.LoginName != row.LoginName || existing.ProviderKind != row.ProviderKind || existing.Population != row.Population)
                        throw new IdentityEnrollmentRequiredException();
                    imported.Add(existing); // Preserve disabling, role changes and sessions after an earlier import.
                    continue;
                }
                if (allBound.Any(x => x is not null)) throw new IdentityAlreadyLinkedException();
                if (FindLogin(c, t, row.LoginName) is not null) throw new IdentityEnrollmentRequiredException();
                var created = Insert(c, t, row);
                provisionApplicationRecord?.Invoke(c, t, created, proof);
                Audit(c, t, created.Id, actorId, "ApprovedIdentityMigrationImported");
                imported.Add(created);
            }
            return imported;
        });
    }

    public IReadOnlyList<SecurityAccount> List()
    {
        using DbConnection c = Open();
        using DbCommand q = Command(c, null, SelectAccount +
            " WHERE application_id=@app ORDER BY login_key", ("app", applicationId));
        using DbDataReader reader = q.ExecuteReader();
        List<SecurityAccount> accounts = [];
        while (reader.Read()) accounts.Add(ReadAccount(reader));
        return accounts;
    }

    public IReadOnlyList<LinkedAuthenticationIdentity> GetIdentities(string accountId)
    {
        using DbConnection c = Open();
        using DbCommand q = Command(c, null, "SELECT provider_id,scope_id,subject_id,provider_kind FROM common_security_identities " +
            "WHERE application_id=@app AND account_id=@id ORDER BY provider_id,scope_id,subject_id", ("app", applicationId), ("id", accountId));
        using DbDataReader r = q.ExecuteReader();
        List<LinkedAuthenticationIdentity> identities = [];
        while (r.Read()) identities.Add(new(new ExternalIdentityKey(r.GetString(0), r.GetString(1), r.GetString(2)), (AuthenticationProviderKind)r.GetInt32(3)));
        return identities;
    }

    public void SetStatus(string accountId, SecurityAccountStatus status, string actorId)
    {
        ValidateActor(actorId);
        if (!Enum.IsDefined(status)) throw new ArgumentOutOfRangeException(nameof(status));
        Write((c, t) =>
        {
            RequireAccount(c, t, accountId);
            Execute(c, t, "UPDATE common_security_accounts SET status=@status,session_version=session_version+1 " +
                "WHERE application_id=@app AND account_id=@id", ("status", (int)status), ("app", applicationId), ("id", accountId));
            Audit(c, t, accountId, actorId, "AccountStatus:" + status);
            return 0;
        });
    }

    public void RevokeSessions(string accountId, string actorId)
    {
        ValidateActor(actorId);
        Write((c, t) => { BumpVersion(c, t, accountId); Audit(c, t, accountId, actorId, "SessionsRevoked"); return 0; });
    }

    public bool ConsumeHandoff(string ticketId, DateTimeOffset expiresAt)
    {
        if (!Guid.TryParseExact(ticketId, "D", out _) || expiresAt <= clock.GetUtcNow() ||
            expiresAt > clock.GetUtcNow().AddMinutes(1)) return false;
        return Write((c, t) =>
        {
            Execute(c, t, "DELETE FROM common_security_consumed_handoffs WHERE application_id=@app AND expires_at<@now",
                ("app", applicationId), ("now", clock.GetUtcNow().ToString("O")));
            return Execute(c, t, "INSERT INTO common_security_consumed_handoffs(application_id,ticket_id,expires_at) " +
                "VALUES(@app,@ticket,@expires) ON CONFLICT DO NOTHING", ("app", applicationId),
                ("ticket", ticketId), ("expires", expiresAt.ToUniversalTime().ToString("O"))) == 1;
        });
    }

    /// <summary>Application role persistence and session invalidation share one transaction.</summary>
    public void ChangeAuthorization(string accountId, string actorId, Action<DbConnection, DbTransaction> persistApplicationRoles)
    {
        ValidateActor(actorId);
        ArgumentNullException.ThrowIfNull(persistApplicationRoles);
        Write((c, t) =>
        {
            RequireAccount(c, t, accountId);
            persistApplicationRoles(c, t);
            BumpVersion(c, t, accountId);
            Audit(c, t, accountId, actorId, "ApplicationAuthorizationChanged");
            return 0;
        });
    }

    /// <summary>Caller must authorize the administrator or verify fresh proof for both accounts.</summary>
    public void Link(string accountId, VerifiedIdentity identity, string actorId)
    {
        ValidateActor(actorId);
        Write((c, t) =>
        {
            RequireAccount(c, t, accountId);
            SecurityAccount? linked = FindIdentity(c, t, identity);
            if (linked is not null)
            {
                if (linked.Id != accountId) throw new IdentityAlreadyLinkedException();
                return 0;
            }
            Execute(c,t,"DELETE FROM common_security_revoked_identities WHERE application_id=@app AND provider_id=@provider AND scope_id=@scope AND subject_id=@subject",
                ("app",applicationId),("provider",identity.Key.ProviderId),("scope",identity.Key.ScopeId),("subject",identity.Key.SubjectId));
            InsertIdentity(c, t, accountId, identity.Key, identity.ProviderKind);
            BumpVersion(c, t, accountId);
            Audit(c, t, accountId, actorId, "IdentityLinked");
            return 0;
        });
    }

    public void Unlink(string accountId, ExternalIdentityKey identity, string actorId)
    {
        ValidateActor(actorId);
        Write((c, t) =>
        {
            RequireAccount(c, t, accountId);
            int removed = Execute(c, t, "DELETE FROM common_security_identities WHERE application_id=@app " +
                "AND account_id=@id AND provider_id=@provider AND scope_id=@scope AND subject_id=@subject",
                ("app", applicationId), ("id", accountId), ("provider", identity.ProviderId),
                ("scope", identity.ScopeId), ("subject", identity.SubjectId));
            if (removed != 0)
            {
                Execute(c,t,"INSERT INTO common_security_revoked_identities(application_id,provider_id,scope_id,subject_id) VALUES(@app,@provider,@scope,@subject) ON CONFLICT DO NOTHING",
                    ("app",applicationId),("provider",identity.ProviderId),("scope",identity.ScopeId),("subject",identity.SubjectId));
                BumpVersion(c, t, accountId);
                Audit(c, t, accountId, actorId, "IdentityUnlinked");
            }
            return 0;
        });
    }

    private SecurityAccount Insert(DbConnection c, DbTransaction t, AccountCreation account, bool retryContention = false)
    {
        int inserted = Execute(c, t, """
            INSERT INTO common_security_accounts
            (application_id,account_id,login_name,login_key,display_name,provider_kind,population,status,session_version)
            VALUES (@app,@id,@login,@key,@display,@kind,@population,@status,1)
            """ + (retryContention ? " ON CONFLICT DO NOTHING" : ""), ("app", applicationId), ("id", account.Id), ("login", account.LoginName.Trim()),
            ("key", account.LoginName.Trim().ToUpperInvariant()), ("display", account.DisplayName),
            ("kind", (int)account.ProviderKind), ("population", (int)account.Population), ("status", (int)account.Status));
        if (inserted == 0) throw new ProvisioningContentionException();
        ExternalIdentityKey? key = account.Identity;
        if (account.ProviderKind == AuthenticationProviderKind.LocalDatabase)
            key ??= new ExternalIdentityKey("local", applicationId, account.Id);
        if (key is not null) InsertIdentity(c, t, account.Id, key, account.ProviderKind, retryContention);
        foreach (var extra in account.AdditionalIdentities ?? [])
            InsertIdentity(c, t, account.Id, extra, account.ProviderKind, retryContention);
        return new SecurityAccount(account.Id, account.LoginName.Trim(), account.DisplayName,
            account.ProviderKind, account.Population, account.Status, 1);
    }

    private static IEnumerable<ExternalIdentityKey> Bindings(AccountCreation row) =>
        row.Identity is null ? [] : new[] { row.Identity }.Concat(row.AdditionalIdentities ?? []);

    private void InsertIdentity(DbConnection c, DbTransaction t, string accountId,
        ExternalIdentityKey key, AuthenticationProviderKind kind, bool retryContention = false)
    {
        if(IsRevoked(c,t,key)) throw new InvalidOperationException("A revoked identity requires an explicit approved link.");
        int inserted = Execute(c, t,
            "INSERT INTO common_security_identities (application_id,provider_id,scope_id,subject_id,provider_kind,account_id) " +
            "VALUES (@app,@provider,@scope,@subject,@kind,@id) ON CONFLICT DO NOTHING", ("app", applicationId),
            ("provider", key.ProviderId), ("scope", key.ScopeId), ("subject", key.SubjectId),
            ("kind", (int)kind), ("id", accountId));
        if (inserted == 0)
        {
            if (retryContention) throw new ProvisioningContentionException();
            throw new IdentityAlreadyLinkedException();
        }
    }

    private SecurityAccount? FindIdentity(DbConnection c, DbTransaction t, VerifiedIdentity identity)
    {
        using DbCommand q = Command(c, t, """
            SELECT a.account_id,a.login_name,a.display_name,a.provider_kind,a.population,a.status,a.session_version,i.provider_kind
            FROM common_security_accounts a JOIN common_security_identities i
            ON a.application_id=i.application_id AND a.account_id=i.account_id
            WHERE i.application_id=@app AND i.provider_id=@provider AND i.scope_id=@scope AND i.subject_id=@subject
            """, ("app", applicationId), ("provider", identity.Key.ProviderId),
            ("scope", identity.Key.ScopeId), ("subject", identity.Key.SubjectId));
        using DbDataReader r = q.ExecuteReader();
        if (!r.Read()) return null;
        if (r.GetInt32(7) != (int)identity.ProviderKind)
            throw new InvalidOperationException("The registered provider kind does not match the verified identity.");
        return ReadAccount(r);
    }

    private bool IsRevoked(DbConnection c,DbTransaction t,ExternalIdentityKey identity)
    {
        using var q=Command(c,t,"SELECT 1 FROM common_security_revoked_identities WHERE application_id=@app AND provider_id=@provider AND scope_id=@scope AND subject_id=@subject",
            ("app",applicationId),("provider",identity.ProviderId),("scope",identity.ScopeId),("subject",identity.SubjectId));
        return q.ExecuteScalar() is not null;
    }

    private bool IdentityExists(DbConnection c, DbTransaction t, ExternalIdentityKey identity)
    {
        using DbCommand q = Command(c, t, "SELECT 1 FROM common_security_identities " +
            "WHERE application_id=@app AND provider_id=@provider AND scope_id=@scope AND subject_id=@subject",
            ("app", applicationId), ("provider", identity.ProviderId), ("scope", identity.ScopeId), ("subject", identity.SubjectId));
        return q.ExecuteScalar() is not null;
    }

    private SecurityAccount? FindAccount(DbConnection c, DbTransaction? t, string accountId)
        => QueryAccount(c, t, SelectAccount + " WHERE application_id=@app AND account_id=@value", accountId);
    private SecurityAccount? FindLogin(DbConnection c, DbTransaction t, string login)
        => QueryAccount(c, t, SelectAccount + " WHERE application_id=@app AND login_key=@value", login.Trim().ToUpperInvariant());
    private SecurityAccount? QueryAccount(DbConnection c, DbTransaction? t, string sql, string value)
    {
        using DbCommand q = Command(c, t, sql, ("app", applicationId), ("value", value));
        using DbDataReader reader = q.ExecuteReader();
        return reader.Read() ? ReadAccount(reader) : null;
    }

    private const string SelectAccount = "SELECT account_id,login_name,display_name,provider_kind,population,status,session_version FROM common_security_accounts";
    private static SecurityAccount ReadAccount(DbDataReader r) => new(r.GetString(0), r.GetString(1), r.GetString(2),
        (AuthenticationProviderKind)r.GetInt32(3), (AccountPopulation)r.GetInt32(4), (SecurityAccountStatus)r.GetInt32(5), r.GetInt64(6));

    private SecurityAccount RequireAccount(DbConnection c, DbTransaction t, string accountId)
        => FindAccount(c, t, accountId) ?? throw new KeyNotFoundException("Account was not found.");
    private void BumpVersion(DbConnection c, DbTransaction t, string accountId)
    {
        RequireAccount(c, t, accountId);
        Execute(c, t, "UPDATE common_security_accounts SET session_version=session_version+1 WHERE application_id=@app AND account_id=@id",
            ("app", applicationId), ("id", accountId));
    }

    private void Audit(DbConnection c, DbTransaction t, string accountId, string actorId, string action)
        => Execute(c, t, "INSERT INTO common_security_account_events " +
            "(application_id,event_id,account_id,actor_id,action,occurred_at) VALUES (@app,@event,@account,@actor,@action,@time)",
            ("app", applicationId), ("event", Guid.NewGuid().ToString("D")), ("account", accountId),
            ("actor", actorId), ("action", action), ("time", clock.GetUtcNow().ToString("O")));

    private static void ValidateActor(string actor) => ArgumentException.ThrowIfNullOrWhiteSpace(actor);
    private DbConnection Open()
    {
        DbConnection c = connectionFactory();
        try { if (c.State != ConnectionState.Open) c.Open(); return c; } catch { c.Dispose(); throw; }
    }
    private T Write<T>(Func<DbConnection, DbTransaction, T> action)
    {
        for (int attempt = 0; ; attempt++)
        {
            using DbConnection c = Open();
            using DbTransaction transaction = c.BeginTransaction(IsolationLevel.Serializable);
            try { T value = action(c, transaction); transaction.Commit(); return value; }
            catch (DbException e) when (e.IsTransient && attempt < 3)
            {
                transaction.Rollback();
                Thread.Sleep(10 * (attempt + 1));
            }
            catch (ProvisioningContentionException) when (attempt < 3)
            {
                transaction.Rollback();
                Thread.Sleep(10 * (attempt + 1));
            }
        }
    }
    private static DbCommand Command(DbConnection c, DbTransaction? t, string sql, params (string name, object value)[] parameters)
    {
        DbCommand q = c.CreateCommand(); q.Transaction = t; q.CommandText = sql;
        foreach (var (name, value) in parameters)
        {
            DbParameter p = q.CreateParameter(); p.ParameterName = "@" + name; p.Value = value; q.Parameters.Add(p);
        }
        return q;
    }
    private static int Execute(DbConnection c, DbTransaction? t, string sql, params (string name, object value)[] parameters)
    { using DbCommand q = Command(c, t, sql, parameters); return q.ExecuteNonQuery(); }

    private sealed class ProvisioningContentionException : InvalidOperationException { }
}
