namespace Common.Security.Hosting;

using System.Globalization;
using System.Security.Claims;
using System.Text;
using Common.Security.Abstractions;
using Common.Security.Authenticators;
using Common.Security.Authorization;
using Common.Security.Integration;
using Common.Security.Models;
using Common.Security.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

public sealed record SuiteApplication(string ApplicationId, string CookieName,
    IReadOnlyDictionary<string, string[]> Roles);

public sealed record SuiteIdentity(string UserName, string DisplayName, string Title, string[] Permissions,
    string? AccountId = null, long SessionVersion = 0, ExternalIdentityKey? ExternalIdentity = null,
    AuthenticationProviderKind ProviderKind = AuthenticationProviderKind.ActiveDirectory,
    DateTimeOffset AuthenticatedAt = default);

/// <summary>One human-authentication/session/handoff mechanism; hosts supply their permission policy.</summary>
public sealed class SuiteSecurity
{
    public const string Scheme = "Common.Security.Suite";
    private const string DevelopmentSigningKey = "Common.Security.Isolated.Development.Handoff.Key.Never.Production";
    private readonly IConfiguration configuration;
    private readonly IHostEnvironment environment;
    private readonly IServiceProvider services;
    private readonly IAccountStore accounts;
    private readonly SuiteApplication application;
    private readonly SessionTicketProtector handoffs;

    public SuiteSecurity(IConfiguration configuration, IHostEnvironment environment, IServiceProvider services,
        IAccountStore accounts, SuiteApplication application)
    {
        this.configuration = configuration; this.environment = environment; this.services = services;
        this.accounts = accounts; this.application = application;
        string? key = configuration["SuiteSecurity:SigningKey"];
        if (environment.IsDevelopment()) key ??= DevelopmentSigningKey;
        if (string.IsNullOrWhiteSpace(key) || !environment.IsDevelopment() && key == DevelopmentSigningKey)
            throw new InvalidOperationException("A protected SuiteSecurity:SigningKey is required outside Development.");
        handoffs = new SessionTicketProtector(Encoding.UTF8.GetBytes(key));
    }

    public string Mode => configuration["SuiteSecurity:Mode"] ?? (environment.IsDevelopment() ? "Mock" : "ActiveDirectory");
    public int IdleTimeoutMinutes => Math.Clamp(configuration.GetValue("SuiteSecurity:IdleTimeoutMinutes", 30), 5, 60);
    public bool EntraEnabled => configuration.GetValue("SuiteSecurity:Entra:Enabled", false);

    public SuiteIdentity? Authenticate(string loginName, string password)
    {
        AuthenticationResult result = Mode.ToUpperInvariant() switch
        {
            "ACTIVEDIRECTORY" => services.GetService<IAuthenticator>()?.Authenticate(loginName, password)
                ?? AuthenticationResult.Failed(AuthenticationFailure.ProviderUnavailable),
            "LOCALDATABASE" => new LocalDatabaseAuthenticator(services.GetRequiredService<ILocalCredentialStore>()).Authenticate(loginName, password),
            "MOCK" => new MockAuthenticator(MockAuthenticationConfiguration.Read(configuration.GetSection("SuiteSecurity:Mock"),
                environment.EnvironmentName, "control-plane")).Authenticate(loginName, password),
            _ => AuthenticationResult.Failed(AuthenticationFailure.Prohibited)
        };
        if (!result.IsAuthenticated) return null;
        return AcceptVerifiedIdentity(result.Identity!);
    }

    public SuiteIdentity? AcceptVerifiedIdentity(VerifiedIdentity identity)
    {
        SecurityAccount account;
        try { account = new AccountProvisioningService(accounts).Provision(identity, AccountPopulation.Staff).Account; }
        catch (IdentityEnrollmentRequiredException) { return null; }
        return Project(account, identity.Key, identity.ProviderKind, identity.AuthenticatedAt);
    }

    public SuiteIdentity? Read(HttpRequest request)
    {
        if (request.HttpContext.Items.TryGetValue("SuiteIdentity", out object? cached) && cached is SuiteIdentity existing) return existing;
        if (request.Headers.TryGetValue("X-Aegis-Suite-Handoff", out var header))
        {
            if (header.Count != 1) return null;
            var handoff = AcceptHandoff(header[0]!);
            if (handoff is not null) request.HttpContext.Items["SuiteIdentity"] = handoff;
            return handoff;
        }
        SuiteIdentity? identity = ReadPrincipal(request.HttpContext.User);
        if (identity is not null) request.HttpContext.Items["SuiteIdentity"] = identity;
        return identity;
    }

    internal SuiteIdentity? ReadPrincipal(ClaimsPrincipal user)
    {
        if (user.Identity?.IsAuthenticated != true) return null;
        string? accountId = user.FindFirstValue(AccountSecurityHosting.AccountIdClaim);
        string? version = user.FindFirstValue(AccountSecurityHosting.SessionVersionClaim);
        if (accountId is null || !long.TryParse(version, NumberStyles.None, CultureInfo.InvariantCulture, out long stamp) ||
            !new AccountProvisioningService(accounts).IsCurrentSession(accountId, stamp)) return null;
        string? provider = user.FindFirstValue("provider_id"), scope = user.FindFirstValue("provider_scope"), subject = user.FindFirstValue("provider_subject");
        if (provider is null || scope is null || subject is null ||
            !Enum.TryParse(user.FindFirstValue("authentication_source"), out AuthenticationProviderKind kind)) return null;
        var key = new ExternalIdentityKey(provider, scope, subject);
        if (!accounts.GetIdentities(accountId).Any(x => x.Key == key && x.ProviderKind == kind)) return null;
        DateTimeOffset time = long.TryParse(user.FindFirstValue("authentication_time"), out long seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds) : DateTimeOffset.UtcNow;
        SuiteIdentity? identity = Project(accounts.Find(accountId)!, key, kind, time);
        return identity;
    }

    public ClaimsPrincipal CreatePrincipal(SuiteIdentity identity)
    {
        SecurityAccount? account = identity.AccountId is null ? null : accounts.Find(identity.AccountId);
        if (account is null || identity.ExternalIdentity is null ||
            !new AccountProvisioningService(accounts).IsCurrentSession(account.Id, identity.SessionVersion))
            throw new UnauthorizedAccessException("A current approved account is required.");
        if (Project(account, identity.ExternalIdentity, identity.ProviderKind, identity.AuthenticatedAt) is null ||
            !accounts.GetIdentities(account.Id).Any(x => x.Key == identity.ExternalIdentity && x.ProviderKind == identity.ProviderKind))
            throw new UnauthorizedAccessException("The account no longer has approved access or its identity has been unlinked.");
        var verified = new VerifiedIdentity(identity.ExternalIdentity, identity.ProviderKind, account.LoginName,
            account.DisplayName, identity.AuthenticatedAt, "suite-session");
        List<Claim> claims = [new(ClaimTypes.NameIdentifier, account.Id), new(ClaimTypes.Name, account.DisplayName),
            new("login_name", account.LoginName), new("provider_id", verified.Key.ProviderId),
            new("provider_scope", verified.Key.ScopeId), new("provider_subject", verified.Key.SubjectId),
            new("authentication_time", identity.AuthenticatedAt.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture))];
        claims.AddRange(AccountSecurityHosting.SessionClaims(account, verified));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme));
    }

    public Task SignInAsync(HttpContext context, SuiteIdentity identity)
        => context.SignInAsync(Scheme, CreatePrincipal(identity), new AuthenticationProperties
        { IsPersistent = false, AllowRefresh = true, ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(IdleTimeoutMinutes) });

    public Task SignOutAsync(HttpContext context) => context.SignOutAsync(Scheme);

    public string CreateHandoff(SuiteIdentity identity, string audience)
    {
        if (identity.AccountId is null || identity.ExternalIdentity is null ||
            !new AccountProvisioningService(accounts).IsCurrentSession(identity.AccountId, identity.SessionVersion))
            throw new UnauthorizedAccessException("A current approved account is required.");
        return handoffs.Create(identity.AccountId, audience, identity.SessionVersion, TimeSpan.FromSeconds(45), "handoff", identity.ExternalIdentity);
    }

    public SuiteIdentity? AcceptHandoff(string token)
    {
        var ticket = handoffs.Validate(token, application.ApplicationId, "handoff", value =>
            new AccountProvisioningService(accounts).IsCurrentSession(value.AccountId, value.SessionVersion) &&
            accounts.GetIdentities(value.AccountId).Any(x => x.Key == value.ExternalIdentity) &&
            services.GetRequiredService<RelationalAccountStore>().ConsumeHandoff(value.Id, DateTimeOffset.FromUnixTimeSeconds(value.ExpiresAt)));
        if (ticket?.ExternalIdentity is null) return null;
        SecurityAccount? account = accounts.Find(ticket.AccountId);
        var binding = accounts.GetIdentities(ticket.AccountId).SingleOrDefault(x => x.Key == ticket.ExternalIdentity);
        return account is null || binding is null ? null : Project(account, ticket.ExternalIdentity, binding.ProviderKind,
            DateTimeOffset.FromUnixTimeSeconds(ticket.IssuedAt));
    }

    private SuiteIdentity? Project(SecurityAccount account, ExternalIdentityKey key, AuthenticationProviderKind kind, DateTimeOffset authenticatedAt)
    {
        if (account.Status != SecurityAccountStatus.Active) return null;
        var authorizer = new PermissionAuthorizer(new ConfiguredRoleStore(configuration, application));
        var subject = AuthorizationSubject.Create(account.Id, []);
        string[] permissions = application.Roles.Values.SelectMany(x => x).Distinct(StringComparer.OrdinalIgnoreCase)
            .Where(permission => authorizer.CanAsync(subject, permission).GetAwaiter().GetResult()).ToArray();
        return permissions.Length == 0 ? null : new(account.LoginName, account.DisplayName, "Operator", permissions,
            account.Id, account.SessionVersion, key, kind, authenticatedAt);
    }

    private sealed class ConfiguredRoleStore(IConfiguration configuration, SuiteApplication application) : IAuthorizationStore
    {
        public Task<IReadOnlyCollection<string>> GetDirectRoleKeysAsync(string subjectId, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyCollection<string>>(configuration.GetSection("SuiteSecurity:AccountRoles:" + subjectId).Get<string[]>() ?? []);
        public Task<IReadOnlyCollection<string>> GetRoleKeysForGroupsAsync(IReadOnlyCollection<string> groups, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyCollection<string>>([]);
        public Task<IReadOnlyCollection<RoleDefinition>> GetRolesAsync(IReadOnlyCollection<string> keys, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyCollection<RoleDefinition>>(keys.Where(application.Roles.ContainsKey)
                .Select(key => new RoleDefinition(key, key, application.Roles[key])).ToArray());
    }
}
