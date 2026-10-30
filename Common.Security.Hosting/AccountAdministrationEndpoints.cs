using System.Security.Claims;
using Common.Security.Abstractions;
using Common.Security.Hosting;
using Common.Security.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Common.Security.Services;

namespace Common.Security.Hosting;

public static class AccountAdministrationEndpoints
{
    public static void MapCommonAccountAdministration(this WebApplication app, string routePrefix, AccountPopulation population,
        IReadOnlyDictionary<AuthenticationProviderKind, string> providers, Func<HttpContext, bool> authorizeAdministrator,
        string? recoveryPath = null)
    {
        var group = app.MapGroup(routePrefix).RequireAuthorization();
        group.AddEndpointFilter(async (context, next) =>
        {
            var http = context.HttpContext;
            string? accountId = http.User.FindFirstValue(AccountSecurityHosting.AccountIdClaim);
            bool current = accountId is not null && long.TryParse(http.User.FindFirstValue(AccountSecurityHosting.SessionVersionClaim), out long version) &&
                http.RequestServices.GetRequiredService<AccountProvisioningService>().IsCurrentSession(accountId, version);
            return current && authorizeAdministrator(http) ? await next(context) : Results.StatusCode(StatusCodes.Status403Forbidden);
        });
        group.MapGet("/", (IAccountStore accounts) => Results.Ok(accounts.List().Select(a => new
        {
            a.Id, a.LoginName, a.DisplayName, providerKind = a.ProviderKind.ToString(),
            population = a.Population.ToString(), status = a.Status.ToString(),
            identities = accounts.GetIdentities(a.Id).Select(i => new { i.Key, providerKind = i.ProviderKind.ToString() })
        })));
        group.MapPost("/", (SecurityAccountCreationRequest request, IAccountStore accounts, ClaimsPrincipal actor) =>
        {
            try
            {
                if (!Enum.TryParse(request.AuthenticationSource, out AuthenticationProviderKind source) ||
                    !providers.ContainsKey(source))
                    return Results.BadRequest(new { error = "Choose ActiveDirectory, EntraId or LocalDatabase." });
                if(source==AuthenticationProviderKind.LocalDatabase && (request.SubjectId is not null || request.ScopeId is not null))
                    return Results.BadRequest(new {error="Local identities are assigned by the account store."});
                ExternalIdentityKey? key = string.IsNullOrWhiteSpace(request.SubjectId) ? null :
                    new ExternalIdentityKey(providers[source],
                        Scope(source,request.ScopeId ?? ""), Subject(source,request.SubjectId));
                var account = accounts.Create(new AccountCreation(Guid.NewGuid().ToString("D"), request.UserName,
                    request.DisplayName, source, population, SecurityAccountStatus.PendingAccess, key),
                    Actor(actor), request.InitialPassword);
                return Results.Ok(account);
            }
            catch (Exception e) when (e is ArgumentException or InvalidOperationException or FormatException)
            { return Results.BadRequest(new { error = e.Message }); }
        });
        group.MapPut("/{id}/status", (string id, AccountStatusRequest request, IAccountStore accounts, ClaimsPrincipal actor) =>
        {
            if (!Enum.TryParse(request.Status, out SecurityAccountStatus status) || !Enum.IsDefined(status))
                return Results.BadRequest(new { error = "Invalid account status." });
            if (id == actor.FindFirstValue(AccountSecurityHosting.AccountIdClaim) && status != SecurityAccountStatus.Active)
                return Results.BadRequest(new { error = "Use another administrator to disable your own account." });
            accounts.SetStatus(id, status, Actor(actor));
            return Results.NoContent();
        });
        group.MapPost("/{id}/revoke", (string id, IAccountStore accounts, ClaimsPrincipal actor) =>
        { accounts.RevokeSessions(id, Actor(actor)); return Results.NoContent(); });
        group.MapPost("/{id}/recovery", (string id, ILocalCredentialStore credentials, ClaimsPrincipal actor) =>
        {
            try { return Results.Ok(new { token = credentials.IssueRecovery(id, Actor(actor)), expiresInMinutes = 15 }); }
            catch (InvalidOperationException e) { return Results.BadRequest(new { error = e.Message }); }
        });
        group.MapPost("/{id}/identities", (string id, IdentityBindingRequest request, IAccountStore accounts, ClaimsPrincipal actor) =>
        {
            try
            {
                if (!Enum.TryParse(request.AuthenticationSource, out AuthenticationProviderKind source) ||
                    !providers.ContainsKey(source) || source == AuthenticationProviderKind.LocalDatabase)
                    return Results.BadRequest(new { error = "An external staff authentication source is required." });
                SecurityAccount? account = accounts.Find(id);
                if (account is null) return Results.NotFound();
                var identity = new VerifiedIdentity(new ExternalIdentityKey(
                    providers[source],
                    Scope(source,request.ScopeId), Subject(source,request.SubjectId)), source, account.LoginName, account.DisplayName,
                    DateTimeOffset.UtcNow, "administrator-approved-binding");
                accounts.Link(id, identity, Actor(actor));
                return Results.NoContent();
            }
            catch (Exception e) when (e is ArgumentException or InvalidOperationException or FormatException)
            { return Results.BadRequest(new { error = e.Message }); }
        });
        group.MapDelete("/{id}/identities", (string id, string providerId, string scopeId, string subjectId,
            IAccountStore accounts, ClaimsPrincipal actor) =>
        {
            if (id == actor.FindFirstValue(AccountSecurityHosting.AccountIdClaim) && accounts.GetIdentities(id).Count <= 1)
                return Results.BadRequest(new { error = "Enroll and verify another authentication method before unlinking your last identity." });
            accounts.Unlink(id, new ExternalIdentityKey(providerId, scopeId, subjectId), Actor(actor));
            return Results.NoContent();
        });
        if (recoveryPath is not null) app.MapPost(recoveryPath, (RecoveryRequest request, ILocalCredentialStore credentials) =>
        {
            try { return credentials.Recover(request.Token, request.NewPassword) ? Results.Ok(new { recovered = true }) : Results.BadRequest(new { error = "The recovery proof is invalid, expired or already used." }); }
            catch (ArgumentException e) { return Results.BadRequest(new { error = e.Message }); }
        }).AllowAnonymous().RequireRateLimiting(AccountSecurityHosting.LoginRateLimit);
    }

    private static string Scope(AuthenticationProviderKind source,string value) => source is AuthenticationProviderKind.ActiveDirectory or AuthenticationProviderKind.EntraId ? Guid.Parse(value).ToString("D") : value;
    private static string Subject(AuthenticationProviderKind source,string value) => source is AuthenticationProviderKind.ActiveDirectory or AuthenticationProviderKind.EntraId ? Guid.Parse(value).ToString("D") : value;
    private static string Actor(ClaimsPrincipal actor) => actor.FindFirstValue(AccountSecurityHosting.AccountIdClaim)
        ?? throw new InvalidOperationException("An authenticated security administrator is required.");
}

public sealed record SecurityAccountCreationRequest(string UserName, string DisplayName, string AuthenticationSource,
    string? ScopeId = null, string? SubjectId = null, string? InitialPassword = null);
public sealed record AccountStatusRequest(string Status);
public sealed record IdentityBindingRequest(string AuthenticationSource, string ScopeId, string SubjectId);
public sealed record RecoveryRequest(string Token, string NewPassword);
