namespace Common.Security.Hosting;

using System.Data.Common;
using System.Globalization;
using System.Security.Claims;
using System.Threading.RateLimiting;
using Common.Security.Abstractions;
using Common.Security.Authenticators;
using Common.Security.Integration;
using Common.Security.Models;
using Common.Security.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

public static class AccountSecurityHosting
{
    public const string AccountIdClaim = "common_security_account_id";
    public const string AuthenticationTimeClaim = "common_security_authenticated_at";
    public const string SessionVersionClaim = "common_security_session_version";
    public const string LoginRateLimit = "common-security-login";
    private const string CurrentAccountItem = "Common.Security.CurrentAccount";

    public static IServiceCollection AddCommonAccountSecurity(this IServiceCollection services,
        Func<IServiceProvider, DbConnection> connections, string applicationId)
    {
        services.AddCommonAccountStore(connections, applicationId);
        return services.AddCommonAuthenticationRateLimiting();
    }

    public static IServiceCollection AddCommonAuthenticationRateLimiting(this IServiceCollection services)
    {
        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.AddPolicy(LoginRateLimit, context => RateLimitPartition.GetFixedWindowLimiter(
                context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 10, Window = TimeSpan.FromMinutes(1), QueueLimit = 0,
                    AutoReplenishment = true
                }));
        });
        return services;
    }

    public static void InitializeCommonAccounts(this WebApplication app)
    { _ = app.Services.GetRequiredService<RelationalAccountStore>(); }

    public static IEnumerable<Claim> SessionClaims(SecurityAccount account, VerifiedIdentity verifiedIdentity)
    {
        yield return new Claim(AuthenticationTimeClaim,verifiedIdentity.AuthenticatedAt.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));
        yield return new Claim(AccountIdClaim, account.Id);
        yield return new Claim(SessionVersionClaim, account.SessionVersion.ToString(CultureInfo.InvariantCulture));
        yield return new Claim("authentication_source", verifiedIdentity.ProviderKind.ToString());
        yield return new Claim("account_state", account.Status.ToString());
    }

    public static async Task ValidateCookieAsync(CookieValidatePrincipalContext context)
        => await ValidateCookieAsync(context, context.HttpContext.RequestServices.GetRequiredService<IAccountStore>());

    public static async Task ValidateCookieAsync(CookieValidatePrincipalContext context, IAccountStore store)
    {
        string? id = context.Principal?.FindFirstValue(AccountIdClaim);
        string? version = context.Principal?.FindFirstValue(SessionVersionClaim);
        SecurityAccount? account = id is null ? null : store.Find(id);
        if (account is null || IsMockForbidden(account,context.Principal,context.HttpContext.RequestServices) || !long.TryParse(version, NumberStyles.None, CultureInfo.InvariantCulture, out long stamp) ||
            stamp != account.SessionVersion || account.Status is SecurityAccountStatus.Disabled or SecurityAccountStatus.Suspended)
        {
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(context.Scheme.Name);
            return;
        }
        context.HttpContext.Items[CurrentAccountItem] = account;
    }

    private static bool IsMockForbidden(SecurityAccount account,ClaimsPrincipal? principal,IServiceProvider services)
    {
        bool mock=account.ProviderKind==AuthenticationProviderKind.Mock ||
            string.Equals(principal?.FindFirstValue("authentication_source"),nameof(AuthenticationProviderKind.Mock),StringComparison.OrdinalIgnoreCase);
        string environment=services.GetService<IHostEnvironment>()?.EnvironmentName ?? "Production";
        return mock && !MockEnvironmentPolicy.IsPermitted(true,environment,true);
    }

    /// <summary>Must run after authentication and before application authorization/business middleware.</summary>
    public static IApplicationBuilder UseCommonAccountEnforcement(this IApplicationBuilder app, string loginPath, params string[] pendingIdentityPaths)
    {
        var pending = pendingIdentityPaths.ToHashSet(StringComparer.OrdinalIgnoreCase);
        pending.Add(loginPath);
        return app.Use(async (context, next) =>
        {
            string? accountId = context.User.FindFirstValue(AccountIdClaim);
            if (accountId is not null && context.User.Identity?.IsAuthenticated == true)
            {
                var account = context.Items.TryGetValue(CurrentAccountItem, out object? existing)
                    ? existing as SecurityAccount : context.RequestServices.GetRequiredService<IAccountStore>().Find(accountId);
                string? version = context.User.FindFirstValue(SessionVersionClaim);
                if (account is null || IsMockForbidden(account,context.User,context.RequestServices) || account.Status is SecurityAccountStatus.Disabled or SecurityAccountStatus.Suspended ||
                    !long.TryParse(version, NumberStyles.None, CultureInfo.InvariantCulture, out long stamp) || stamp != account.SessionVersion)
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return;
                }
                if (account.Status != SecurityAccountStatus.Active &&
                    !pending.Contains(context.Request.Path.Value ?? string.Empty) &&
                    context.GetEndpoint()?.Metadata.GetMetadata<IAllowAnonymous>() is null)
                {
                    if (!context.Request.Path.StartsWithSegments("/api") && context.Request.Headers.Accept.ToString().Contains("text/html", StringComparison.OrdinalIgnoreCase))
                    {
                        context.Response.Redirect(loginPath + "?pending=1");
                        return;
                    }
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    await context.Response.WriteAsJsonAsync(new { error = "Pending Access. An administrator must grant access.", accountState = account?.Status.ToString() });
                    return;
                }
            }
            await next(context);
        });
    }
}
