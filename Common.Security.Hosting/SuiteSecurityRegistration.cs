namespace Common.Security.Hosting;

using System.Data.Common;
using Common.Security.Abstractions;
using Common.Security.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

public static class SuiteSecurityRegistration
{
    public static IServiceCollection AddCommonSuiteSecurity(this IServiceCollection services, SuiteApplication application,
        Func<IServiceProvider, DbConnection> connections,
        Func<IServiceProvider, CommonOpenIdConnectOptions>? entraRegistration = null)
    {
        services.AddSingleton(application);
        services.AddSingleton<SuiteSecurity>();
        services.AddCommonAccountSecurity(connections, "control-plane");
        services.AddAuthorization();
        var authentication = services.AddAuthentication(SuiteSecurity.Scheme).AddCookie(SuiteSecurity.Scheme, options =>
        {
            options.Cookie.Name = application.CookieName;
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.LoginPath = "/login";
            options.SlidingExpiration = true;
            options.Events.OnValidatePrincipal = async context =>
            {
                await AccountSecurityHosting.ValidateCookieAsync(context);
                if (context.Principal is not null && context.HttpContext.RequestServices.GetRequiredService<SuiteSecurity>().ReadPrincipal(context.Principal) is null)
                {
                    context.RejectPrincipal();
                    await context.HttpContext.SignOutAsync(context.Scheme.Name);
                }
            };
        });
        services.AddOptions<CookieAuthenticationOptions>(SuiteSecurity.Scheme).Configure<IConfiguration, IHostEnvironment>((options, configuration, environment) =>
        {
            options.ExpireTimeSpan = TimeSpan.FromMinutes(Math.Clamp(configuration.GetValue("SuiteSecurity:IdleTimeoutMinutes", 30), 5, 60));
            if (environment.IsDevelopment()) options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        });
        if (entraRegistration is not null)
            authentication.AddCommonOpenIdConnect("SuiteEntra", entraRegistration, (context, identity) =>
            {
                var security = context.HttpContext.RequestServices.GetRequiredService<SuiteSecurity>();
                SuiteIdentity? approved = security.AcceptVerifiedIdentity(identity);
                if (approved is null) context.Fail("This operator has no approved access.");
                else context.Principal = security.CreatePrincipal(approved);
                return Task.CompletedTask;
            });
        return services;
    }

    public static CommonOpenIdConnectOptions EntraOptions(IConfiguration configuration, string clientSecret)
    {
        string tenant = Guid.Parse(configuration["SuiteSecurity:Entra:TenantId"] ?? "").ToString("D");
        string issuer = $"https://login.microsoftonline.com/{tenant}/v2.0";
        return new CommonOpenIdConnectOptions("SuiteEntra", issuer, configuration["SuiteSecurity:Entra:ClientId"] ?? "",
            clientSecret, configuration["SuiteSecurity:Entra:CallbackPath"] ?? "/auth/signin-entra", SuiteSecurity.Scheme,
            new Common.Security.Integration.ExternalIdentityRegistration("suite-entra", issuer, AuthenticationProviderKind.EntraId, [tenant]));
    }

    public static void MapCommonSuiteIdentityEndpoints(this WebApplication app)
    {
        bool enabled = app.Configuration.GetValue("SuiteSecurity:Entra:Enabled", false);
        app.MapGet("/auth/entra", () => enabled
            ? Results.Challenge(new AuthenticationProperties { RedirectUri = "/" }, ["SuiteEntra"])
            : Results.NotFound()).AllowAnonymous().RequireRateLimiting(AccountSecurityHosting.LoginRateLimit);
        app.MapCommonAccountAdministration("/api/security/accounts", AccountPopulation.Staff,
            new Dictionary<AuthenticationProviderKind, string>
            {
                [AuthenticationProviderKind.ActiveDirectory] = "active-directory",
                [AuthenticationProviderKind.EntraId] = "suite-entra",
                [AuthenticationProviderKind.LocalDatabase] = "local"
            }, context => context.RequestServices.GetRequiredService<SuiteSecurity>().Read(context.Request)
                ?.Permissions.Contains("Security.Manage", StringComparer.OrdinalIgnoreCase) == true,
            "/auth/recover");
    }
}
