namespace Common.Security.Integration;

using Common.Diagnostics;
using Common.Security.Abstractions;
using Common.Security.Authenticators;
using Common.Security.Authorization;
using Common.Security.Options;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

public static class SecurityServiceCollectionExtensions
{
    public static IServiceCollection AddCommonSecurity(
        this IServiceCollection services,
        ActiveDirectoryAuthenticationOptions options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);

        services.AddSingleton(options);
        services.TryAddSingleton<ISecurityEventSink, NullSecurityEventSink>();
        services.AddSingleton<ActiveDirectory>();
        services.AddSingleton<IAuthenticator>(provider => new PlatformAuthenticator(
            provider.GetRequiredService<ActiveDirectory>(),
            provider.GetRequiredService<ISecurityEventSink>()));
        services.AddScoped<IDiagnosticCheck, CommonSecurityDiagnosticCheck>();
        return services;
    }

    public static IServiceCollection AddCommonAuthorization<TAuthorizationStore>(this IServiceCollection services)
        where TAuthorizationStore : class, IAuthorizationStore
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddScoped<IAuthorizationStore, TAuthorizationStore>();
        services.AddScoped<IPermissionAuthorizer, PermissionAuthorizer>();
        return services;
    }

    public static IServiceCollection AddCommonAuthorizationAdministration<TAuthorizationStore>(this IServiceCollection services)
        where TAuthorizationStore : class, IAuthorizationStore, IAuthorizationAdministrationStore, ITimeBoundAuthorizationStore, IAuthorizationAuditStore
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddScoped<TAuthorizationStore>();
        services.AddScoped<IAuthorizationStore>(provider => provider.GetRequiredService<TAuthorizationStore>());
        services.AddScoped<IAuthorizationAdministrationStore>(provider => provider.GetRequiredService<TAuthorizationStore>());
        services.AddScoped<ITimeBoundAuthorizationStore>(provider => provider.GetRequiredService<TAuthorizationStore>());
        services.AddScoped<IAuthorizationAuditStore>(provider => provider.GetRequiredService<TAuthorizationStore>());
        services.AddScoped<IPermissionAuthorizer, PermissionAuthorizer>();
        services.AddScoped<AuthorizationAdministrationService>();
        return services;
    }

    public static IServiceCollection AddCommonSecurityDiagnostics(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddSingleton<ISecurityEventSink, CommonDiagnosticsSecurityEventSink>();
        return services;
    }
}
