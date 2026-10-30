namespace Common.Security.Integration;

using Common.Diagnostics;
using Common.Security.Abstractions;
using Common.Security.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System.Data.Common;
using Common.Security.Services;

public static class SecurityServiceCollectionExtensions
{
    public static IServiceCollection AddCommonAccountStore(this IServiceCollection services,
        Func<IServiceProvider, DbConnection> connections, string applicationId)
    {
        services.AddSingleton(provider =>
        {
            var store = new RelationalAccountStore(() => connections(provider), applicationId);
            store.EnsureSchema();
            return store;
        });
        services.AddSingleton<IAccountStore>(provider => provider.GetRequiredService<RelationalAccountStore>());
        services.AddSingleton<ILocalCredentialStore>(provider => provider.GetRequiredService<RelationalAccountStore>());
        services.AddSingleton<AccountProvisioningService>();
        return services;
    }

    public static IServiceCollection AddCommonSecurity(
        this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<ISecurityEventSink, NullSecurityEventSink>();
        services.AddScoped<IDiagnosticCheck, CommonSecurityDiagnosticCheck>();
        services.AddSingleton<IDiagnosticLevelLocalTest, SecurityOperationalPermissionsDiagnosticLevelTest>();
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
