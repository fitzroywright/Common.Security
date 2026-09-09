namespace Common.Security.Integration;

using Common.Diagnostics;
using Common.Security.Abstractions;
using Common.Security.Authenticators;
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

    public static IServiceCollection AddCommonSecurityDiagnostics(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddSingleton<ISecurityEventSink, CommonDiagnosticsSecurityEventSink>();
        return services;
    }
}
