namespace Common.Security.Plugin.ActiveDirectory;

using Common.Security.Abstractions;
using Common.Security.Authenticators;
using Common.Security.Options;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

public sealed class ActiveDirectoryAuthenticationPlugin : IAuthenticationPlugin
{
    public string Name => "ActiveDirectory";

    public void Register(IServiceCollection services, IConfigurationSection configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        ActiveDirectoryAuthenticationOptions options =
            configuration.Get<ActiveDirectoryAuthenticationOptions>()
            ?? throw new InvalidOperationException("Active Directory authentication plugin settings are missing.");

        services.AddSingleton(options);
        services.AddSingleton<IAuthenticator>(_ => new ActiveDirectory(options));
        services.AddSingleton<IDirectoryProfileProvider>(_ => new ActiveDirectoryDirectoryProfileProvider(options));
    }
}
