namespace Common.Security.Abstractions;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers one external identity provider into Common.Security.
/// Applications depend on Common.Security contracts and do not construct provider-specific authenticators directly.
/// </summary>
public interface IAuthenticationPlugin
{
    string Name { get; }

    void Register(
        IServiceCollection services,
        IConfigurationSection configuration);
}
