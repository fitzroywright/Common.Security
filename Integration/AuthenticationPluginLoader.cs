namespace Common.Security.Integration;

using Common.Security.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System.Reflection;
using System.Runtime.Loader;

public static class AuthenticationPluginLoader
{
    public static void Register(
        IServiceCollection services,
        IConfiguration configuration,
        string contentRootPath,
        string sectionName = "AuthenticationPlugin")
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        IConfigurationSection section = configuration.GetSection(sectionName);
        bool enabled = !bool.TryParse(section["Enabled"], out bool configuredEnabled) || configuredEnabled;
        if (!enabled)
            throw new InvalidOperationException("Authentication plugin is disabled.");

        string configuredPath = section["AssemblyPath"]?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(configuredPath))
            throw new InvalidOperationException($"{sectionName}:AssemblyPath is required.");

        string assemblyPath = ResolveAssemblyPath(configuredPath, contentRootPath);
        if (!File.Exists(assemblyPath))
            throw new FileNotFoundException("Configured authentication plugin was not found.", assemblyPath);

        AssemblyDependencyResolver resolver = new(assemblyPath);
        AssemblyLoadContext.Default.Resolving += (_, assemblyName) =>
        {
            string? dependencyPath = resolver.ResolveAssemblyToPath(assemblyName);
            return dependencyPath is null
                ? null
                : AssemblyLoadContext.Default.LoadFromAssemblyPath(dependencyPath);
        };

        Assembly assembly = AssemblyLoadContext.Default.LoadFromAssemblyPath(assemblyPath);
        Type contract = typeof(IAuthenticationPlugin);
        Type[] implementations = assembly.GetTypes()
            .Where(type => type.IsClass && !type.IsAbstract && type.IsPublic && contract.IsAssignableFrom(type))
            .ToArray();

        if (implementations.Length != 1)
            throw new InvalidOperationException(
                $"Authentication plugin '{assembly.GetName().Name}' must contain exactly one {contract.FullName} implementation; found {implementations.Length}.");

        IAuthenticationPlugin plugin = (IAuthenticationPlugin)(
            Activator.CreateInstance(implementations[0])
            ?? throw new InvalidOperationException($"Could not create authentication plugin {implementations[0].FullName}."));

        plugin.Register(services, section.GetSection("Settings"));
    }

    private static string ResolveAssemblyPath(string configuredPath, string contentRootPath)
    {
        if (Path.IsPathRooted(configuredPath))
            return Path.GetFullPath(configuredPath);

        string contentRootCandidate = Path.GetFullPath(Path.Combine(contentRootPath, configuredPath));
        if (File.Exists(contentRootCandidate))
            return contentRootCandidate;

        return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, configuredPath));
    }
}
