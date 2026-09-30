namespace Common.Security.Plugin.ActiveDirectory;

using Common.Diagnostics;
using System.Diagnostics;
using System.Net.Sockets;

public sealed class ActiveDirectoryDependencyProbe(
    ActiveDirectoryAuthenticationOptions options) : IDependencyDiagnosticProbe
{
    private readonly ActiveDirectoryAuthenticationOptions options =
        options ?? throw new ArgumentNullException(nameof(options));

    public string Component => "Common.Security";
    public string Dependency => "Active Directory";
    public DependencyDiagnosticKind Kind => DependencyDiagnosticKind.Security;
    public EngineeringDiagnosticLevel Level => EngineeringDiagnosticLevel.Level4Analysis;

    public async Task<DependencyVerificationResult> VerifyAsync(
        CancellationToken cancellationToken = default)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();
        string[] servers = options.Servers
            .Where(server => !string.IsNullOrWhiteSpace(server))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        bool configured =
            !string.IsNullOrWhiteSpace(options.Domain) &&
            !string.IsNullOrWhiteSpace(options.SearchBase) &&
            servers.Length > 0;

        if (!configured)
        {
            stopwatch.Stop();
            return new DependencyVerificationResult(
                Component,
                Dependency,
                Kind,
                false,
                false,
                false,
                OperationalDiagnosticState.Warning,
                DateTimeOffset.UtcNow,
                stopwatch.Elapsed,
                "Active Directory authentication is not fully configured.",
                $"DomainPresent={!string.IsNullOrWhiteSpace(options.Domain)}; SearchBasePresent={!string.IsNullOrWhiteSpace(options.SearchBase)}; Servers={servers.Length}",
                "AD_NOT_CONFIGURED");
        }

        List<string> failures = [];
        foreach (string server in servers)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                using TcpClient client = new();
                using CancellationTokenSource timeout =
                    CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(Math.Max(1, options.TimeoutSeconds)));
                await client.ConnectAsync(server, options.Port, timeout.Token).ConfigureAwait(false);
                stopwatch.Stop();

                return new DependencyVerificationResult(
                    Component,
                    Dependency,
                    Kind,
                    true,
                    true,
                    true,
                    OperationalDiagnosticState.Healthy,
                    DateTimeOffset.UtcNow,
                    stopwatch.Elapsed,
                    $"Active Directory endpoint {server}:{options.Port} is reachable.",
                    $"Domain={options.Domain}; SearchBasePresent=True; ServersConfigured={servers.Length}; ReachableServer={server}; Port={options.Port}",
                    null);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                failures.Add($"{server}:{options.Port}={exception.GetType().Name}");
            }
        }

        stopwatch.Stop();
        return new DependencyVerificationResult(
            Component,
            Dependency,
            Kind,
            true,
            false,
            false,
            OperationalDiagnosticState.Offline,
            DateTimeOffset.UtcNow,
            stopwatch.Elapsed,
            "No configured Active Directory endpoint is reachable.",
            $"Domain={options.Domain}; ServersConfigured={servers.Length}; Failures={string.Join(",", failures)}",
            "AD_ENDPOINT_UNREACHABLE");
    }
}
