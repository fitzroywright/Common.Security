namespace Common.Security.Integration;

using Common.Diagnostics;
using Common.Security.Options;
using System.Diagnostics;
using System.Net.Sockets;

public sealed class CommonSecurityDiagnosticCheck : ILeveledDiagnosticCheck
{
    private readonly ActiveDirectoryAuthenticationOptions options;

    public CommonSecurityDiagnosticCheck(ActiveDirectoryAuthenticationOptions options)
    {
        this.options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public string Name => "Common.Security";

    public DiagnosticLevel Level => DiagnosticLevel.Level4;

    public async Task<DiagnosticResult> RunAsync(CancellationToken cancellationToken = default)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();
        List<string> failed = [];
        foreach (string server in options.Servers.Where(value => !string.IsNullOrWhiteSpace(value)))
        {
            try
            {
                using TcpClient client = new();
                using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(options.TimeoutSeconds));
                await client.ConnectAsync(server, options.Port, timeout.Token).ConfigureAwait(false);
            }
            catch
            {
                failed.Add(server);
            }
        }

        stopwatch.Stop();
        if (failed.Count == options.Servers.Count)
        {
            return new DiagnosticResult(Name, DiagnosticStatus.Unhealthy, "No configured directory server is reachable.", stopwatch.Elapsed);
        }

        if (failed.Count > 0)
        {
            return new DiagnosticResult(Name, DiagnosticStatus.Warning, $"Directory failover available; unreachable servers: {string.Join(", ", failed)}.", stopwatch.Elapsed);
        }

        return new DiagnosticResult(Name, DiagnosticStatus.Healthy, "All configured directory servers are reachable.", stopwatch.Elapsed);
    }
}
