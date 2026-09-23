namespace Common.Security.Integration;

using Common.Diagnostics;
using Common.Security.Constants;
using Common.Security.Options;
using System.Net.Sockets;
using System.Text.RegularExpressions;

public sealed class SecurityDirectoryConfigurationLevelXTest(ActiveDirectoryAuthenticationOptions options) : ILevelXLocalTest
{
    private readonly ActiveDirectoryAuthenticationOptions options = options ?? throw new ArgumentNullException(nameof(options));
    public string TestId => "COMMON.SECURITY.L5.DIRECTORY.CONFIG";
    public string Name => "Directory configuration complete";
    public string Owner => "Common.Security";
    public EngineeringDiagnosticLevel Level => EngineeringDiagnosticLevel.Level5Scan;
    public bool IsDestructive => false;

    public Task<EngineeringDiagnosticCheckResult> RunAsync(CancellationToken cancellationToken)
    {
        List<string> missing = [];
        if (string.IsNullOrWhiteSpace(options.Domain)) missing.Add(nameof(options.Domain));
        if (string.IsNullOrWhiteSpace(options.SearchBase)) missing.Add(nameof(options.SearchBase));
        if (options.Servers is null || options.Servers.Count == 0 || options.Servers.All(string.IsNullOrWhiteSpace)) missing.Add(nameof(options.Servers));
        if (options.Port is <= 0 or > 65535) missing.Add(nameof(options.Port));
        if (options.TimeoutSeconds <= 0) missing.Add(nameof(options.TimeoutSeconds));

        return Task.FromResult(missing.Count == 0
            ? EngineeringDiagnosticPolicy.Passed(TestId, Name, "Directory configuration is complete.")
            : EngineeringDiagnosticPolicy.Failed(TestId, Name, "Directory configuration is incomplete or invalid.", $"Fields={string.Join(",", missing)}"));
    }
}

public sealed class SecurityOperationalPermissionsLevelXTest : ILevelXLocalTest
{
    public string TestId => "COMMON.SECURITY.L5.PERMISSIONS.CATALOG";
    public string Name => "Operational permission catalog valid";
    public string Owner => "Common.Security";
    public EngineeringDiagnosticLevel Level => EngineeringDiagnosticLevel.Level5Scan;
    public bool IsDestructive => false;

    public Task<EngineeringDiagnosticCheckResult> RunAsync(CancellationToken cancellationToken)
    {
        string[] values = OperationalPermissions.All.ToArray();
        string[] empty = values.Where(string.IsNullOrWhiteSpace).ToArray();
        string[] duplicates = values.GroupBy(x => x, StringComparer.OrdinalIgnoreCase).Where(x => x.Count() > 1).Select(x => x.Key).ToArray();

        if (empty.Length > 0 || duplicates.Length > 0)
            return Task.FromResult(EngineeringDiagnosticPolicy.Failed(
                TestId,
                Name,
                "Operational permission catalog contains invalid entries.",
                $"Empty={empty.Length}; Duplicates={string.Join(",", duplicates)}"));

        return Task.FromResult(EngineeringDiagnosticPolicy.Passed(
            TestId,
            Name,
            $"{values.Length} operational permission keys are unique and non-empty."));
    }
}

public sealed class SecurityDirectoryServerReachabilityLevelXTest : ILevelXLocalTest
{
    private readonly string server;
    private readonly int port;
    private readonly int timeoutSeconds;
    private readonly string idSuffix;

    public SecurityDirectoryServerReachabilityLevelXTest(string server, int port, int timeoutSeconds)
    {
        this.server = string.IsNullOrWhiteSpace(server) ? throw new ArgumentException("Server is required.", nameof(server)) : server.Trim();
        this.port = port;
        this.timeoutSeconds = Math.Max(1, timeoutSeconds);
        idSuffix = Regex.Replace(this.server.ToUpperInvariant(), "[^A-Z0-9]+", "_").Trim('_');
        if (string.IsNullOrWhiteSpace(idSuffix)) idSuffix = "SERVER";
    }

    public string TestId => $"COMMON.SECURITY.L4.DIRECTORY.REACHABLE.{idSuffix}";
    public string Name => $"Directory server reachable: {server}";
    public string Owner => "Common.Security";
    public EngineeringDiagnosticLevel Level => EngineeringDiagnosticLevel.Level4Analysis;
    public bool IsDestructive => false;

    public async Task<EngineeringDiagnosticCheckResult> RunAsync(CancellationToken cancellationToken)
    {
        try
        {
            using TcpClient client = new();
            using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));
            await client.ConnectAsync(server, port, timeout.Token).ConfigureAwait(false);
            return EngineeringDiagnosticPolicy.Passed(TestId, Name, "Directory server TCP connection succeeded.", $"Server={server}; Port={port}");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            return EngineeringDiagnosticPolicy.Failed(TestId, Name, "Directory server TCP connection failed.", $"Server={server}; Port={port}; FailureType={ex.GetType().Name}");
        }
    }
}
