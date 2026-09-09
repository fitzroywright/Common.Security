namespace Common.Security.Integration;

using Common.Diagnostics;

public sealed class CommonDiagnosticsSecurityEventSink : ISecurityEventSink
{
    private readonly IDiagnosticOperationsRouter router;

    public CommonDiagnosticsSecurityEventSink(IDiagnosticOperationsRouter router)
    {
        this.router = router ?? throw new ArgumentNullException(nameof(router));
    }

    public void Record(SecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        DiagnosticTelemetryEvent telemetryEvent = new(
            securityEvent.Timestamp,
            "Common.Security",
            securityEvent.Code,
            MapSeverity(securityEvent.Severity),
            $"Security operation {securityEvent.Operation} completed with outcome {securityEvent.Outcome}.",
            securityEvent.CorrelationId,
            new Dictionary<string, string>
            {
                ["Operation"] = securityEvent.Operation,
                ["Outcome"] = securityEvent.Outcome,
                ["Subject"] = securityEvent.Subject ?? string.Empty,
                ["Server"] = securityEvent.Server ?? string.Empty
            });

        try
        {
            router.RouteAsync(telemetryEvent).GetAwaiter().GetResult();
        }
        catch
        {
            // Authentication must never fail because operational telemetry is unavailable.
        }
    }

    private static DiagnosticSeverity MapSeverity(SecurityEventSeverity severity) => severity switch
    {
        SecurityEventSeverity.Critical => DiagnosticSeverity.Critical,
        SecurityEventSeverity.Error => DiagnosticSeverity.Error,
        SecurityEventSeverity.Warning => DiagnosticSeverity.Warning,
        _ => DiagnosticSeverity.Information
    };
}
