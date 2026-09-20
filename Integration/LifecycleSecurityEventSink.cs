namespace Common.Security.Integration;

using Common.Diagnostics;

public sealed class LifecycleSecurityEventSink : ISecurityEventSink
{
    private readonly string applicationId;
    private readonly string instanceId;
    private readonly ILifecycleEventSink lifecycle;

    public LifecycleSecurityEventSink(
        string applicationId,
        string instanceId,
        ILifecycleEventSink lifecycle)
    {
        if (string.IsNullOrWhiteSpace(applicationId)) throw new ArgumentException("Application id is required.", nameof(applicationId));
        if (string.IsNullOrWhiteSpace(instanceId)) throw new ArgumentException("Instance id is required.", nameof(instanceId));
        this.applicationId = applicationId.Trim();
        this.instanceId = instanceId.Trim();
        this.lifecycle = lifecycle ?? throw new ArgumentNullException(nameof(lifecycle));
    }

    public void Record(SecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);

        LifecycleEventOutcome outcome = securityEvent.Severity switch
        {
            SecurityEventSeverity.Critical or SecurityEventSeverity.Error => LifecycleEventOutcome.Failed,
            SecurityEventSeverity.Warning => LifecycleEventOutcome.Warning,
            _ => LifecycleEventOutcome.Succeeded
        };

        string correlationId = string.IsNullOrWhiteSpace(securityEvent.CorrelationId)
            ? Guid.NewGuid().ToString("N")
            : securityEvent.CorrelationId.Trim();

        try
        {
            lifecycle.EmitAsync(
                LifecycleEvent.Create(
                    applicationId,
                    instanceId,
                    "Security",
                    securityEvent.Operation,
                    outcome,
                    correlationId,
                    code: securityEvent.Code,
                    properties: new Dictionary<string, string>
                    {
                        ["Outcome"] = securityEvent.Outcome,
                        ["Server"] = securityEvent.Server ?? string.Empty
                    }),
                CancellationToken.None).GetAwaiter().GetResult();
        }
        catch
        {
            // Security decisions must never depend on telemetry availability.
        }
    }
}
