namespace Common.Security.Integration;

public enum SecurityEventSeverity
{
    Information = 0,
    Warning = 1,
    Error = 2,
    Critical = 3
}

public sealed record SecurityEvent(
    string Code,
    SecurityEventSeverity Severity,
    string Operation,
    string Outcome,
    string? Subject,
    string? Server,
    DateTimeOffset Timestamp,
    string? CorrelationId = null);

public interface ISecurityEventSink
{
    void Record(SecurityEvent securityEvent);
}

public sealed class NullSecurityEventSink : ISecurityEventSink
{
    public void Record(SecurityEvent securityEvent)
    {
    }
}
