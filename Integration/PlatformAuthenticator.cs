namespace Common.Security.Integration;

using Common.Security.Abstractions;
using Common.Security.Models;

public sealed class PlatformAuthenticator : IAuthenticator
{
    private readonly IAuthenticator inner;
    private readonly ISecurityEventSink telemetry;

    public PlatformAuthenticator(IAuthenticator inner, ISecurityEventSink telemetry)
    {
        this.inner = inner ?? throw new ArgumentNullException(nameof(inner));
        this.telemetry = telemetry ?? throw new ArgumentNullException(nameof(telemetry));
    }

    public AuthenticationResult Authenticate(string loginName, string password)
    {
        string? subject = string.IsNullOrWhiteSpace(loginName) ? null : loginName.Trim();
        try
        {
            AuthenticationResult result = inner.Authenticate(loginName, password);
            telemetry.Record(new SecurityEvent(
                result.IsAuthenticated ? "SEC101" : "SEC201",
                result.IsAuthenticated ? SecurityEventSeverity.Information : SecurityEventSeverity.Warning,
                "Authenticate",
                result.IsAuthenticated ? "Success" : "Denied",
                subject,
                null,
                DateTimeOffset.UtcNow));
            return result;
        }
        catch
        {
            telemetry.Record(new SecurityEvent(
                "SEC501",
                SecurityEventSeverity.Error,
                "Authenticate",
                "Error",
                subject,
                null,
                DateTimeOffset.UtcNow));
            throw;
        }
    }
}
