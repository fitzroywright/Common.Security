namespace Common.Security.UnitTests;

using Common.Diagnostics;
using Common.Security.Abstractions;
using Common.Security.Integration;
using Common.Security.Models;
using Xunit;

public sealed class CommonPlatformIntegrationTests
{
    [Fact]
    public void PlatformAuthenticatorEmitsSuccessAndFailureTelemetry()
    {
        RecordingSecurityEventSink sink = new();
        PlatformAuthenticator success = new(new StubAuthenticator(true), sink);
        PlatformAuthenticator failure = new(new StubAuthenticator(false), sink);

        AuthenticationResult successResult = success.Authenticate("alice", "password");
        AuthenticationResult failureResult = failure.Authenticate("bob", "password");

        Assert.True(successResult.IsAuthenticated);
        Assert.False(failureResult.IsAuthenticated);
        Assert.Contains(sink.Events, item => item.Code == "SEC101" && item.Outcome == "Success");
        Assert.Contains(sink.Events, item => item.Code == "SEC201" && item.Outcome == "Denied");
    }

    [Fact]
    public void DiagnosticsSinkRoutesSecurityEventWithoutSecretMaterial()
    {
        RecordingRouter router = new();
        CommonDiagnosticsSecurityEventSink sink = new(router);

        sink.Record(new SecurityEvent(
            "SEC201",
            SecurityEventSeverity.Warning,
            "Authenticate",
            "Denied",
            "alice",
            "dc01",
            DateTimeOffset.UtcNow));

        DiagnosticTelemetryEvent telemetry = Assert.Single(router.Events);
        Assert.Equal("Common.Security", telemetry.Source);
        Assert.Equal(DiagnosticSeverity.Warning, telemetry.Severity);
        Assert.DoesNotContain("password", telemetry.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("alice", telemetry.Properties!["Subject"]);
    }

    private sealed class StubAuthenticator : IAuthenticator
    {
        private readonly bool success;

        public StubAuthenticator(bool success)
        {
            this.success = success;
        }

        public AuthenticationResult Authenticate(string loginName, string password)
        {
            return new AuthenticationResult
            {
                IsAuthenticated = success,
                IsAdministrative = false,
                UserInfo = null
            };
        }
    }

    private sealed class RecordingSecurityEventSink : ISecurityEventSink
    {
        public List<SecurityEvent> Events { get; } = [];

        public void Record(SecurityEvent securityEvent)
        {
            Events.Add(securityEvent);
        }
    }

    private sealed class RecordingRouter : IDiagnosticOperationsRouter
    {
        public List<DiagnosticTelemetryEvent> Events { get; } = [];

        public Task RouteAsync(DiagnosticTelemetryEvent telemetryEvent, CancellationToken cancellationToken = default)
        {
            Events.Add(telemetryEvent);
            return Task.CompletedTask;
        }
    }
}
