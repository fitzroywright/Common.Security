namespace Common.Security.UnitTests;

using Common.Diagnostics;
using Common.Security.Integration;
using Xunit;

public sealed class LifecycleSecurityEventSinkTests
{
    [Fact]
    public void Record_EmitsSecurityLifecycleWithoutSubject()
    {
        var sink = new RecordingSink();
        var adapter = new LifecycleSecurityEventSink("Aegis.Hello", "hello-01", sink);

        adapter.Record(new SecurityEvent(
            "SEC100",
            SecurityEventSeverity.Warning,
            "Authorize",
            "Denied",
            "sensitive-user-name",
            "directory-01",
            DateTimeOffset.UtcNow,
            "corr-1"));

        LifecycleEvent item = Assert.Single(sink.Items);
        Assert.Equal("Security", item.Flow);
        Assert.Equal("Authorize", item.Stage);
        Assert.Equal(LifecycleEventOutcome.Warning, item.Outcome);
        string json = System.Text.Json.JsonSerializer.Serialize(item);
        Assert.DoesNotContain("sensitive-user-name", json, StringComparison.Ordinal);
    }

    private sealed class RecordingSink : ILifecycleEventSink
    {
        public List<LifecycleEvent> Items { get; } = [];
        public Task EmitAsync(LifecycleEvent lifecycleEvent, CancellationToken cancellationToken = default)
        {
            Items.Add(lifecycleEvent);
            return Task.CompletedTask;
        }
    }
}
