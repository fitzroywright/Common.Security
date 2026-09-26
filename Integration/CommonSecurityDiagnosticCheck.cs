namespace Common.Security.Integration;

using Common.Diagnostics;
using Common.Security.Abstractions;
using System.Diagnostics;

public sealed class CommonSecurityDiagnosticCheck(IAuthenticator authenticator) : ILeveledDiagnosticCheck
{
    private readonly IAuthenticator authenticator = authenticator ?? throw new ArgumentNullException(nameof(authenticator));

    public string Name => "Common.Security";

    public DiagnosticLevel Level => DiagnosticLevel.Level4;

    public Task<DiagnosticResult> RunAsync(CancellationToken cancellationToken = default)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();
        stopwatch.Stop();
        return Task.FromResult(new DiagnosticResult(
            Name,
            DiagnosticStatus.Healthy,
            $"Authentication provider is registered: {authenticator.GetType().FullName}.",
            stopwatch.Elapsed));
    }
}
