namespace Common.Security.Integration;

using Common.Diagnostics;
using Common.Security.Constants;

public sealed class SecurityOperationalPermissionsDiagnosticLevelTest : IDiagnosticLevelLocalTest
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
        string[] duplicates = values
            .GroupBy(x => x, StringComparer.OrdinalIgnoreCase)
            .Where(x => x.Count() > 1)
            .Select(x => x.Key)
            .ToArray();

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
