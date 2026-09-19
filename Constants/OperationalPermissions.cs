namespace Common.Security.Constants;

/// <summary>
/// Shared capability keys for cross-cutting operational surfaces.
/// Applications decide which roles receive these permissions.
/// </summary>
public static class OperationalPermissions
{
    public const string DiagnosticsView = "Diagnostics.View";
    public const string DiagnosticsRun = "Diagnostics.Run";
    public const string DiagnosticsViewSensitive = "Diagnostics.ViewSensitive";

    public const string AlertsAcknowledge = "Operations.Alerts.Acknowledge";
    public const string AlertsResolve = "Operations.Alerts.Resolve";
    public const string HistoryView = "Operations.History.View";

    public const string EngineerLogCreate = "Operations.EngineerLog.Create";
    public const string EngineerLogCreateCritical = "Operations.EngineerLog.CreateCritical";
    public const string NotificationsSend = "Operations.Notifications.Send";

    public const string SecurityDiagnosticsView = "Operations.SecurityDiagnostics.View";
    public const string RunbooksView = "Operations.Runbooks.View";
    public const string PrivilegedActionsExecute = "Operations.PrivilegedActions.Execute";
    public const string AdvisorView = "Operations.Advisor.View";

    public static IReadOnlyList<string> All { get; } =
    [
        DiagnosticsView,
        DiagnosticsRun,
        DiagnosticsViewSensitive,
        AlertsAcknowledge,
        AlertsResolve,
        HistoryView,
        EngineerLogCreate,
        EngineerLogCreateCritical,
        NotificationsSend,
        SecurityDiagnosticsView,
        RunbooksView,
        PrivilegedActionsExecute,
        AdvisorView
    ];
}
