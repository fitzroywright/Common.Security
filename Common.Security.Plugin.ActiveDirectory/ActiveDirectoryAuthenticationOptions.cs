namespace Common.Security.Plugin.ActiveDirectory;

public sealed class ActiveDirectoryAuthenticationOptions
{
    public required string Domain { get; init; }
    public required string SearchBase { get; init; }
    public int Port { get; init; } = 636;
    public int TimeoutSeconds { get; init; } = 5;
    public required IReadOnlyList<string> Servers { get; init; }
    public IReadOnlyList<string> AdministrativeGroups { get; init; } = [];
}
