namespace Common.Security.Options
{
    [Obsolete("Active Directory provider options now live in Common.Security.Plugin.ActiveDirectory.", true)]
    public sealed class ActiveDirectoryAuthenticationOptions
    {
        public required string Domain { get; init; }
        public required string SearchBase { get; init; }
        public int Port { get; init; } = 636;
        public int TimeoutSeconds { get; init; } = 5;

        public required IReadOnlyList<string> Servers { get; init; }
        public IReadOnlyList<string> AdministrativeGroups { get; init; } =
        [
            "Domain Admins",
            "Administrators",
            "Enterprise Admins",
            "Schema Admins"
        ];
    }
}