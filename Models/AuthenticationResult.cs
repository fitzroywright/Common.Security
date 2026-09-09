namespace Common.Security.Models
{
    public sealed class AuthenticationResult
    {
        public bool IsAuthenticated { get; init; }

        public bool IsAdministrative { get; init; }

        public ApplicationUserInfo? UserInfo { get; init; }

        public IReadOnlyList<string> GroupNames { get; init; } = [];
    }
}
