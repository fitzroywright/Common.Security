namespace Common.Security.Options
{
    public sealed class MockAuthenticationOptions
    {
        public string? AdminUsers { get; init; }
        public string? AllowedUsers { get; init; }

        public bool AllowAnyUser { get; init; }

        public string? Password { get; init; }
    }
}