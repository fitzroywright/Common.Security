namespace Common.Security.Authenticators
{
    using Common.Security.Abstractions;
    using Common.Security.Constants;
    using Common.Security.Models;
    using Common.Security.Options;
    using Common.Security.Services.Functions;
    using System.Diagnostics;

    public sealed class MockAuthenticator : IAuthenticator
    {
        private readonly string configuredPassword;
        private readonly bool allowAnyUser;
        private readonly HashSet<string> allowedUsers;
        private readonly HashSet<string> adminUsers;

        public MockAuthenticator(MockAuthenticationOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);
            configuredPassword = options.Password ?? string.Empty;
            allowAnyUser = options.AllowAnyUser;
            allowedUsers = ParseUsers(options.AllowedUsers);
            adminUsers = ParseUsers(options.AdminUsers);
        }

        public AuthenticationResult Authenticate(string loginName, string password)
        {
            if (string.IsNullOrWhiteSpace(loginName) || string.IsNullOrWhiteSpace(password)) return AuthenticationFailed();
            string userName = UserNameNormalizer.GetUserNameWithoutDomain(loginName);
            if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrWhiteSpace(configuredPassword)) return AuthenticationFailed();
            bool isAdministrative = adminUsers.Contains(userName);
            bool isAllowed = allowAnyUser || allowedUsers.Contains(userName) || isAdministrative;
            if (!isAllowed || !string.Equals(password, configuredPassword, StringComparison.Ordinal)) return AuthenticationFailed();
            ApplicationUserInfo userInfo = CreateUserInfo(userName);
            Trace.WriteLine($"Mock authentication succeeded. UserName={userName}, IsAdministrative={isAdministrative}");
            return new AuthenticationResult { IsAuthenticated = true, IsAdministrative = isAdministrative, UserInfo = userInfo };
        }

        private static HashSet<string> ParseUsers(string? users)
        {
            if (string.IsNullOrWhiteSpace(users)) return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            return users.Split([StringConstants.Comma, StringConstants.Semicolon], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(UserNameNormalizer.GetUserNameWithoutDomain)
                .Where(userName => !string.IsNullOrWhiteSpace(userName))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
        }

        private static AuthenticationResult AuthenticationFailed() => new() { IsAuthenticated = false, IsAdministrative = false, UserInfo = null };

        private static ApplicationUserInfo CreateUserInfo(string userName) => new()
        {
            DisplayName = $"Mock {userName}", Mail = $"{userName}@mockdomain.org", Department = "Mock Department", Title = "Mock User",
            Manager = "Mock Manager", TelephoneNumber = "000-0000", Mobile = "000-0000", OtherTelephoneNumber = string.Empty,
            OtherMobile = string.Empty, Photo = null, UserAccountControl = 0, LastSync = DateTime.UtcNow
        };
    }
}
