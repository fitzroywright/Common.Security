namespace Common.Security.Services.Functions
{
    using Common.Security.Constants;

    public static class UserNameNormalizer
    {
        public static string GetUserNameWithoutDomain(string? loginName)
        {
            if (string.IsNullOrWhiteSpace(loginName)) return string.Empty;
            string userName = loginName.Trim();
            int slashIndex = userName.LastIndexOf(AuthenticationConstants.DomainUserNameSeparator);
            if (slashIndex >= 0 && slashIndex < userName.Length - 1) userName = userName[(slashIndex + 1)..];
            int atIndex = userName.IndexOf(AuthenticationConstants.UserNameDomainSeparator);
            if (atIndex > 0) userName = userName[..atIndex];
            return userName.Trim().ToLowerInvariant();
        }

        public static string ToCanonicalUserName(string? loginName, string? tenantKey)
        {
            string userName = GetUserNameWithoutDomain(loginName);
            if (string.IsNullOrWhiteSpace(userName)) return string.Empty;
            if (string.IsNullOrWhiteSpace(tenantKey)) return userName;
            return string.Concat(userName, AuthenticationConstants.UserNameDomainSeparator, tenantKey.Trim().ToLowerInvariant());
        }

        public static string ToDisplayUserName(string? canonicalUserName)
        {
            if (string.IsNullOrWhiteSpace(canonicalUserName)) return string.Empty;
            int atIndex = canonicalUserName.IndexOf(AuthenticationConstants.UserNameDomainSeparator);
            return atIndex <= 0 ? canonicalUserName.Trim() : canonicalUserName[..atIndex].Trim();
        }

        public static string NormalizeLogin(string? userName, string? defaultDomain)
        {
            string login = userName?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(login)) return string.Empty;
            string shortUserName = GetUserNameWithoutDomain(login);
            if (string.IsNullOrWhiteSpace(shortUserName)) return string.Empty;
            if (HasDomainSuffix(login)) return login.Trim().ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(defaultDomain)) return shortUserName;
            return string.Concat(shortUserName, AuthenticationConstants.UserNameDomainSeparator, defaultDomain.Trim().ToLowerInvariant());
        }

        public static bool HasDomainSuffix(string? loginName)
        {
            if (string.IsNullOrWhiteSpace(loginName)) return false;
            int atIndex = loginName.IndexOf(AuthenticationConstants.UserNameDomainSeparator);
            return atIndex > 0 && atIndex < loginName.Length - 1;
        }

        public static string Normalize(string? value) => (value ?? string.Empty).Trim().ToLowerInvariant();

        public static bool Matches(string? left, string? right)
        {
            string normalizedLeft = Normalize(left);
            string normalizedRight = Normalize(right);
            if (string.Equals(normalizedLeft, normalizedRight, StringComparison.Ordinal)) return true;
            return string.Equals(ShortName(normalizedLeft), ShortName(normalizedRight), StringComparison.Ordinal);
        }

        public static string GetDomainQualifiedUserName(string? loginName)
        {
            if (string.IsNullOrWhiteSpace(loginName)) return string.Empty;
            string normalized = Normalize(loginName);
            int slashIndex = normalized.LastIndexOf(AuthenticationConstants.DomainUserNameSeparator);
            if (slashIndex >= 0 && slashIndex < normalized.Length - 1) normalized = normalized[(slashIndex + 1)..];
            if (HasDomainSuffix(normalized)) return normalized;
            return normalized;
        }

        public static string ShortName(string? value)
        {
            string normalized = Normalize(value);
            int at = normalized.IndexOf(AuthenticationConstants.UserNameDomainSeparator);
            return at > 0 ? normalized[..at] : normalized;
        }
    }
}
