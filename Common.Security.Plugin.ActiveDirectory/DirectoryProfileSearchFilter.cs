namespace Common.Security.Plugin.ActiveDirectory;

public static class DirectoryProfileSearchFilter
{
    public static string Build(IEnumerable<string> loginNames)
    {
        ArgumentNullException.ThrowIfNull(loginNames);
        string[] names = loginNames.Where(name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (names.Length == 0)
        {
            throw new ArgumentException("At least one login name is required.", nameof(loginNames));
        }

        string[] clauses = names.Select(name => $"(sAMAccountName={LdapFilterEscaper.Escape(name)})").ToArray();
        string accounts = clauses.Length == 1 ? clauses[0] : $"(|{string.Concat(clauses)})";
        return $"(&(objectCategory=person)(objectClass=user){accounts})";
    }
}
