namespace Common.Security.Authorization;

public sealed record AuthorizationSubject(
    string SubjectId,
    IReadOnlyCollection<string> GroupNames)
{
    public static AuthorizationSubject Create(string subjectId, IEnumerable<string>? groupNames = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);

        string[] groups = (groupNames ?? Array.Empty<string>())
            .Where(group => !string.IsNullOrWhiteSpace(group))
            .Select(group => group.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new AuthorizationSubject(subjectId.Trim(), groups);
    }
}
