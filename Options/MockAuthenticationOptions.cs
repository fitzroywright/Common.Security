namespace Common.Security.Options;

public sealed class MockAuthenticationOptions
{
    public bool Enabled { get; init; }
    public required string EnvironmentName { get; init; }
    public bool IsolationConfirmed { get; init; }
    public required string ApplicationId { get; init; }
    public string Password { get; init; } = string.Empty;
    public IReadOnlyList<MockIdentityDefinition> Identities { get; init; } = [];
}

public sealed record MockIdentityDefinition(string LoginName, string SubjectId, string DisplayName,
    IReadOnlyList<string>? Groups = null, string? Email = null);
