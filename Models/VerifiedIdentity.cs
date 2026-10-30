namespace Common.Security.Models;

using System.Collections.ObjectModel;

public enum AuthenticationProviderKind { ActiveDirectory, EntraId, LocalDatabase, External, Mock }

/// <summary>All components are provider-scoped, immutable and case-sensitive.</summary>
public sealed record ExternalIdentityKey
{
    public string ProviderId { get; }
    public string ScopeId { get; }
    public string SubjectId { get; }

    public ExternalIdentityKey(string providerId, string scopeId, string subjectId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerId);
        ArgumentException.ThrowIfNullOrWhiteSpace(scopeId);
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);
        if (providerId.Length > 200 || scopeId.Length > 500 || subjectId.Length > 500)
            throw new ArgumentException("Provider identity exceeds its maximum length.");
        ProviderId = providerId;
        ScopeId = scopeId;
        SubjectId = subjectId;
    }
}

/// <summary>Produced by a server-side provider after verification, never from a login request.</summary>
public sealed class VerifiedIdentity
{
    public ExternalIdentityKey Key { get; }
    public AuthenticationProviderKind ProviderKind { get; }
    public string LoginName { get; }
    public string DisplayName { get; }
    public string? VerifiedEmail { get; }
    public DateTimeOffset AuthenticatedAt { get; }
    public string Assurance { get; }
    public IReadOnlyList<string> GroupNames { get; }
    public IReadOnlyDictionary<string, string> Claims { get; }

    public VerifiedIdentity(ExternalIdentityKey key, AuthenticationProviderKind providerKind,
        string loginName, string displayName, DateTimeOffset authenticatedAt,
        string assurance, string? verifiedEmail = null, IEnumerable<string>? groups = null,
        IReadOnlyDictionary<string, string>? claims = null)
    {
        Key = key ?? throw new ArgumentNullException(nameof(key));
        ArgumentException.ThrowIfNullOrWhiteSpace(loginName);
        ArgumentException.ThrowIfNullOrWhiteSpace(assurance);
        if (!Enum.IsDefined(providerKind)) throw new ArgumentOutOfRangeException(nameof(providerKind));
        if (authenticatedAt == default) throw new ArgumentException("Authentication time is required.");
        ProviderKind = providerKind;
        LoginName = loginName.Trim();
        DisplayName = string.IsNullOrWhiteSpace(displayName) ? LoginName : displayName.Trim();
        AuthenticatedAt = authenticatedAt.ToUniversalTime();
        Assurance = assurance;
        VerifiedEmail = string.IsNullOrWhiteSpace(verifiedEmail) ? null : verifiedEmail.Trim();
        GroupNames = Array.AsReadOnly((groups ?? []).Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
        Claims = new ReadOnlyDictionary<string, string>(claims is null
            ? new Dictionary<string, string>() : new Dictionary<string, string>(claims, StringComparer.Ordinal));
    }
}
