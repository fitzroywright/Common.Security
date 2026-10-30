namespace Common.Security.Integration;

using System.Globalization;
using System.Security.Claims;
using Common.Security.Models;

public sealed record ExternalIdentityRegistration(string ProviderId, string Issuer,
    AuthenticationProviderKind Kind, IReadOnlyCollection<string>? AllowedTenants = null,
    string UserNameClaim = "preferred_username", string DisplayNameClaim = "name", string EmailClaim = "email",
    IReadOnlyCollection<string>? GroupClaimTypes = null);

public static class VerifiedExternalIdentityFactory
{
    /// <summary>Use only with the principal supplied by a validated provider callback.</summary>
    public static VerifiedIdentity FromValidatedPrincipal(ClaimsPrincipal principal,
        ExternalIdentityRegistration registration, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(registration);
        if (principal.Identity?.IsAuthenticated != true)
            throw new InvalidOperationException("The external provider has not authenticated the identity.");
        if (registration.Kind is not (AuthenticationProviderKind.EntraId or AuthenticationProviderKind.External))
            throw new ArgumentException("An external provider registration is required.");
        if (!Uri.TryCreate(registration.Issuer, UriKind.Absolute, out Uri? issuer) ||
            issuer.Scheme != "https" || !string.IsNullOrEmpty(issuer.UserInfo))
            throw new ArgumentException("An HTTPS issuer is required.");
        string scope = registration.Issuer;
        string subject;
        if (registration.Kind == AuthenticationProviderKind.EntraId)
        {
            string tenant = Required(principal, "tid");
            string objectId = Required(principal, "oid");
            if (!Guid.TryParse(tenant, out Guid tenantId) || !Guid.TryParse(objectId, out Guid subjectId) ||
                registration.AllowedTenants is null || !registration.AllowedTenants.Any(x =>
                    Guid.TryParse(x, out Guid allowed) && allowed == tenantId))
                throw new InvalidOperationException("The Entra tenant or stable object identity is not allowed.");
            scope = tenantId.ToString("D");
            subject = subjectId.ToString("D");
        }
        else subject = Single(principal, "sub") ?? Required(principal, ClaimTypes.NameIdentifier);
        TimeProvider clock = timeProvider ?? TimeProvider.System;
        DateTimeOffset authenticated = clock.GetUtcNow();
        string? authTime = Single(principal, "auth_time");
        if (authTime is not null)
        {
            if (!long.TryParse(authTime, NumberStyles.None, CultureInfo.InvariantCulture, out long seconds))
                throw new InvalidOperationException("Invalid provider authentication time.");
            authenticated = DateTimeOffset.FromUnixTimeSeconds(seconds);
        }
        if (authenticated > clock.GetUtcNow().AddMinutes(2))
            throw new InvalidOperationException("Provider authentication time is in the future.");
        return Build(principal,new ExternalIdentityKey(registration.ProviderId,scope,subject),registration,authenticated);
    }

    /// <summary>Call only after the host validates the protected/correlated OAuth callback cookie.</summary>
    public static VerifiedIdentity FromValidatedOAuthPrincipal(ClaimsPrincipal principal,ExternalIdentityKey providerKey,TimeProvider? timeProvider=null)
    {
        if(principal.Identity?.IsAuthenticated!=true || Required(principal,ClaimTypes.NameIdentifier)!=providerKey.SubjectId)
            throw new InvalidOperationException("The correlated OAuth provider subject does not match its verified principal.");
        if(!Uri.TryCreate(providerKey.ScopeId,UriKind.Absolute,out var scope)||scope.Scheme!="https")
            throw new ArgumentException("An explicit HTTPS provider scope is required.");
        return Build(principal,providerKey,new ExternalIdentityRegistration(providerKey.ProviderId,providerKey.ScopeId,AuthenticationProviderKind.External),
            (timeProvider??TimeProvider.System).GetUtcNow());
    }

    private static VerifiedIdentity Build(ClaimsPrincipal principal,ExternalIdentityKey key,ExternalIdentityRegistration registration,DateTimeOffset authenticated)
    {
        string login = principal.FindFirstValue(registration.UserNameClaim) ?? principal.FindFirstValue(ClaimTypes.Email) ?? key.SubjectId;
        string name = principal.FindFirstValue(registration.DisplayNameClaim) ?? principal.FindFirstValue(ClaimTypes.Name) ?? login;
        string? verifiedEmail = principal.FindFirstValue("email_verified") == "true"
            ? principal.FindFirstValue(registration.EmailClaim) ?? principal.FindFirstValue(ClaimTypes.Email) : null;
        string[] groups = (registration.GroupClaimTypes ?? ["groups","directory_group"]).SelectMany(type=>principal.FindAll(type))
            .SelectMany(x=>x.Value.Split([';',','],StringSplitOptions.RemoveEmptyEntries|StringSplitOptions.TrimEntries)).ToArray();
        var claims = principal.Claims.Where(x => x.Type is "amr" or "acr" or "iss" or "tid" or "oid")
            .GroupBy(x => x.Type, StringComparer.Ordinal).ToDictionary(x => x.Key, x => string.Join(' ', x.Select(c => c.Value)));
        string? contact=principal.FindFirstValue(registration.EmailClaim) ?? principal.FindFirstValue(ClaimTypes.Email);
        if(!string.IsNullOrWhiteSpace(contact))claims["contact_email"]=contact;
        return new VerifiedIdentity(key, registration.Kind,
            login, name, authenticated, principal.FindFirstValue("acr") ?? "external-provider", verifiedEmail, groups, claims);
    }

    private static string Required(ClaimsPrincipal principal, string claim)
    {
        string? value = Single(principal, claim);
        return string.IsNullOrWhiteSpace(value) ? throw new InvalidOperationException("A stable provider claim is missing: " + claim) : value;
    }

    private static string? Single(ClaimsPrincipal principal, string claim)
    {
        string[] values = principal.FindAll(claim).Select(x => x.Value).ToArray();
        return values.Length > 1 ? throw new InvalidOperationException("An ambiguous provider claim was returned: " + claim)
            : values.SingleOrDefault();
    }
}
