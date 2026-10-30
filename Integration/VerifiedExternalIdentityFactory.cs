namespace Common.Security.Integration;

using System.Globalization;
using System.Security.Claims;
using Common.Security.Models;

public sealed record ExternalIdentityRegistration(string ProviderId, string Issuer,
    AuthenticationProviderKind Kind, IReadOnlyCollection<string>? AllowedTenants = null);

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
        string login = principal.FindFirstValue("preferred_username") ?? principal.FindFirstValue(ClaimTypes.Email) ?? subject;
        string name = principal.FindFirstValue("name") ?? principal.FindFirstValue(ClaimTypes.Name) ?? login;
        string? verifiedEmail = principal.FindFirstValue("email_verified") == "true"
            ? principal.FindFirstValue("email") ?? principal.FindFirstValue(ClaimTypes.Email) : null;
        string[] groups = principal.FindAll("groups").Concat(principal.FindAll("directory_group"))
            .Select(x => x.Value).ToArray();
        var claims = principal.Claims.Where(x => x.Type is "amr" or "acr" or "iss" or "tid" or "oid")
            .GroupBy(x => x.Type, StringComparer.Ordinal).ToDictionary(x => x.Key, x => string.Join(' ', x.Select(c => c.Value)));
        return new VerifiedIdentity(new ExternalIdentityKey(registration.ProviderId, scope, subject), registration.Kind,
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
