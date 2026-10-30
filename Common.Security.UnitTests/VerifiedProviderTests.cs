namespace Common.Security.UnitTests;

using System.Security.Claims;
using Common.Security.Authenticators;
using Common.Security.Integration;
using Common.Security.Models;
using Common.Security.Options;
using Xunit;

public sealed class VerifiedProviderTests
{
    [Theory]
    [InlineData("Production", true)]
    [InlineData("Staging", true)]
    [InlineData("Development", false)]
    [InlineData("Demo", false)]
    public void MockFailsClosedInProhibitedOrUnisolatedEnvironments(string environment, bool isolated)
    {
        var auth = Mock(environment, isolated);
        Assert.Equal(AuthenticationFailure.Prohibited, auth.Authenticate("test-user", "test-password").Failure);
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Demo")]
    public void MockOnlyAuthenticatesServerDefinedIdentitiesAndNeverManufacturesGroups(string environment)
    {
        var auth = Mock(environment, true);
        AuthenticationResult valid = auth.Authenticate("test-user", "test-password");
        Assert.True(valid.IsAuthenticated);
        Assert.Equal("server-subject", valid.Identity!.Key.SubjectId);
        Assert.Empty(valid.GroupNames);
        Assert.False(auth.Authenticate("arbitrary-administrator", "test-password").IsAuthenticated);
        Assert.False(auth.Authenticate("test-user", "incorrect").IsAuthenticated);
    }

    [Fact]
    public void ConfiguredFederatedDirectoryProfileAndGroupClaimsArePreserved()
    {
        var principal=new ClaimsPrincipal(new ClaimsIdentity(new[]{new Claim("sub","stable-subject"),new Claim("upn","directory-alias"),new Claim("display_name","Directory User"),new Claim("mail","contact@example.test"),new Claim("memberOf","Reviewers;Readers")},"validated-oidc"));
        var registration=new ExternalIdentityRegistration("federation","https://identity.example.test",AuthenticationProviderKind.External,
            UserNameClaim:"upn",DisplayNameClaim:"display_name",EmailClaim:"mail",GroupClaimTypes:["memberOf"]);
        var proof=VerifiedExternalIdentityFactory.FromValidatedPrincipal(principal,registration);
        Assert.Equal("directory-alias",proof.LoginName);Assert.Equal("Directory User",proof.DisplayName);
        Assert.Equal(new[]{"Reviewers","Readers"},proof.GroupNames);Assert.Null(proof.VerifiedEmail);
        Assert.Equal("contact@example.test",proof.Claims["contact_email"]);
    }

    [Fact]
    public void CorrelatedOAuthSubjectCannotBeReplacedByARequestIdentifier()
    {
        var principal=new ClaimsPrincipal(new ClaimsIdentity(new[]{new Claim(ClaimTypes.NameIdentifier,"verified-subject")},"validated-oauth"));
        Assert.Throws<InvalidOperationException>(()=>VerifiedExternalIdentityFactory.FromValidatedOAuthPrincipal(principal,new ExternalIdentityKey("provider","https://provider.example.test","attacker-subject")));
    }

    [Fact]
    public void ExternalSubjectIsIndependentOfEmailOrDisplayName()
    {
        var registration = new ExternalIdentityRegistration("google", "https://accounts.google.com", AuthenticationProviderKind.External);
        var one = VerifiedExternalIdentityFactory.FromValidatedPrincipal(External("same-subject", "first@example.test"), registration);
        var two = VerifiedExternalIdentityFactory.FromValidatedPrincipal(External("same-subject", "changed@example.test"), registration);
        Assert.Equal(one.Key, two.Key);
        Assert.Null(one.VerifiedEmail);
    }

    [Fact]
    public void SameEmailDoesNotConflateDifferentProviders()
    {
        ClaimsPrincipal principal = External("subject", "same@example.test");
        var one = VerifiedExternalIdentityFactory.FromValidatedPrincipal(principal,
            new("one", "https://one.example.test", AuthenticationProviderKind.External));
        var two = VerifiedExternalIdentityFactory.FromValidatedPrincipal(principal,
            new("two", "https://two.example.test", AuthenticationProviderKind.External));
        Assert.NotEqual(one.Key, two.Key);
    }

    [Fact]
    public void UnauthenticatedPrincipalCannotBecomeVerifiedIdentity()
    {
        Assert.Throws<InvalidOperationException>(() => VerifiedExternalIdentityFactory.FromValidatedPrincipal(
            new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "subject")])),
            new("one", "https://one.example.test", AuthenticationProviderKind.External)));
    }

    [Fact]
    public void EntraRequiresImmutableObjectAndAllowedTenant()
    {
        string tenant = Guid.NewGuid().ToString("D"), subject = Guid.NewGuid().ToString("D");
        var principal = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim("tid", tenant), new Claim("oid", subject), new Claim("preferred_username", "alice@example.test")], "oidc"));
        var registration = new ExternalIdentityRegistration("staff-entra", "https://login.microsoftonline.com/tenant/v2.0",
            AuthenticationProviderKind.EntraId, [tenant]);
        var identity = VerifiedExternalIdentityFactory.FromValidatedPrincipal(principal, registration);
        Assert.Equal(tenant, identity.Key.ScopeId);
        Assert.Equal(subject, identity.Key.SubjectId);
        Assert.Throws<InvalidOperationException>(() => VerifiedExternalIdentityFactory.FromValidatedPrincipal(principal,
            registration with { AllowedTenants = [Guid.NewGuid().ToString("D")] }));
    }

    private static MockAuthenticator Mock(string environment, bool isolated) => new(new MockAuthenticationOptions
    {
        Enabled = true, EnvironmentName = environment, IsolationConfirmed = isolated, ApplicationId = "isolated-demo",
        Password = "test-password", Identities = [new("test-user", "server-subject", "Test user")]
    });
    private static ClaimsPrincipal External(string subject, string email) => new(new ClaimsIdentity([
        new Claim("sub", subject), new Claim(ClaimTypes.Email, email)], "validated-provider"));
}
