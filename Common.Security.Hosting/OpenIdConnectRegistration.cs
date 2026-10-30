namespace Common.Security.Hosting;

using Common.Security.Integration;
using Common.Security.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.DependencyInjection;

public sealed record CommonOpenIdConnectOptions(string Scheme, string Authority, string ClientId,
    string ClientSecret, string CallbackPath, string SignInScheme, ExternalIdentityRegistration Identity);

public static class OpenIdConnectRegistration
{
    public static AuthenticationBuilder AddCommonOpenIdConnect(this AuthenticationBuilder builder,
        CommonOpenIdConnectOptions registration, Func<TokenValidatedContext, VerifiedIdentity, Task> onVerified)
        => builder.AddCommonOpenIdConnect(registration.Scheme, _ => registration, onVerified);

    public static AuthenticationBuilder AddCommonOpenIdConnect(this AuthenticationBuilder builder, string scheme,
        Func<IServiceProvider, CommonOpenIdConnectOptions> registration, Func<TokenValidatedContext, VerifiedIdentity, Task> onVerified)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(onVerified);
        builder.AddOpenIdConnect(scheme, _ => { });
        builder.Services.AddOptions<OpenIdConnectOptions>(scheme).Configure<IServiceProvider>((options, provider) =>
            Configure(options, registration(provider), onVerified));
        return builder;
    }

    private static void Configure(OpenIdConnectOptions options, CommonOpenIdConnectOptions registration,
        Func<TokenValidatedContext, VerifiedIdentity, Task> onVerified)
    {
        if (!Uri.TryCreate(registration.Authority, UriKind.Absolute, out Uri? authority) ||
            authority.Scheme != "https" || !string.IsNullOrEmpty(authority.UserInfo))
            throw new ArgumentException("An HTTPS OpenID Connect authority is required.");
        ArgumentException.ThrowIfNullOrWhiteSpace(registration.ClientId);
        ArgumentException.ThrowIfNullOrWhiteSpace(registration.ClientSecret);
        if (!registration.CallbackPath.StartsWith('/') || registration.CallbackPath.StartsWith("//"))
            throw new ArgumentException("A local callback path is required.");

            options.Authority = registration.Authority;
            options.ClientId = registration.ClientId;
            options.ClientSecret = registration.ClientSecret;
            options.CallbackPath = registration.CallbackPath;
            options.SignInScheme = registration.SignInScheme;
            options.ResponseType = "code";
            options.UsePkce = true;
            options.RequireHttpsMetadata = true;
            options.SaveTokens = false;
            options.MapInboundClaims = false;
            options.Scope.Clear();
            options.Scope.Add("openid"); options.Scope.Add("profile"); options.Scope.Add("email");
            options.ProtocolValidator.RequireNonce = true;
            options.ProtocolValidator.RequireAuthTime = true;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true, ValidIssuer = registration.Identity.Issuer,
                ValidateAudience = true, ValidAudience = registration.ClientId,
                ValidateLifetime = true, RequireExpirationTime = true, RequireSignedTokens = true,
                ValidateIssuerSigningKey = true, ClockSkew = TimeSpan.FromMinutes(2),
                NameClaimType = "name", RoleClaimType = "aegis_application_role"
            };
            options.Events = new OpenIdConnectEvents
            {
                OnRedirectToIdentityProvider = context =>
                {
                    context.ProtocolMessage.MaxAge = "600";
                    return Task.CompletedTask;
                },
                OnTokenValidated = async context =>
                {
                    if (context.Principal is null) { context.Fail("The provider did not return a principal."); return; }
                    VerifiedIdentity identity;
                    try { identity = VerifiedExternalIdentityFactory.FromValidatedPrincipal(context.Principal, registration.Identity); }
                    catch (Exception e) when (e is ArgumentException or InvalidOperationException)
                    { context.Fail("The provider did not return an allowed stable identity."); return; }
                    await onVerified(context, identity);
                }
            };

    }
}
