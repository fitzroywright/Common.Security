namespace Common.Security.UnitTests;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Common.Security.Hosting;
using Common.Security.Integration;
using Common.Security.Models;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;

public sealed class OpenIdConnectSecurityTests
{
    [Theory]
    [InlineData("valid",true)]
    [InlineData("audience",false)]
    [InlineData("issuer",false)]
    [InlineData("expired",false)]
    [InlineData("signature",false)]
    public void RegisteredOpenIdConnectPolicyRejectsInvalidSignedTokens(string scenario,bool allowed)
    {
        var services=new ServiceCollection();services.AddLogging();
        const string issuer="https://login.example.test/tenant/v2.0";
        services.AddAuthentication().AddCommonOpenIdConnect(new CommonOpenIdConnectOptions("test",issuer,"client","protected-secret","/signin","cookie",
            new ExternalIdentityRegistration("provider",issuer,AuthenticationProviderKind.External)),(_,_)=>Task.CompletedTask);
        using var provider=services.BuildServiceProvider();
        var options=provider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("test");
        Assert.Equal("code",options.ResponseType);Assert.True(options.UsePkce);Assert.True(options.ProtocolValidator.RequireNonce);
        Assert.True(options.RequireHttpsMetadata);Assert.False(options.SaveTokens);
        var trusted=new SymmetricSecurityKey(Encoding.UTF8.GetBytes(new string('t',48)));
        var signing=scenario=="signature" ? new SymmetricSecurityKey(Encoding.UTF8.GetBytes(new string('x',48))) : trusted;
        var now=DateTime.UtcNow;
        var jwt=new JwtSecurityToken(scenario=="issuer" ? "https://attacker.example.test" : issuer,
            scenario=="audience" ? "other-client" : "client",[new Claim("sub","stable-subject")],
            scenario=="expired" ? now.AddHours(-2) : now.AddMinutes(-1),scenario=="expired" ? now.AddHours(-1) : now.AddMinutes(5),new SigningCredentials(signing,SecurityAlgorithms.HmacSha256));
        var handler=new JwtSecurityTokenHandler();var parameters=options.TokenValidationParameters.Clone();parameters.IssuerSigningKey=trusted;
        string token=handler.WriteToken(jwt);
        if(allowed) Assert.True(handler.ValidateToken(token,parameters,out _).Identity!.IsAuthenticated);
        else Assert.ThrowsAny<SecurityTokenException>(()=>handler.ValidateToken(token,parameters,out _));
    }
}
