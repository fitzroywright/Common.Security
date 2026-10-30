namespace Common.Security.UnitTests;
using System.Security.Claims;
using Common.Security.Abstractions;
using Common.Security.Hosting;
using Common.Security.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Internal;
using Xunit;

public sealed class HostedMockSessionTests
{
    [Theory]
    [InlineData("Production",false)]
    [InlineData("Staging",false)]
    [InlineData("Development",true)]
    [InlineData("Demo",true)]
    public async Task SignedMockCookieCannotCrossIntoAProhibitedHostEnvironment(string environment,bool allowed)
    {
        using var db=new AccountProvisioningTests.Database();
        var key=new ExternalIdentityKey("mock","isolated-demo","server-user");
        var account=db.Store.Create(new AccountCreation("mock-account","demo.user","Demo User",AuthenticationProviderKind.Mock,
            AccountPopulation.Staff,SecurityAccountStatus.Active,key),"isolated-demo-enrollment");
        var proof=new VerifiedIdentity(key,AuthenticationProviderKind.Mock,"demo.user","Demo User",DateTimeOffset.UtcNow,"isolated-server-proof");
        var recorder=new AuthenticationRecorder();
        using var services=new ServiceCollection().AddSingleton<IHostEnvironment>(new HostingEnvironment {EnvironmentName=environment})
            .AddSingleton<IAuthenticationService>(recorder).BuildServiceProvider();
        var http=new DefaultHttpContext {RequestServices=services};
        var principal=new ClaimsPrincipal(new ClaimsIdentity(AccountSecurityHosting.SessionClaims(account,proof),"cookie"));
        var ticket=new AuthenticationTicket(principal,new AuthenticationProperties(),"cookie");
        var context=new CookieValidatePrincipalContext(http,new AuthenticationScheme("cookie","cookie",typeof(CookieAuthenticationHandler)),new CookieAuthenticationOptions(),ticket);
        await AccountSecurityHosting.ValidateCookieAsync(context,db.Store);
        Assert.Equal(allowed,context.Principal is not null);Assert.Equal(!allowed,recorder.SignedOut);
    }

    [Fact]
    public void ProductionSuiteRejectsMockCookiesAndHandoffsEvenIfAKeyAndApprovedAccountWereAccidentallyShared()
    {
        using var db=new AccountProvisioningTests.Database();var accounts=db.OtherApplication("control-plane");accounts.EnsureSchema();
        var proof=new VerifiedIdentity(new ExternalIdentityKey("mock","control-plane","server-subject"),AuthenticationProviderKind.Mock,
            "demo.user","Demo User",DateTimeOffset.UtcNow,"isolated-server-proof");
        accounts.Create(new AccountCreation("approved-demo-id",proof.LoginName,proof.DisplayName,proof.ProviderKind,
            AccountPopulation.Staff,SecurityAccountStatus.Active,proof.Key),"isolated-demo-enrollment");
        var configuration=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["SuiteSecurity:SigningKey"]=new string('s',48),["SuiteSecurity:AccountRoles:approved-demo-id:0"]="Administrator" }).Build();
        using var services=new ServiceCollection().BuildServiceProvider();
        var source=new SuiteSecurity(configuration,new HostingEnvironment{EnvironmentName="Development"},services,accounts,
            new SuiteApplication("source","source-cookie",new Dictionary<string,string[]>{{"Administrator",["Security.Manage"]}}));
        var target=new SuiteSecurity(configuration,new HostingEnvironment{EnvironmentName="Production"},services,accounts,
            new SuiteApplication("target","target-cookie",new Dictionary<string,string[]>{{"Administrator",["Security.Manage"]}}));
        var identity=Assert.IsType<SuiteIdentity>(source.AcceptVerifiedIdentity(proof));
        Assert.Null(target.AcceptVerifiedIdentity(proof));
        var http=new DefaultHttpContext();http.User=source.CreatePrincipal(identity);
        Assert.Null(target.Read(http.Request));
        Assert.Null(target.AcceptHandoff(source.CreateHandoff(identity,"target")));
        var unseen=new VerifiedIdentity(new ExternalIdentityKey("mock","control-plane","unseen-subject"),AuthenticationProviderKind.Mock,
            "another.user","Another User",DateTimeOffset.UtcNow,"isolated-server-proof");
        Assert.Null(target.AcceptVerifiedIdentity(unseen));Assert.Single(accounts.List());
    }

    private sealed class AuthenticationRecorder:IAuthenticationService
    {
        public bool SignedOut {get;private set;}
        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context,string? scheme)=>Task.FromResult(AuthenticateResult.NoResult());
        public Task ChallengeAsync(HttpContext context,string? scheme,AuthenticationProperties? properties)=>Task.CompletedTask;
        public Task ForbidAsync(HttpContext context,string? scheme,AuthenticationProperties? properties)=>Task.CompletedTask;
        public Task SignInAsync(HttpContext context,string? scheme,ClaimsPrincipal principal,AuthenticationProperties? properties)=>Task.CompletedTask;
        public Task SignOutAsync(HttpContext context,string? scheme,AuthenticationProperties? properties){SignedOut=true;return Task.CompletedTask;}
    }
}
