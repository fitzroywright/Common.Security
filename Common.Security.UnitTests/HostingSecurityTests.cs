namespace Common.Security.UnitTests;

using System.Security.Claims;
using Common.Security.Abstractions;
using Common.Security.Hosting;
using Common.Security.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

public sealed class HostingSecurityTests
{
    [Fact]
    public void CallerSuppliedSidClaimsCannotImpersonateAWindowsIdentity()
    {
        var principal=new ClaimsPrincipal(new ClaimsIdentity(new[]{new Claim(ClaimTypes.PrimarySid,"S-1-5-21-1-2-3-999")},"Negotiate"));
        Assert.Throws<InvalidOperationException>(()=>WindowsNegotiateIdentity.FromValidatedPrincipal(principal));
    }

    [Theory]
    [InlineData(SecurityAccountStatus.PendingAccess,403)]
    [InlineData(SecurityAccountStatus.Disabled,401)]
    [InlineData(SecurityAccountStatus.Suspended,401)]
    [InlineData(SecurityAccountStatus.Active,200)]
    public async Task BusinessMiddlewareChecksLiveAccountState(SecurityAccountStatus status,int expected)
    {
        using var db=new AccountProvisioningTests.Database();
        var account=db.Store.Resolve(AccountProvisioningTests.Identity(),AccountPopulation.Staff,true).Account;
        db.Store.SetStatus(account.Id,status,"administrator");account=db.Store.Find(account.Id)!;
        using var services=new ServiceCollection().AddSingleton<IAccountStore>(db.Store).BuildServiceProvider();
        var app=new ApplicationBuilder(services);app.UseCommonAccountEnforcement("/login");
        app.Run(context=> {context.Response.StatusCode=200;return Task.CompletedTask;});
        var http=new DefaultHttpContext {RequestServices=services};http.Request.Path="/api/business";
        http.Response.Body=new MemoryStream();
        http.User=new ClaimsPrincipal(new ClaimsIdentity(AccountSecurityHosting.SessionClaims(account,AccountProvisioningTests.Identity()),"test"));
        await app.Build()(http);Assert.Equal(expected,http.Response.StatusCode);
    }

    [Fact]
    public async Task PendingIdentityCanReachItsOwnStatusButCannotUseBusinessEndpoints()
    {
        using var db=new AccountProvisioningTests.Database();var proof=AccountProvisioningTests.Identity();
        var account=db.Store.Resolve(proof,AccountPopulation.Staff,true).Account;
        using var services=new ServiceCollection().AddSingleton<IAccountStore>(db.Store).BuildServiceProvider();
        var app=new ApplicationBuilder(services);app.UseCommonAccountEnforcement("/login","/api/auth/me");
        app.Run(_=>Task.CompletedTask);
        var http=new DefaultHttpContext {RequestServices=services};http.Request.Path="/api/auth/me";
        http.User=new ClaimsPrincipal(new ClaimsIdentity(AccountSecurityHosting.SessionClaims(account,proof),"test"));
        await app.Build()(http);Assert.Equal(200,http.Response.StatusCode);
    }

    [Fact]
    public async Task AuthenticationLimiterRejectsEleventhAttempt()
    {
        using var db=new AccountProvisioningTests.Database();
        var builder=WebApplication.CreateBuilder();builder.WebHost.UseTestServer();
        builder.Services.AddCommonAccountSecurity(_=>db.Connection(),"limiter-test");
        await using var app=builder.Build();app.UseRouting();app.UseRateLimiter();
        app.MapPost("/login",()=>Results.Unauthorized()).RequireRateLimiting(AccountSecurityHosting.LoginRateLimit);
        await app.StartAsync();using var client=app.GetTestClient();
        for(int i=0;i<10;i++) Assert.Equal(System.Net.HttpStatusCode.Unauthorized,(await client.PostAsync("/login",null)).StatusCode);
        Assert.Equal(System.Net.HttpStatusCode.TooManyRequests,(await client.PostAsync("/login",null)).StatusCode);
    }

    [Fact]
    public void ApplicationProjectionAndIdentityProvisioningRollbackTogether()
    {
        using var db=new AccountProvisioningTests.Database();db.Execute("CREATE TABLE business_profile(id TEXT PRIMARY KEY)");
        var store=new Common.Security.Integration.RelationalAccountStore(db.Connection,"projection",provisionApplicationRecord:(c,t,a,p)=>
        {
            using var q=c.CreateCommand();q.Transaction=t;q.CommandText="INSERT INTO business_profile VALUES('profile')";q.ExecuteNonQuery();
            throw new InvalidOperationException("Business persistence failed.");
        });
        Assert.Throws<InvalidOperationException>(()=>store.Resolve(AccountProvisioningTests.Identity(),AccountPopulation.PublicApplicant,true));
        Assert.Empty(store.List());Assert.Equal(0L,db.Scalar("SELECT COUNT(*) FROM business_profile"));
    }

    [Fact]
    public void UnlinkedIdentityCannotAutomaticallyReenrollWithAChangedAlias()
    {
        using var db=new AccountProvisioningTests.Database();var proof=AccountProvisioningTests.Identity();
        var account=db.Store.Resolve(proof,AccountPopulation.Staff,true).Account;
        db.Store.Unlink(account.Id,proof.Key,"administrator");
        Assert.Throws<InvalidOperationException>(()=>db.Store.Resolve(AccountProvisioningTests.Identity(login:"renamed"),AccountPopulation.Staff,true));
        db.Store.Link(account.Id,proof,"administrator-approved-reenrollment");
        Assert.Equal(account.Id,db.Store.Resolve(proof,AccountPopulation.Staff,true).Account.Id);
    }

    [Fact]
    public void ImportPreservesMultiplePreviouslyLinkedProviderIdentities()
    {
        using var db=new AccountProvisioningTests.Database();var google=new Common.Security.Models.ExternalIdentityKey("Google","https://accounts.google.com","google-subject");
        var microsoft=new Common.Security.Models.ExternalIdentityKey("Microsoft","https://graph.microsoft.com","microsoft-subject");
        var row=new AccountCreation("original-applicant-id","person@example.test","Existing Applicant",Common.Security.Models.AuthenticationProviderKind.External,
            AccountPopulation.PublicApplicant,SecurityAccountStatus.Active,google,[microsoft]);
        db.Store.ImportApprovedAccounts([row],"approved-migration");db.Store.ImportApprovedAccounts([row],"approved-migration");
        Assert.Equal(2,db.Store.GetIdentities(row.Id).Count);Assert.Single(db.Store.List());
    }

    [Fact]
    public void OpaqueBearerSessionImmediatelyRejectsRevocation()
    {
        using var db=new AccountProvisioningTests.Database();var account=db.Store.Resolve(AccountProvisioningTests.Identity(),AccountPopulation.Operator,true).Account;
        db.Store.SetStatus(account.Id,SecurityAccountStatus.Active,"administrator");account=db.Store.Find(account.Id)!;
        var sessions=new OpaqueAccountSessions<string>(db.Store);var session=sessions.Create(account.Id,account.SessionVersion,"operator",TimeSpan.FromMinutes(30));
        Assert.NotNull(sessions.Find(session.Token));db.Store.RevokeSessions(account.Id,"administrator");Assert.Null(sessions.Find(session.Token));
    }
}
