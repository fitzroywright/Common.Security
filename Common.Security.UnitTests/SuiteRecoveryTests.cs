namespace Common.Security.UnitTests;
using Common.Security.Abstractions;
using Common.Security.Hosting;
using Common.Security.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting.Internal;
using Xunit;

public sealed class SuiteRecoveryTests
{
    [Fact]
    public void LocalEmergencyRecoveryRequiresExplicitEnrollmentAndRetainsAccountAndRoles()
    {
        using var db=new AccountProvisioningTests.Database();var accounts=db.OtherApplication("control-plane");accounts.EnsureSchema();
        accounts.Create(new AccountCreation("approved-admin-id","emergency.admin","Emergency Administrator",AuthenticationProviderKind.LocalDatabase,
            AccountPopulation.Staff,SecurityAccountStatus.Active),"offline-authorized-enrollment","original-local-password");
        using var services=new ServiceCollection().AddSingleton<ILocalCredentialStore>(accounts).BuildServiceProvider();
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["SuiteSecurity:Mode"]="LocalDatabase",["SuiteSecurity:SigningKey"]=new string('a',48),
            ["SuiteSecurity:AccountRoles:approved-admin-id:0"]="Administrator" }).Build();
        var suite=new SuiteSecurity(config,new HostingEnvironment {EnvironmentName="Production"},services,accounts,
            new SuiteApplication("Operations","cookie",new Dictionary<string,string[]>{{"Administrator",["Security.Manage","Operations.View"]}}));
        var identity=suite.Authenticate("emergency.admin","original-local-password");Assert.NotNull(identity);Assert.Contains("Security.Manage",identity.Permissions);
        var request=new DefaultHttpContext();request.User=suite.CreatePrincipal(identity);
        var recovery=accounts.IssueRecovery("approved-admin-id","offline-authorized-recovery");
        Assert.True(accounts.Recover(recovery,"replacement-local-password"));
        Assert.Null(suite.Read(request.Request));Assert.Null(suite.Authenticate("emergency.admin","original-local-password"));
        var recovered=suite.Authenticate("emergency.admin","replacement-local-password");Assert.Equal(identity.AccountId,recovered!.AccountId);
        Assert.Contains("Security.Manage",recovered.Permissions);Assert.False(accounts.Recover(recovery,"another-local-password"));
    }
    [Fact]
    public void CorrectLocalPasswordDoesNotGrantAnUnassignedAdministrativeRole()
    {
        using var db=new AccountProvisioningTests.Database();var accounts=db.OtherApplication("control-plane");accounts.EnsureSchema();
        accounts.Create(new AccountCreation("no-role","operator","Operator",AuthenticationProviderKind.LocalDatabase,
            AccountPopulation.Staff,SecurityAccountStatus.Active),"administrator","correct-local-password");
        using var services=new ServiceCollection().AddSingleton<ILocalCredentialStore>(accounts).BuildServiceProvider();
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["SuiteSecurity:Mode"]="LocalDatabase",["SuiteSecurity:SigningKey"]=new string('a',48),
            ["SuiteSecurity:AccountRoles:operator:0"]="Administrator" }).Build();
        var suite=new SuiteSecurity(config,new HostingEnvironment {EnvironmentName="Production"},services,accounts,
            new SuiteApplication("Operations","cookie",new Dictionary<string,string[]>{{"Administrator",["Security.Manage"]}}));
        Assert.Null(suite.Authenticate("operator","correct-local-password"));
    }
}
