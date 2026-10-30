namespace Common.Security.UnitTests;
using Common.Security.Hosting;
using Microsoft.AspNetCore.Http;
using Xunit;

public sealed class BrowserMutationPolicyTests
{
    [Theory]
    [InlineData("POST","https://app.example.test","same-origin",true)]
    [InlineData("POST","https://other.example.test","same-site",false)]
    [InlineData("POST","https://attacker.invalid","cross-site",false)]
    [InlineData("POST",null,"same-site",false)]
    [InlineData("POST",null,null,true)]
    [InlineData("POST","null","cross-site",false)]
    [InlineData("POST","https://app.example.test/path","same-origin",false)]
    [InlineData("GET","https://attacker.invalid","cross-site",true)]
    public void BrowserSecurityMutationRequiresItsOwnOrigin(string method,string? origin,string? site,bool allowed)
    {
        var http=new DefaultHttpContext();http.Request.Scheme="https";http.Request.Host=new HostString("app.example.test");http.Request.Method=method;
        if(origin is not null)http.Request.Headers.Origin=origin;
        if(site is not null)http.Request.Headers["Sec-Fetch-Site"]=site;
        Assert.Equal(allowed,BrowserMutationPolicy.IsAllowed(http.Request));
    }
}
