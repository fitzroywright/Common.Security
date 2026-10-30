namespace Common.Security.Hosting;
using System.Security.Claims;
using System.Security.Principal;
using Common.Security.Models;

/// <summary>Uses only a WindowsIdentity authenticated by the host Negotiate handler. Request claims cannot substitute a SID.</summary>
public static class WindowsNegotiateIdentity
{
    public static VerifiedIdentity FromValidatedPrincipal(ClaimsPrincipal principal)
    {
        if(!OperatingSystem.IsWindows() || principal.Identity is not WindowsIdentity windows || !windows.IsAuthenticated ||
            windows.User is null || windows.User.AccountDomainSid is null)
            throw new InvalidOperationException("A validated domain Windows identity with immutable SIDs is required.");
        var groups=new List<string>();
        foreach(var sid in windows.Groups ?? new IdentityReferenceCollection())
        {
            groups.Add(sid.Value);
            try {string name=sid.Translate(typeof(NTAccount)).Value;groups.Add(name);int slash=name.LastIndexOf('\\');if(slash>=0)groups.Add(name[(slash+1)..]);}
            catch(IdentityNotMappedException) { }
        }
        string login=windows.Name;int separator=login.LastIndexOf('\\');if(separator>=0)login=login[(separator+1)..];
        return new VerifiedIdentity(new ExternalIdentityKey("windows-negotiate",windows.User.AccountDomainSid.Value,windows.User.Value),
            AuthenticationProviderKind.ActiveDirectory,login,login,DateTimeOffset.UtcNow,"windows-negotiate",groups:groups);
    }
}
