namespace Common.Security.Hosting;
using Microsoft.AspNetCore.Http;

/// <summary>Rejects cross-origin browser security mutations while preserving authenticated non-browser clients.</summary>
public static class BrowserMutationPolicy
{
    public static bool IsAllowed(HttpRequest request)
    {
        if(HttpMethods.IsGet(request.Method)||HttpMethods.IsHead(request.Method)||HttpMethods.IsOptions(request.Method))return true;
        string site=request.Headers["Sec-Fetch-Site"].ToString();
        if(site.Length>0 && !site.Equals("same-origin",StringComparison.OrdinalIgnoreCase) && !site.Equals("none",StringComparison.OrdinalIgnoreCase))return false;
        var values=request.Headers.Origin;
        if(values.Count==0)return true;
        if(values.Count!=1 || !Uri.TryCreate(values[0],UriKind.Absolute,out var origin) ||
            !Uri.TryCreate(request.Scheme+"://"+request.Host.ToUriComponent(),UriKind.Absolute,out var target))return false;
        return string.IsNullOrEmpty(origin.UserInfo) && origin.AbsolutePath=="/" && string.IsNullOrEmpty(origin.Query) && string.IsNullOrEmpty(origin.Fragment) &&
            origin.Scheme.Equals(target.Scheme,StringComparison.OrdinalIgnoreCase) && origin.IdnHost.Equals(target.IdnHost,StringComparison.OrdinalIgnoreCase) && origin.Port==target.Port;
    }
}
