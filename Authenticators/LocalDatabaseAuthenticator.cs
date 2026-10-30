namespace Common.Security.Authenticators;

using Common.Security.Abstractions;
using Common.Security.Models;

public sealed class LocalDatabaseAuthenticator(ILocalCredentialStore store) : IAuthenticator
{
    public AuthenticationResult Authenticate(string loginName, string password)
    {
        if (string.IsNullOrWhiteSpace(loginName) || string.IsNullOrEmpty(password))
            return AuthenticationResult.Failed();
        return store.AuthenticateLocal(loginName, password);
    }
}
