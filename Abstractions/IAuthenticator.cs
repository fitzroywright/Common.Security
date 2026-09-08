namespace Common.Security.Abstractions
{
    using Common.Security.Models;

    public interface IAuthenticator
    {
        public AuthenticationResult Authenticate(string loginName, string password);
    }
}
