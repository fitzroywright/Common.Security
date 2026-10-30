namespace Common.Security.Abstractions;

using Common.Security.Models;

/// <summary>Verification/lockout updates and recovery consumption are atomic in application storage.</summary>
public interface ILocalCredentialStore
{
    AuthenticationResult AuthenticateLocal(string loginName, string password);
    void SetLocalPassword(string accountId, string newPassword, string actorId);
    string IssueRecovery(string accountId, string actorId);
    bool Recover(string token, string newPassword);
}
