using Common.Security.Authorization;

namespace Common.Security.Abstractions;

public interface IPermissionAuthorizer
{
    Task<AuthorizationDecision> AuthorizeAsync(
        AuthorizationSubject subject,
        string permission,
        CancellationToken cancellationToken = default);

    async Task<bool> CanAsync(
        AuthorizationSubject subject,
        string permission,
        CancellationToken cancellationToken = default)
        => (await AuthorizeAsync(subject, permission, cancellationToken).ConfigureAwait(false)).Allowed;
}
