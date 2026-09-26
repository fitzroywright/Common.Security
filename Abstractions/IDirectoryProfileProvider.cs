namespace Common.Security.Abstractions;

using Common.Security.Models;

public interface IDirectoryProfileProvider
{
    Task<IReadOnlyDictionary<string, DirectoryUserProfile>> GetByLoginNamesAsync(
        IEnumerable<string> loginNames,
        CancellationToken cancellationToken = default);
}
