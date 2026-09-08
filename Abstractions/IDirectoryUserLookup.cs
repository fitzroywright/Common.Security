namespace Common.Security.Abstractions;

using Common.Security.Models;

public interface IDirectoryUserLookup
{
    DirectoryUserInfo? FindByLoginName(string loginName);
}
