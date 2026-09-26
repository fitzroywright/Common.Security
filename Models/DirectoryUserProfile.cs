namespace Common.Security.Models;

public sealed record DirectoryUserProfile(
    string LoginName,
    string DisplayName,
    string EmailAddress,
    string Department,
    string Extension,
    string Manager,
    IReadOnlyList<string> GroupNames);
