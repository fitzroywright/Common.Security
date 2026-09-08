namespace Common.Security.Models;

public sealed record DirectoryUserInfo
(
      string LoginName
    , string? DisplayName
    , string? Mail
);
