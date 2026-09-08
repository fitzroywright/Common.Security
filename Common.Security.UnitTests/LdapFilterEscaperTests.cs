using Common.Security.Services.Functions;
using Xunit;

namespace Common.Security.UnitTests;

public sealed class LdapFilterEscaperTests
{
    [Fact]
    public void EscapeProtectsLdapFilterMetaCharacters()
    {
        string actual = LdapFilterEscaper.Escape("a*(b)\\c");
        Assert.Equal(@"a\2a\28b\29\5cc", actual);
    }
}
