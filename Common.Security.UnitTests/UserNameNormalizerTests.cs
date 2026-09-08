using Common.Security.Services.Functions;
using Xunit;

namespace Common.Security.UnitTests;

public sealed class UserNameNormalizerTests
{
    [Theory]
    [InlineData("EXAMPLE\\TestUser", "testuser")]
    [InlineData("testuser@example.local", "testuser")]
    [InlineData(" TESTUSER ", "testuser")]
    public void GetUserNameWithoutDomainNormalizesSupportedForms(string input, string expected)
    {
        string actual = UserNameNormalizer.GetUserNameWithoutDomain(input);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void NormalizeLoginAddsDefaultDomain()
    {
        string actual = UserNameNormalizer.NormalizeLogin("TestUser", "example.local");
        Assert.Equal("testuser@example.local", actual);
    }

    [Fact]
    public void MatchesAllowsQualifiedAndShortNames()
    {
        Assert.True(UserNameNormalizer.Matches("testuser", "testuser@example.local"));
    }
}
