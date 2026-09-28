namespace Common.Security.UnitTests;

using Common.Security.Plugin.ActiveDirectory;
using Xunit;

public sealed class DirectoryProfileSearchFilterTests
{
    [Fact]
    public void MultipleEmployees_EachAccountClauseIsClosed()
    {
        Assert.Equal(
            "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=alice)(sAMAccountName=bob)))",
            DirectoryProfileSearchFilter.Build(["alice", "bob"]));
    }

    [Fact]
    public void SingleEmployee_DoesNotNeedOrClause()
    {
        Assert.Equal(
            "(&(objectCategory=person)(objectClass=user)(sAMAccountName=alice))",
            DirectoryProfileSearchFilter.Build(["alice", "ALICE"]));
    }

    [Fact]
    public void AccountNames_AreEscapedInsideEachClause()
    {
        Assert.Equal(
            @"(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=a\2a\28b\29)(sAMAccountName=c\5cd)))",
            DirectoryProfileSearchFilter.Build(["a*(b)", @"c\d"]));
    }

    [Fact]
    public void EmptyRequest_IsRejectedInsteadOfMatchingEveryEmployee()
    {
        Assert.Throws<ArgumentException>(() => DirectoryProfileSearchFilter.Build([]));
    }
}
