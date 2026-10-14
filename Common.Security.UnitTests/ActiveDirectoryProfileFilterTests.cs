namespace Common.Security.UnitTests;

using Common.Security.Plugin.ActiveDirectory;
using Xunit;

public sealed class ActiveDirectoryProfileFilterTests
{
    [Fact]
    public void SingleEmployee_HasCompleteUserFilter()
    {
        Assert.Equal("(&(objectCategory=person)(objectClass=user)(sAMAccountName=fwright))",
            ActiveDirectoryDirectoryProfileProvider.BuildSearchFilter(["fwright"]));
    }

    [Fact]
    public void MultipleEmployees_EachEqualityConditionIsClosed()
    {
        Assert.Equal("(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=fwright)(sAMAccountName=asmith)))",
            ActiveDirectoryDirectoryProfileProvider.BuildSearchFilter(["fwright", "asmith"]));
    }

    [Theory]
    [InlineData("*", @"\2a")]
    [InlineData("(", @"\28")]
    [InlineData(")", @"\29")]
    [InlineData(@"\", @"\5c")]
    [InlineData("\0", @"\00")]
    public void BulkLookup_EscapesSpecialCharactersWithoutChangingFilterStructure(string value, string escaped)
    {
        Assert.Equal($"(&(objectCategory=person)(objectClass=user)(|(sAMAccountName={escaped})(sAMAccountName=fwright)))",
            ActiveDirectoryDirectoryProfileProvider.BuildSearchFilter([value, "fwright"]));
    }

    [Fact]
    public void TenEmployeeBatch_ContainsTenCompleteConditions()
    {
        string[] names = Enumerable.Range(1, 10).Select(i => $"employee{i}").ToArray();
        string filter = ActiveDirectoryDirectoryProfileProvider.BuildSearchFilter(names);
        foreach (string name in names)
            Assert.Contains($"(sAMAccountName={name})", filter);
        Assert.Equal(filter.Count(c => c == '('), filter.Count(c => c == ')'));
    }

    [Fact]
    public void EmptyBatch_DoesNotProduceAnUnrestrictedSearch()
    {
        Assert.Throws<ArgumentException>(() => ActiveDirectoryDirectoryProfileProvider.BuildSearchFilter([]));
    }
}
