namespace Common.Security.Integration;

using Common.Security.Options;
using Microsoft.Extensions.Configuration;

/// <summary>Reads server-owned mock definitions; never accepts a requested identity as configuration.</summary>
public static class MockAuthenticationConfiguration
{
    public static MockAuthenticationOptions Read(IConfigurationSection section, string environmentName, string applicationId)
    {
        var definitions = new List<MockIdentityDefinition>();
        foreach (IConfigurationSection identity in section.GetSection("Identities").GetChildren())
        {
            string login = identity["LoginName"] ?? throw new InvalidOperationException("Mock LoginName is required.");
            string subject = identity["SubjectId"] ?? throw new InvalidOperationException("Mock SubjectId is required.");
            definitions.Add(new(login, subject, identity["DisplayName"] ?? login,
                identity.GetSection("Groups").GetChildren().Select(x => x.Value).OfType<string>().ToArray(), identity["Email"]));
        }
        return new MockAuthenticationOptions
        {
            Enabled = bool.TryParse(section["Enabled"], out bool enabled) && enabled,
            EnvironmentName = environmentName,
            IsolationConfirmed = bool.TryParse(section["IsolationConfirmed"], out bool isolated) && isolated,
            ApplicationId = applicationId,
            Password = section["Password"] ?? string.Empty,
            Identities = definitions
        };
    }
}
