namespace Common.Security.Services;

using System.Security.Cryptography;
using System.Text.Json;
using Common.Security.Models;

public sealed record SecuritySessionTicket(string Id, string AccountId, string Audience,
    long SessionVersion, long IssuedAt, long ExpiresAt, string Purpose, ExternalIdentityKey? ExternalIdentity);

public sealed class SessionTicketProtector
{
    private readonly byte[] key;
    private readonly TimeProvider clock;

    public SessionTicketProtector(byte[] signingKey, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        if (signingKey.Length < 32) throw new ArgumentException("A protected signing key of at least 32 bytes is required.");
        key = signingKey.ToArray();
        clock = timeProvider ?? TimeProvider.System;
    }

    public string Create(string accountId, string audience, long sessionVersion, TimeSpan lifetime, string purpose = "session",
        ExternalIdentityKey? externalIdentity = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accountId);
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);
        if (sessionVersion < 1 || lifetime <= TimeSpan.Zero || lifetime > TimeSpan.FromHours(8) ||
            purpose is not ("session" or "handoff") || purpose == "handoff" && (lifetime > TimeSpan.FromSeconds(60) || externalIdentity is null))
            throw new ArgumentException("Invalid session version, purpose or lifetime.");
        long now = clock.GetUtcNow().ToUnixTimeSeconds();
        var ticket = new SecuritySessionTicket(Guid.NewGuid().ToString("D"), accountId, audience,
            sessionVersion, now, clock.GetUtcNow().Add(lifetime).ToUnixTimeSeconds(), purpose, externalIdentity);
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(ticket);
        return Encode(payload) + "." + Encode(HMACSHA256.HashData(key, payload));
    }

    /// <summary>The mandatory policy checks current account state/version and consumes handoffs once.</summary>
    public SecuritySessionTicket? Validate(string? token, string audience, string purpose,
        Func<SecuritySessionTicket, bool> currentSessionPolicy)
    {
        ArgumentNullException.ThrowIfNull(currentSessionPolicy);
        if (string.IsNullOrWhiteSpace(token) || token.Length > 8192) return null;
        string[] pieces = token.Split('.');
        if (pieces.Length != 2) return null;
        try
        {
            byte[] payload = Decode(pieces[0]), signature = Decode(pieces[1]);
            if (!CryptographicOperations.FixedTimeEquals(HMACSHA256.HashData(key, payload), signature)) return null;
            SecuritySessionTicket? ticket = JsonSerializer.Deserialize<SecuritySessionTicket>(payload);
            long now = clock.GetUtcNow().ToUnixTimeSeconds();
            if (ticket is null || !Guid.TryParseExact(ticket.Id, "D", out _) || string.IsNullOrWhiteSpace(ticket.AccountId) ||
                ticket.Audience != audience || ticket.Purpose != purpose || ticket.SessionVersion < 1 ||
                purpose == "handoff" && ticket.ExternalIdentity is null ||
                ticket.IssuedAt > now + 120 || ticket.ExpiresAt <= now || ticket.ExpiresAt <= ticket.IssuedAt ||
                ticket.ExpiresAt - ticket.IssuedAt > (purpose == "handoff" ? 60 : 8 * 3600)) return null;
            return currentSessionPolicy(ticket) ? ticket : null;
        }
        catch (Exception e) when (e is FormatException or JsonException or ArgumentException) { return null; }
    }

    private static string Encode(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] Decode(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(padded.PadRight((padded.Length + 3) / 4 * 4, '='));
    }
}
