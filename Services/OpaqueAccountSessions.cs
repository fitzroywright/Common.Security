namespace Common.Security.Services;

using System.Collections.Concurrent;
using System.Security.Cryptography;
using Common.Security.Abstractions;

public sealed record OpaqueAccountSession<T>(string Token, string AccountId, long SessionVersion,
    T Identity, DateTimeOffset ExpiresAt);

/// <summary>Ephemeral server sessions; account status/version are authoritative on every use.</summary>
public sealed class OpaqueAccountSessions<T>(IAccountStore accounts, TimeProvider? timeProvider = null)
{
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;
    private readonly ConcurrentDictionary<string, OpaqueAccountSession<T>> sessions = new(StringComparer.Ordinal);

    public OpaqueAccountSession<T> Create(string accountId, long version, T identity, TimeSpan lifetime)
    {
        if (lifetime <= TimeSpan.Zero || lifetime > TimeSpan.FromHours(8)) throw new ArgumentOutOfRangeException(nameof(lifetime));
        if (!new AccountProvisioningService(accounts, clock).IsCurrentSession(accountId, version))
            throw new UnauthorizedAccessException("An active approved account is required.");
        foreach(var expired in sessions.Where(x=>x.Value.ExpiresAt<=clock.GetUtcNow())) sessions.TryRemove(expired.Key,out _);
        if(sessions.Count>=10000) throw new InvalidOperationException("The host session capacity has been reached.");
        string token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var session = new OpaqueAccountSession<T>(token, accountId, version, identity, clock.GetUtcNow().Add(lifetime));
        sessions[token] = session;
        return session;
    }

    public OpaqueAccountSession<T>? Find(string token)
    {
        if (string.IsNullOrWhiteSpace(token) || token.Length > 128 || !sessions.TryGetValue(token, out var session)) return null;
        if (session.ExpiresAt <= clock.GetUtcNow() ||
            !new AccountProvisioningService(accounts, clock).IsCurrentSession(session.AccountId, session.SessionVersion))
        {
            sessions.TryRemove(token, out _);
            return null;
        }
        return session;
    }

    public void Remove(string token) => sessions.TryRemove(token, out _);
}
