using System.Collections.Concurrent;
using P2PFileTransfer.Configuration;

namespace P2PFileTransfer.Security;

/// <summary>Remembers recently used request nonces to block replayed requests.</summary>
public sealed class NonceCache(P2POptions options)
{
    private readonly ConcurrentDictionary<string, long> _seen = new(StringComparer.Ordinal);
    private readonly TimeSpan _ttl = TimeSpan.FromSeconds(options.Security.ClockSkewSeconds * 2 + 60);
    private long _nextCleanup;

    /// <summary>Returns false if the nonce was already used.</summary>
    public bool TryUse(string node, string nonce)
    {
        var now = Environment.TickCount64;
        if (now >= Interlocked.Read(ref _nextCleanup))
        {
            Interlocked.Exchange(ref _nextCleanup, now + 60_000);
            foreach (var (key, expiry) in _seen)
                if (expiry < now) _seen.TryRemove(key, out _);
        }
        return _seen.TryAdd(node + "|" + nonce, now + (long)_ttl.TotalMilliseconds);
    }
}
