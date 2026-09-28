using System.Collections.Concurrent;
using System.Net;
using P2PFileTransfer.Configuration;

namespace P2PFileTransfer.Security;

/// <summary>IP allow-list plus brute-force protection (temporary ban after repeated authentication failures).</summary>
public sealed class ClientIpGuard
{
    private readonly List<IPNetwork> _allowed = [];
    private readonly ConcurrentDictionary<IPAddress, Tracker> _trackers = new();
    private readonly SecurityOptions _options;
    private readonly ILogger<ClientIpGuard> _logger;

    private sealed class Tracker
    {
        public readonly Queue<DateTime> Failures = new();
        public DateTime BannedUntilUtc;
    }

    public ClientIpGuard(P2POptions options, ILogger<ClientIpGuard> logger)
    {
        _options = options.Security;
        _logger = logger;
        foreach (var entry in _options.AllowedIPs)
            if (TryParseNetwork(entry, out var network))
                _allowed.Add(network);
    }

    public static IPAddress Normalize(IPAddress ip) => ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;

    public static bool TryParseNetwork(string value, out IPNetwork network)
    {
        value = value.Trim();
        if (value.Contains('/'))
            return IPNetwork.TryParse(value, out network);
        if (IPAddress.TryParse(value, out var ip))
        {
            ip = Normalize(ip);
            network = new IPNetwork(ip, ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128);
            return true;
        }
        network = default;
        return false;
    }

    public bool IsAllowed(IPAddress ip) => _allowed.Count == 0 || _allowed.Any(n => n.Contains(ip));

    public bool IsBanned(IPAddress ip)
    {
        if (!_trackers.TryGetValue(ip, out var t)) return false;
        lock (t) return t.BannedUntilUtc > DateTime.UtcNow;
    }

    public void RecordFailure(IPAddress ip, string reason)
    {
        var t = _trackers.GetOrAdd(ip, _ => new Tracker());
        lock (t)
        {
            var now = DateTime.UtcNow;
            var windowStart = now.AddMinutes(-_options.FailedAttemptWindowMinutes);
            while (t.Failures.Count > 0 && t.Failures.Peek() < windowStart) t.Failures.Dequeue();
            t.Failures.Enqueue(now);
            _logger.LogWarning("Rejected request from {Ip}: {Reason} ({Count}/{Max} failures)", ip, reason, t.Failures.Count, _options.MaxFailedAttempts);

            if (t.Failures.Count >= _options.MaxFailedAttempts && _options.BanMinutes > 0)
            {
                t.BannedUntilUtc = now.AddMinutes(_options.BanMinutes);
                t.Failures.Clear();
                _logger.LogWarning("IP {Ip} banned for {Minutes} minutes after repeated authentication failures", ip, _options.BanMinutes);
            }
        }
    }

    public void RecordSuccess(IPAddress ip)
    {
        if (_trackers.TryGetValue(ip, out var t))
            lock (t)
                if (t.BannedUntilUtc <= DateTime.UtcNow) t.Failures.Clear();
    }

    public void Cleanup()
    {
        var windowStart = DateTime.UtcNow.AddMinutes(-_options.FailedAttemptWindowMinutes);
        foreach (var (ip, t) in _trackers)
            lock (t)
                if (t.BannedUntilUtc <= DateTime.UtcNow && (t.Failures.Count == 0 || t.Failures.Last() < windowStart))
                    _trackers.TryRemove(ip, out _);
    }
}
