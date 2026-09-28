using P2PFileTransfer.Configuration;

namespace P2PFileTransfer.Storage;

public sealed record SentRecord(
    string Job,
    string Peer,
    string SourcePath,
    long Size,
    DateTime LastWriteUtc,
    string Sha256,
    DateTimeOffset SentAtUtc,
    string? RemoteName);

/// <summary>History of files already delivered, per job and peer, so they are never sent twice.</summary>
public sealed class SentHistory(P2POptions options)
{
    private readonly JsonListFile<SentRecord> _file = new(Path.Combine(PathHelper.Resolve(options.DataDirectory), "sent-history.json"));

    public string FilePath => _file.FilePath;

    /// <summary>A file is identified by its full path, size and last write time.</summary>
    public static string Key(string job, string peer, string sourcePath, long size, DateTime lastWriteUtc)
    {
        var path = Path.GetFullPath(sourcePath);
        if (OperatingSystem.IsWindows()) path = path.ToUpperInvariant();
        return $"{job.ToUpperInvariant()}|{peer.ToUpperInvariant()}|{path}|{size}|{lastWriteUtc.Ticks / TimeSpan.TicksPerSecond}";
    }

    public async Task<HashSet<string>> LoadKeysAsync(string job, CancellationToken ct)
    {
        var list = await _file.ReadAsync(ct);
        return list.Where(r => string.Equals(r.Job, job, StringComparison.OrdinalIgnoreCase))
                   .Select(r => Key(r.Job, r.Peer, r.SourcePath, r.Size, r.LastWriteUtc))
                   .ToHashSet(StringComparer.Ordinal);
    }

    public Task<List<SentRecord>> ReadAllAsync(CancellationToken ct) => _file.ReadAsync(ct);

    public Task AddAsync(SentRecord record, CancellationToken ct) =>
        _file.UpdateAsync(list => { list.Add(record); return true; }, ct);

    /// <summary>Forgets entries whose source file no longer exists (e.g. rotated backups) after a grace period.</summary>
    public Task PruneAsync(string job, IReadOnlySet<string> existingPaths, CancellationToken ct) =>
        _file.UpdateAsync(list =>
        {
            var cutoff = DateTimeOffset.UtcNow.AddDays(-7);
            return list.RemoveAll(r =>
                string.Equals(r.Job, job, StringComparison.OrdinalIgnoreCase) &&
                r.SentAtUtc < cutoff &&
                !existingPaths.Contains(r.SourcePath)) > 0;
        }, ct);
}
