using P2PFileTransfer.Configuration;

namespace P2PFileTransfer.Storage;

public sealed record ReceivedRecord(
    DateTimeOffset ReceivedAtUtc,
    string Sender,
    string Destination,
    string FileName,
    string SavedPath,
    long Size,
    string Sha256,
    string? RemoteIp);

/// <summary>Log of files received by this node. Also used to detect duplicates if a sender lost its own history.</summary>
public sealed class ReceivedLog(P2POptions options)
{
    private readonly JsonListFile<ReceivedRecord> _file = new(Path.Combine(PathHelper.Resolve(options.DataDirectory), "received-log.json"));

    public string FilePath => _file.FilePath;

    public async Task<ReceivedRecord?> FindAsync(string sender, string destination, string fileName, string sha256, CancellationToken ct)
    {
        var list = await _file.ReadAsync(ct);
        return list.LastOrDefault(r =>
            string.Equals(r.Sender, sender, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(r.Destination, destination, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(r.FileName, fileName, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(r.Sha256, sha256, StringComparison.OrdinalIgnoreCase));
    }

    public Task AddAsync(ReceivedRecord record, CancellationToken ct) =>
        _file.UpdateAsync(list => { list.Add(record); return true; }, ct);

    /// <summary>Removes entries for files that were deleted from disk more than 30 days after reception.</summary>
    public Task PruneAsync(CancellationToken ct) =>
        _file.UpdateAsync(list =>
        {
            var cutoff = DateTimeOffset.UtcNow.AddDays(-30);
            return list.RemoveAll(r => r.ReceivedAtUtc < cutoff && !File.Exists(r.SavedPath)) > 0;
        }, ct);
}
