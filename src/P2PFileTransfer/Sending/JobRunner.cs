using System.Diagnostics;
using System.Security.Cryptography;
using P2PFileTransfer.Configuration;
using P2PFileTransfer.Protocol;
using P2PFileTransfer.Security;
using P2PFileTransfer.Storage;

namespace P2PFileTransfer.Sending;

public sealed record JobResult(string Job, int Sent, int Skipped, int Failed, bool Ran)
{
    public bool Success => Ran && Failed == 0;
}

/// <summary>Executes one transfer job: finds new files, sends them to every target peer and records them in the history.</summary>
public sealed class JobRunner(
    P2POptions options,
    PeerClientFactory clients,
    KeyMaterial keys,
    SentHistory history,
    ILogger<JobRunner> logger)
{
    public async Task<JobResult> RunAsync(JobOptions job, CancellationToken ct)
    {
        var lockPath = Path.Combine(PathHelper.Resolve(options.DataDirectory), "locks", $"job-{job.Name.ToLowerInvariant()}.lock");
        using var jobLock = FileLock.TryAcquire(lockPath);
        if (jobLock is null)
        {
            logger.LogWarning("Job {Job} is already running (lock {Lock}); skipping this run", job.Name, lockPath);
            return new JobResult(job.Name, 0, 0, 0, Ran: false);
        }

        var stopwatch = Stopwatch.StartNew();
        logger.LogInformation("Job {Job} started", job.Name);

        List<FileInfo> files;
        try
        {
            files = EnumerateFiles(job);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            logger.LogError("Job {Job}: cannot read source directory {Dir}: {Error}", job.Name, job.SourceDirectory, ex.Message);
            return new JobResult(job.Name, 0, 0, 1, Ran: true);
        }

        await history.PruneAsync(job.Name, files.Select(f => f.FullName).ToHashSet(PathHelper.PathComparer), ct);
        var sentKeys = await history.LoadKeysAsync(job.Name, ct);

        int sent = 0, skipped = 0, failed = 0;
        var now = DateTime.UtcNow;
        var minAge = TimeSpan.FromMinutes(options.Sender.MinFileAgeMinutes);

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            file.Refresh();
            if (!file.Exists) continue;

            if (job.MaxFileAgeDays > 0 && file.LastWriteTimeUtc < now.AddDays(-job.MaxFileAgeDays))
            {
                skipped++;
                continue;
            }
            if (now - file.LastWriteTimeUtc < minAge)
            {
                logger.LogInformation("Job {Job}: {File} was modified less than {Minutes} minutes ago (backup still running?); will retry next run",
                    job.Name, file.Name, options.Sender.MinFileAgeMinutes);
                skipped++;
                continue;
            }

            var pendingPeers = job.TargetPeers
                .Where(p => !sentKeys.Contains(SentHistory.Key(job.Name, p, file.FullName, file.Length, file.LastWriteTimeUtc)))
                .ToList();
            if (pendingPeers.Count == 0)
            {
                skipped++;
                continue;
            }

            var snapshot = (file.Length, file.LastWriteTimeUtc);
            var hash = await ComputeStableHashAsync(file, ct);
            if (hash is null)
            {
                skipped++;
                continue;
            }

            foreach (var peerName in pendingPeers)
            {
                ct.ThrowIfCancellationRequested();
                var peer = clients.Get(peerName);
                try
                {
                    var remoteName = await SendWithRetriesAsync(peer, job, file, hash, ct);
                    await history.AddAsync(new SentRecord(job.Name, peer.Peer.Name, file.FullName, snapshot.Length, snapshot.LastWriteTimeUtc,
                        hash, DateTimeOffset.UtcNow, remoteName), CancellationToken.None);
                    sentKeys.Add(SentHistory.Key(job.Name, peer.Peer.Name, file.FullName, snapshot.Length, snapshot.LastWriteTimeUtc));
                    sent++;
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    failed++;
                    logger.LogError("Job {Job}: failed to send {File} to {Peer}: {Error}", job.Name, file.Name, peer.Peer.Name, ex.Message);
                    logger.LogDebug(ex, "Transfer failure details");
                }
            }
        }

        logger.LogInformation("Job {Job} finished in {Elapsed}: {Sent} sent, {Skipped} skipped, {Failed} failed",
            job.Name, stopwatch.Elapsed.ToString(@"hh\:mm\:ss"), sent, skipped, failed);
        return new JobResult(job.Name, sent, skipped, failed, Ran: true);
    }

    private List<FileInfo> EnumerateFiles(JobOptions job)
    {
        var dir = new DirectoryInfo(PathHelper.Resolve(job.SourceDirectory));
        if (!dir.Exists) throw new DirectoryNotFoundException($"'{dir.FullName}' does not exist");

        var enumeration = new EnumerationOptions
        {
            RecurseSubdirectories = job.IncludeSubdirectories,
            IgnoreInaccessible = true,
            MatchCasing = MatchCasing.CaseInsensitive,
            AttributesToSkip = FileAttributes.System | FileAttributes.Hidden | FileAttributes.ReparsePoint,
        };
        var patterns = job.FilePatterns.Count > 0 ? job.FilePatterns : ["*"];
        var separator = Path.DirectorySeparatorChar;

        return patterns
            .SelectMany(p => dir.EnumerateFiles(p.Trim(), enumeration))
            .Where(f => !f.Name.EndsWith(".part", StringComparison.OrdinalIgnoreCase) &&
                        !f.FullName.Contains($"{separator}{Receiving.TransferReceiver.StagingFolderName}{separator}", StringComparison.Ordinal))
            .DistinctBy(f => f.FullName, PathHelper.PathComparer)
            .OrderBy(f => f.LastWriteTimeUtc)
            .ToList();
    }

    /// <summary>Hashes the file and makes sure it did not change meanwhile (e.g. a backup still being written).</summary>
    private async Task<string?> ComputeStableHashAsync(FileInfo file, CancellationToken ct)
    {
        var before = (file.Length, file.LastWriteTimeUtc);
        try
        {
            await using var fs = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan | FileOptions.Asynchronous);
            var hash = Convert.ToHexStringLower(await SHA256.HashDataAsync(fs, ct));
            file.Refresh();
            if (file.Length != before.Length || file.LastWriteTimeUtc != before.LastWriteTimeUtc)
            {
                logger.LogInformation("{File} changed while being hashed; will retry next run", file.Name);
                return null;
            }
            return hash;
        }
        catch (IOException ex)
        {
            logger.LogInformation("{File} is in use by another process ({Error}); will retry next run", file.Name, ex.Message);
            return null;
        }
        catch (UnauthorizedAccessException ex)
        {
            logger.LogError("Access denied to {File}: {Error}", file.FullName, ex.Message);
            return null;
        }
    }

    private async Task<string> SendWithRetriesAsync(PeerClient peer, JobOptions job, FileInfo file, string hash, CancellationToken ct)
    {
        var maxAttempts = options.Sender.MaxRetries + 1;
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return await SendOnceAsync(peer, job, file, hash, ct);
            }
            catch (PeerException ex) when (!ex.Retryable)
            {
                throw;
            }
            catch (Exception ex) when (attempt < maxAttempts && !ct.IsCancellationRequested && ex is PeerException or IOException or HttpRequestException)
            {
                var delay = ex is PeerException { StatusCode: 409 }
                    ? TimeSpan.FromSeconds(1)
                    : TimeSpan.FromSeconds(options.Sender.RetryDelaySeconds * attempt);
                logger.LogWarning("Sending {File} to {Peer} failed (attempt {Attempt}/{Max}): {Error}. Retrying in {Delay}s (transfer resumes where it stopped)",
                    file.Name, peer.Peer.Name, attempt, maxAttempts, ex.Message, (int)delay.TotalSeconds);
                await Task.Delay(delay, ct);
            }
        }
    }

    private async Task<string> SendOnceAsync(PeerClient peer, JobOptions job, FileInfo file, string hash, CancellationToken ct)
    {
        var size = file.Length;
        var init = await peer.InitAsync(new InitTransferRequest(file.Name, size, hash, job.RemoteDestination), ct);
        if (init.Status == TransferStatus.AlreadyExists)
        {
            logger.LogInformation("{File} already exists on {Peer} as {Remote}; marking as sent", file.Name, peer.Peer.Name, init.SavedAs);
            return init.SavedAs ?? file.Name;
        }
        if (init.Status != TransferStatus.Ready)
            throw new PeerException($"unexpected status '{init.Status}' from {peer.Peer.Name}", retryable: false);

        var id = init.TransferId;
        var offset = init.Offset;
        if (offset < 0 || offset > size) throw new PeerException($"invalid resume offset {offset} from {peer.Peer.Name}", retryable: false);
        if (offset > 0)
            logger.LogInformation("Resuming {File} -> {Peer} at {Offset:N0}/{Size:N0} bytes", file.Name, peer.Peer.Name, offset, size);
        else
            logger.LogInformation("Sending {File} ({Size:N0} bytes) -> {Peer}:{Destination}", file.Name, size, peer.Peer.Name, job.RemoteDestination);

        var key = keys.DeriveTransferKey(id);
        var buffer = new byte[options.Sender.ChunkSizeMB * 1024 * 1024];
        var stopwatch = Stopwatch.StartNew();
        var startOffset = offset;
        var nextProgress = 10;

        await using (var fs = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16, FileOptions.SequentialScan | FileOptions.Asynchronous))
        {
            if (fs.Length != size) throw new IOException($"{file.Name} changed size during transfer");
            while (offset < size)
            {
                fs.Position = offset;
                var toRead = (int)Math.Min(buffer.Length, size - offset);
                var read = await fs.ReadAtLeastAsync(buffer.AsMemory(0, toRead), toRead, throwOnEndOfStream: false, ct);
                if (read != toRead) throw new IOException($"{file.Name} was truncated during transfer");

                var payload = PayloadCipher.Encrypt(key, buffer.AsSpan(0, read), id, offset);
                ChunkResponse chunk;
                try
                {
                    chunk = await peer.PutChunkAsync(id, offset, payload, ct);
                }
                catch (PeerException ex) when (ex is { StatusCode: 409, ExpectedOffset: long expected } && expected <= size)
                {
                    offset = expected;
                    continue;
                }

                if (chunk.Offset <= offset || chunk.Offset > size)
                    throw new PeerException($"invalid offset {chunk.Offset} acknowledged by {peer.Peer.Name}", retryable: true);
                offset = chunk.Offset;

                var percent = size == 0 ? 100 : (int)(offset * 100 / size);
                if (percent >= nextProgress && offset < size)
                {
                    logger.LogInformation("{File} -> {Peer}: {Percent}% ({Offset:N0}/{Size:N0} bytes)", file.Name, peer.Peer.Name, percent, offset, size);
                    nextProgress = percent / 10 * 10 + 10;
                }
            }
        }

        var done = await peer.CompleteAsync(id, ct);
        var seconds = Math.Max(stopwatch.Elapsed.TotalSeconds, 0.001);
        logger.LogInformation("Sent {File} -> {Peer} as {Remote} ({Size:N0} bytes in {Seconds:0.0}s, {Speed:0.0} MB/s, sha256 {Hash})",
            file.Name, peer.Peer.Name, done.SavedAs, size, seconds, (size - startOffset) / 1048576.0 / seconds, hash);
        return done.SavedAs;
    }
}
