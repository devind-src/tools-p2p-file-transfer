using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using P2PFileTransfer.Configuration;
using P2PFileTransfer.Protocol;
using P2PFileTransfer.Security;
using P2PFileTransfer.Storage;

namespace P2PFileTransfer.Receiving;

/// <summary>
/// Receives files in encrypted chunks into "&lt;destination&gt;/.incoming/&lt;id&gt;.part" (resumable),
/// verifies the SHA-256 checksum and then atomically moves the file to its final location.
/// </summary>
public sealed partial class TransferReceiver(
    P2POptions options,
    KeyMaterial keys,
    ReceivedLog receivedLog,
    ILogger<TransferReceiver> logger)
{
    public const string StagingFolderName = ".incoming";

    [GeneratedRegex("^[a-f0-9]{32}$")]
    private static partial Regex IdPattern();

    [GeneratedRegex("^[a-fA-F0-9]{64}$")]
    private static partial Regex Sha256Pattern();

    private readonly ConcurrentDictionary<string, TransferState> _states = new(StringComparer.Ordinal);
    private ReceiverOptions R => options.Receiver;

    private sealed class TransferState
    {
        public SemaphoreSlim Lock { get; } = new(1, 1);
        public IncrementalHash? Hasher { get; set; }
        public long HashedLength { get; set; }
        public DateTime LastActivityUtc { get; set; } = DateTime.UtcNow;

        public void ResetHasher(bool start)
        {
            Hasher?.Dispose();
            Hasher = start ? IncrementalHash.CreateHash(HashAlgorithmName.SHA256) : null;
            HashedLength = 0;
        }
    }

    private sealed record TransferMeta(string Id, string Sender, string Destination, string FileName, long Size, string Sha256, DateTimeOffset CreatedUtc);

    private sealed record Located(TransferMeta Meta, string DestinationRoot, string StagingDir)
    {
        public string PartPath => Path.Combine(StagingDir, Meta.Id + ".part");
        public string MetaPath => Path.Combine(StagingDir, Meta.Id + ".json");
    }

    // ------------------------------------------------------------------------------------------
    // POST /api/v1/transfers
    // ------------------------------------------------------------------------------------------
    public async Task<IResult> InitAsync(HttpContext ctx, CancellationToken ct)
    {
        if (!R.Enabled) return Error(StatusCodes.Status403Forbidden, "receiving is disabled on this node");
        var sender = ctx.GetPeerNode();

        InitTransferRequest? req;
        try { req = JsonSerializer.Deserialize<InitTransferRequest>(ctx.GetVerifiedBody(), ProtocolJson.Options); }
        catch (JsonException) { req = null; }
        if (req is null) return Error(StatusCodes.Status400BadRequest, "invalid request body");

        if (!TryGetDestination(req.Destination, out var destName, out var destRoot))
            return Error(StatusCodes.Status400BadRequest, $"unknown destination '{req.Destination}'");
        if (!FileNameValidator.TryValidate(req.FileName, R.AllowedExtensions, out var nameError))
        {
            logger.LogWarning("Rejected file '{File}' from {Sender}: {Error}", req.FileName, sender, nameError);
            return Error(StatusCodes.Status400BadRequest, nameError);
        }
        if (req.Size < 0) return Error(StatusCodes.Status400BadRequest, "invalid size");
        if (R.MaxFileSizeMB > 0 && req.Size > R.MaxFileSizeMB * 1024L * 1024L)
            return Error(StatusCodes.Status413PayloadTooLarge, $"file exceeds the receiver limit of {R.MaxFileSizeMB} MB");
        if (req.Sha256 is null || !Sha256Pattern().IsMatch(req.Sha256))
            return Error(StatusCodes.Status400BadRequest, "invalid sha256");
        var sha = req.Sha256.ToLowerInvariant();

        // Already received earlier (e.g. the sender lost its history)?
        var previous = await receivedLog.FindAsync(sender, destName, req.FileName, sha, ct);
        if (previous is not null && File.Exists(previous.SavedPath) && new FileInfo(previous.SavedPath).Length == req.Size)
        {
            logger.LogInformation("File {File} from {Sender} was already received as {Saved}; skipping", req.FileName, sender, previous.SavedPath);
            return Results.Ok(new InitTransferResponse("", TransferStatus.AlreadyExists, req.Size, Path.GetFileName(previous.SavedPath)));
        }

        var id = ComputeTransferId(sender, destName, req.FileName, req.Size, sha);
        var staging = Path.Combine(destRoot, StagingFolderName);
        Directory.CreateDirectory(staging);
        TryHide(staging);
        var located = new Located(new TransferMeta(id, sender, destName, req.FileName, req.Size, sha, DateTimeOffset.UtcNow), destRoot, staging);

        var state = _states.GetOrAdd(id, _ => new TransferState());
        await state.Lock.WaitAsync(ct);
        try
        {
            if (!File.Exists(located.MetaPath))
            {
                if (File.Exists(located.PartPath)) File.Delete(located.PartPath);
                await File.WriteAllBytesAsync(located.MetaPath, JsonSerializer.SerializeToUtf8Bytes(located.Meta, ProtocolJson.Options), ct);
            }

            long offset = File.Exists(located.PartPath) ? new FileInfo(located.PartPath).Length : 0;
            if (offset > req.Size)
            {
                File.Delete(located.PartPath);
                offset = 0;
            }

            var free = PathHelper.GetAvailableFreeSpace(staging);
            var needed = req.Size - offset + R.MinFreeDiskSpaceMB * 1024L * 1024L;
            if (free >= 0 && free < needed)
            {
                logger.LogError("Not enough disk space for {File} from {Sender}: {Free:N0} bytes free, {Needed:N0} required", req.FileName, sender, free, needed);
                return Error(StatusCodes.Status507InsufficientStorage, "insufficient disk space on receiver");
            }

            if (offset == 0) state.ResetHasher(start: true);
            else if (state.Hasher is null || state.HashedLength != offset) state.ResetHasher(start: false);
            state.LastActivityUtc = DateTime.UtcNow;

            if (offset > 0)
                logger.LogInformation("Resuming transfer {Id}: {File} from {Sender} at {Offset:N0}/{Size:N0} bytes", id, req.FileName, sender, offset, req.Size);
            else
                logger.LogInformation("Starting transfer {Id}: {File} ({Size:N0} bytes) from {Sender} -> {Destination}", id, req.FileName, req.Size, sender, destName);

            return Results.Ok(new InitTransferResponse(id, TransferStatus.Ready, offset, null));
        }
        finally
        {
            state.Lock.Release();
        }
    }

    // ------------------------------------------------------------------------------------------
    // PUT /api/v1/transfers/{id}/chunks/{offset}
    // ------------------------------------------------------------------------------------------
    public async Task<IResult> ChunkAsync(HttpContext ctx, string id, long offset, CancellationToken ct)
    {
        if (!R.Enabled) return Error(StatusCodes.Status403Forbidden, "receiving is disabled on this node");
        if (!IdPattern().IsMatch(id) || offset < 0) return Error(StatusCodes.Status400BadRequest, "invalid transfer id or offset");

        var located = FindTransfer(id);
        if (located is null) return Error(StatusCodes.Status404NotFound, "unknown transfer");
        var sender = ctx.GetPeerNode();
        if (!string.Equals(located.Meta.Sender, sender, StringComparison.OrdinalIgnoreCase))
            return Error(StatusCodes.Status403Forbidden, "transfer belongs to another node");

        var state = _states.GetOrAdd(id, _ => new TransferState());
        await state.Lock.WaitAsync(ct);
        try
        {
            var current = File.Exists(located.PartPath) ? new FileInfo(located.PartPath).Length : 0;
            if (offset > current) return Error(StatusCodes.Status409Conflict, "offset mismatch", current);

            byte[] plain;
            try
            {
                plain = PayloadCipher.Decrypt(keys.DeriveTransferKey(id), ctx.GetVerifiedBody(), id, offset);
            }
            catch (CryptographicException)
            {
                logger.LogWarning("Chunk for transfer {Id} from {Sender} failed decryption/integrity check", id, sender);
                return Error(StatusCodes.Status400BadRequest, "chunk failed decryption or integrity check");
            }

            if (plain.Length == 0 || offset + plain.Length > located.Meta.Size)
                return Error(StatusCodes.Status400BadRequest, "chunk exceeds the declared file size");

            await using (var fs = new FileStream(located.PartPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.None, 1, FileOptions.Asynchronous))
            {
                if (offset < current) fs.SetLength(offset);
                fs.Position = offset;
                await fs.WriteAsync(plain, ct);
                await fs.FlushAsync(ct);
            }

            if (state.Hasher is not null && state.HashedLength == offset)
            {
                state.Hasher.AppendData(plain);
                state.HashedLength += plain.Length;
            }
            else
            {
                state.ResetHasher(start: false);
            }
            state.LastActivityUtc = DateTime.UtcNow;

            return Results.Ok(new ChunkResponse(offset + plain.Length));
        }
        finally
        {
            state.Lock.Release();
        }
    }

    // ------------------------------------------------------------------------------------------
    // POST /api/v1/transfers/{id}/complete
    // ------------------------------------------------------------------------------------------
    public async Task<IResult> CompleteAsync(HttpContext ctx, string id, CancellationToken ct)
    {
        if (!R.Enabled) return Error(StatusCodes.Status403Forbidden, "receiving is disabled on this node");
        if (!IdPattern().IsMatch(id)) return Error(StatusCodes.Status400BadRequest, "invalid transfer id");

        var located = FindTransfer(id);
        if (located is null) return Error(StatusCodes.Status404NotFound, "unknown transfer");
        var sender = ctx.GetPeerNode();
        var meta = located.Meta;
        if (!string.Equals(meta.Sender, sender, StringComparison.OrdinalIgnoreCase))
            return Error(StatusCodes.Status403Forbidden, "transfer belongs to another node");

        var state = _states.GetOrAdd(id, _ => new TransferState());
        await state.Lock.WaitAsync(ct);
        var finished = false;
        try
        {
            if (!File.Exists(located.PartPath))
            {
                if (meta.Size != 0) return Error(StatusCodes.Status409Conflict, "no data received", 0);
                await File.WriteAllBytesAsync(located.PartPath, [], ct);
            }

            var length = new FileInfo(located.PartPath).Length;
            if (length != meta.Size) return Error(StatusCodes.Status409Conflict, "transfer incomplete", length);

            string actual;
            if (state.Hasher is not null && state.HashedLength == meta.Size)
            {
                actual = Convert.ToHexStringLower(state.Hasher.GetHashAndReset());
            }
            else
            {
                await using var fs = new FileStream(located.PartPath, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan | FileOptions.Asynchronous);
                actual = Convert.ToHexStringLower(await SHA256.HashDataAsync(fs, ct));
            }
            state.ResetHasher(start: false);

            if (!string.Equals(actual, meta.Sha256, StringComparison.Ordinal))
            {
                DeleteQuietly(located.PartPath);
                DeleteQuietly(located.MetaPath);
                finished = true;
                logger.LogError("Checksum mismatch for {File} from {Sender} (expected {Expected}, got {Actual}); transfer discarded", meta.FileName, sender, meta.Sha256, actual);
                return Error(StatusCodes.Status422UnprocessableEntity, "checksum mismatch; transfer discarded");
            }

            var targetDir = GetTargetDirectory(located.DestinationRoot, meta.Sender);
            Directory.CreateDirectory(targetDir);
            var finalPath = ResolveFinalPath(targetDir, meta.FileName);
            if (!PathHelper.IsInside(finalPath, located.DestinationRoot))
                return Error(StatusCodes.Status400BadRequest, "invalid target path");

            File.Move(located.PartPath, finalPath, overwrite: R.OverwriteExisting);
            DeleteQuietly(located.MetaPath);
            finished = true;

            await receivedLog.AddAsync(new ReceivedRecord(DateTimeOffset.UtcNow, meta.Sender, meta.Destination, meta.FileName, finalPath,
                meta.Size, meta.Sha256, ctx.Connection.RemoteIpAddress?.ToString()), CancellationToken.None);

            logger.LogInformation("Received {File} ({Size:N0} bytes, sha256 {Sha}) from {Sender} -> {Path}", meta.FileName, meta.Size, meta.Sha256, meta.Sender, finalPath);
            return Results.Ok(new CompleteResponse(TransferStatus.Completed, Path.GetFileName(finalPath)));
        }
        finally
        {
            state.Lock.Release();
            if (finished) _states.TryRemove(id, out _);
        }
    }

    /// <summary>Deletes incomplete transfers that have not been touched for IncompleteTransferExpiryHours.</summary>
    public int CleanupExpired()
    {
        var cutoff = DateTime.UtcNow.AddHours(-R.IncompleteTransferExpiryHours);
        var removed = 0;
        foreach (var (_, root) in ResolvedDestinations())
        {
            var staging = Path.Combine(root, StagingFolderName);
            if (!Directory.Exists(staging)) continue;
            foreach (var metaFile in Directory.EnumerateFiles(staging, "*.json"))
            {
                var id = Path.GetFileNameWithoutExtension(metaFile);
                var part = Path.Combine(staging, id + ".part");
                var last = File.GetLastWriteTimeUtc(metaFile);
                if (File.Exists(part) && File.GetLastWriteTimeUtc(part) > last) last = File.GetLastWriteTimeUtc(part);
                if (last >= cutoff) continue;
                if (_states.TryGetValue(id, out var st) && st.Lock.CurrentCount == 0) continue;

                DeleteQuietly(part);
                DeleteQuietly(metaFile);
                _states.TryRemove(id, out _);
                removed++;
                logger.LogInformation("Removed expired incomplete transfer {Id}", id);
            }
        }

        foreach (var (id, st) in _states)
            if (st.LastActivityUtc < cutoff && st.Lock.CurrentCount == 1)
                _states.TryRemove(id, out _);

        return removed;
    }

    // ------------------------------------------------------------------------------------------

    private IEnumerable<(string Name, string Root)> ResolvedDestinations() =>
        R.Destinations.Select(d => (d.Key, PathHelper.Resolve(d.Value)));

    private bool TryGetDestination(string? alias, out string name, out string root)
    {
        foreach (var (n, r) in ResolvedDestinations())
        {
            if (string.Equals(n, alias, StringComparison.OrdinalIgnoreCase))
            {
                name = n;
                root = r;
                return true;
            }
        }
        name = root = "";
        return false;
    }

    private Located? FindTransfer(string id)
    {
        foreach (var (name, root) in ResolvedDestinations())
        {
            var staging = Path.Combine(root, StagingFolderName);
            var metaPath = Path.Combine(staging, id + ".json");
            if (!File.Exists(metaPath)) continue;
            try
            {
                var meta = JsonSerializer.Deserialize<TransferMeta>(File.ReadAllBytes(metaPath), ProtocolJson.Options);
                if (meta is not null && meta.Id == id && string.Equals(meta.Destination, name, StringComparison.OrdinalIgnoreCase))
                    return new Located(meta, root, staging);
            }
            catch (Exception ex) when (ex is JsonException or IOException)
            {
                logger.LogWarning(ex, "Could not read transfer metadata {Path}", metaPath);
            }
        }
        return null;
    }

    private string GetTargetDirectory(string destinationRoot, string sender) =>
        R.SeparateFolderPerSender ? Path.Combine(destinationRoot, sender) : destinationRoot;

    private string ResolveFinalPath(string directory, string fileName)
    {
        var candidate = Path.Combine(directory, fileName);
        if (R.OverwriteExisting || !File.Exists(candidate)) return candidate;

        var name = Path.GetFileNameWithoutExtension(fileName);
        var ext = Path.GetExtension(fileName);
        var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss", System.Globalization.CultureInfo.InvariantCulture);
        for (var i = 0; ; i++)
        {
            candidate = Path.Combine(directory, i == 0 ? $"{name}_{stamp}{ext}" : $"{name}_{stamp}_{i}{ext}");
            if (!File.Exists(candidate)) return candidate;
        }
    }

    private static string ComputeTransferId(string sender, string destination, string fileName, long size, string sha) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"{sender.ToUpperInvariant()}|{destination.ToUpperInvariant()}|{fileName}|{size}|{sha}")))[..32];

    private static IResult Error(int status, string message, long? expectedOffset = null) =>
        Results.Json(new ErrorResponse(message, expectedOffset), ProtocolJson.Options, statusCode: status);

    private static void DeleteQuietly(string path)
    {
        try { File.Delete(path); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private static void TryHide(string directory)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            var info = new DirectoryInfo(directory);
            if (!info.Attributes.HasFlag(FileAttributes.Hidden)) info.Attributes |= FileAttributes.Hidden;
        }
        catch (Exception) { /* cosmetic only */ }
    }
}
