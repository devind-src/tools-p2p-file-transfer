namespace P2PFileTransfer.Storage;

/// <summary>Exclusive lock based on an OS file lock; works across processes (service + manual --run-job).</summary>
public sealed class FileLock : IDisposable
{
    private readonly FileStream _stream;

    private FileLock(FileStream stream) => _stream = stream;

    public static FileLock? TryAcquire(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        try
        {
            return new FileLock(new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1));
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    public static async Task<FileLock> AcquireAsync(string path, TimeSpan timeout, CancellationToken ct = default)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (true)
        {
            var fileLock = TryAcquire(path);
            if (fileLock is not null) return fileLock;
            if (DateTime.UtcNow > deadline) throw new TimeoutException($"Could not acquire lock '{path}'.");
            await Task.Delay(100, ct);
        }
    }

    public void Dispose() => _stream.Dispose();
}
