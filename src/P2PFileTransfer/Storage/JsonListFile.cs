using System.Text.Json;

namespace P2PFileTransfer.Storage;

/// <summary>A JSON array persisted on disk with atomic writes (write temp file, then rename) and a cross-process lock.</summary>
public sealed class JsonListFile<T>(string path)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private readonly SemaphoreSlim _gate = new(1, 1);

    public string FilePath { get; } = path;

    public Task<List<T>> ReadAsync(CancellationToken ct = default) => Task.FromResult(Load());

    public async Task UpdateAsync(Func<List<T>, bool> mutate, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            using var fileLock = await FileLock.AcquireAsync(FilePath + ".lock", TimeSpan.FromSeconds(60), ct);
            var list = Load();
            if (mutate(list)) Save(list);
        }
        finally
        {
            _gate.Release();
        }
    }

    private List<T> Load()
    {
        if (!File.Exists(FilePath)) return [];
        var bytes = File.ReadAllBytes(FilePath);
        if (bytes.Length == 0) return [];
        try
        {
            return JsonSerializer.Deserialize<List<T>>(bytes, Json) ?? [];
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"History file '{FilePath}' is corrupt: {ex.Message}", ex);
        }
    }

    private void Save(List<T> list)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        var tmp = FilePath + ".tmp";
        using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            JsonSerializer.Serialize(fs, list, Json);
            fs.Flush(true);
        }
        File.Move(tmp, FilePath, overwrite: true);
    }
}
