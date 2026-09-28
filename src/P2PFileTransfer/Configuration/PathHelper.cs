namespace P2PFileTransfer.Configuration;

public static class PathHelper
{
    /// <summary>Comparison that matches the file system's case sensitivity (Windows = ignore case).</summary>
    public static readonly StringComparison PathComparison =
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    public static readonly StringComparer PathComparer =
        OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    /// <summary>Resolves relative paths against the executable folder (services often start with a different working directory).</summary>
    public static string Resolve(string path)
    {
        var expanded = Environment.ExpandEnvironmentVariables(path);
        return Path.GetFullPath(Path.IsPathRooted(expanded) ? expanded : Path.Combine(AppContext.BaseDirectory, expanded));
    }

    /// <summary>True when <paramref name="candidate"/> is located inside <paramref name="directory"/>.</summary>
    public static bool IsInside(string candidate, string directory)
    {
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory)) + Path.DirectorySeparatorChar;
        return Path.GetFullPath(candidate).StartsWith(root, PathComparison);
    }

    /// <summary>Free space of the volume that contains <paramref name="path"/>, or -1 if unknown.</summary>
    public static long GetAvailableFreeSpace(string path)
    {
        var full = Path.GetFullPath(path);
        DriveInfo? best = null;
        var bestLength = -1;
        foreach (var drive in DriveInfo.GetDrives())
        {
            try
            {
                if (!drive.IsReady) continue;
                var root = drive.RootDirectory.FullName;
                var prefix = Path.EndsInDirectorySeparator(root) ? root : root + Path.DirectorySeparatorChar;
                var matches = string.Equals(full, root, PathComparison) ||
                              string.Equals(full + Path.DirectorySeparatorChar, prefix, PathComparison) ||
                              full.StartsWith(prefix, PathComparison);
                if (matches && root.Length > bestLength)
                {
                    best = drive;
                    bestLength = root.Length;
                }
            }
            catch (Exception) { /* inaccessible pseudo file systems */ }
        }

        try { return best?.AvailableFreeSpace ?? -1; }
        catch (Exception) { return -1; }
    }
}
