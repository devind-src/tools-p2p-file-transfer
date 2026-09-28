using System.Text.RegularExpressions;

namespace P2PFileTransfer.Receiving;

/// <summary>Strict validation of incoming file names: no paths, no traversal, no reserved/device names, allowed extensions only.</summary>
public static partial class FileNameValidator
{
    [GeneratedRegex(@"^[\p{L}\p{N}_][\p{L}\p{N} _.()\[\]+=,@#&'-]*$")]
    private static partial Regex AllowedCharacters();

    private static readonly HashSet<string> ReservedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };

    public static bool TryValidate(string? fileName, IReadOnlyCollection<string> allowedExtensions, out string error)
    {
        error = "";
        if (string.IsNullOrWhiteSpace(fileName) || fileName.Length > 200)
            error = "file name is empty or too long";
        else if (fileName.IndexOfAny(['/', '\\', ':', '\0']) >= 0 || fileName.Contains("..") ||
                 fileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || !string.Equals(Path.GetFileName(fileName), fileName, StringComparison.Ordinal))
            error = "file name must not contain path characters";
        else if (fileName.EndsWith('.') || fileName.EndsWith(' '))
            error = "file name must not end with '.' or a space";
        else if (!AllowedCharacters().IsMatch(fileName))
            error = "file name contains characters that are not allowed";
        else if (ReservedNames.Contains(fileName.Split('.')[0].Trim()))
            error = "file name is a reserved device name";
        else if (allowedExtensions.Count > 0 &&
                 !allowedExtensions.Contains(Path.GetExtension(fileName), StringComparer.OrdinalIgnoreCase))
            error = $"file extension '{Path.GetExtension(fileName)}' is not allowed on the receiver";

        return error.Length == 0;
    }
}
