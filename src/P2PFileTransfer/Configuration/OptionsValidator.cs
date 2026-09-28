using System.Globalization;
using System.Text.RegularExpressions;
using P2PFileTransfer.Security;

namespace P2PFileTransfer.Configuration;

public static partial class OptionsValidator
{
    public const int MinApiKeyLength = 32;

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")]
    public static partial Regex NamePattern();

    public static List<string> Validate(P2POptions o)
    {
        var errors = new List<string>();

        if (!NamePattern().IsMatch(o.NodeName))
            errors.Add("P2P:NodeName is required and may only contain letters, digits, '.', '_' or '-' (max 64).");

        if (string.IsNullOrWhiteSpace(o.DataDirectory))
            errors.Add("P2P:DataDirectory is required.");

        // --- Security --------------------------------------------------------
        var s = o.Security;
        if (string.IsNullOrEmpty(s.ApiKey) || s.ApiKey.Length < MinApiKeyLength)
            errors.Add($"P2P:Security:ApiKey must be at least {MinApiKeyLength} characters. Generate one with --generate-key.");
        else if (s.ApiKey.StartsWith("CHANGE_ME", StringComparison.OrdinalIgnoreCase))
            errors.Add("P2P:Security:ApiKey still contains the placeholder value. Generate one with --generate-key.");
        if (s.ClockSkewSeconds is < 30 or > 3600)
            errors.Add("P2P:Security:ClockSkewSeconds must be between 30 and 3600.");
        foreach (var ip in s.AllowedIPs)
            if (!ClientIpGuard.TryParseNetwork(ip, out _))
                errors.Add($"P2P:Security:AllowedIPs contains an invalid IP/CIDR: '{ip}'.");
        if (s.MaxFailedAttempts < 1) errors.Add("P2P:Security:MaxFailedAttempts must be >= 1.");
        if (s.FailedAttemptWindowMinutes < 1) errors.Add("P2P:Security:FailedAttemptWindowMinutes must be >= 1.");
        if (s.BanMinutes < 0) errors.Add("P2P:Security:BanMinutes must be >= 0.");
        if (s.RateLimitPerMinute < 0) errors.Add("P2P:Security:RateLimitPerMinute must be >= 0.");

        // --- Peers -----------------------------------------------------------
        var peerNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in o.Peers)
        {
            if (!NamePattern().IsMatch(p.Name))
                errors.Add($"P2P:Peers: invalid peer name '{p.Name}'.");
            else if (!peerNames.Add(p.Name))
                errors.Add($"P2P:Peers: duplicate peer name '{p.Name}'.");
            else if (string.Equals(p.Name, o.NodeName, StringComparison.OrdinalIgnoreCase))
                errors.Add($"P2P:Peers: peer '{p.Name}' has the same name as this node.");

            if (!Uri.TryCreate(p.BaseUrl, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
                errors.Add($"P2P:Peers:{p.Name}: BaseUrl must be an absolute http:// or https:// URL.");
            else if (!string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.UserInfo))
                errors.Add($"P2P:Peers:{p.Name}: BaseUrl must not contain credentials or a query string.");

            if (!string.IsNullOrWhiteSpace(p.CertificateThumbprint) &&
                !Regex.IsMatch(CertificateTools.NormalizeThumbprint(p.CertificateThumbprint), "^[0-9A-F]{64}$"))
                errors.Add($"P2P:Peers:{p.Name}: CertificateThumbprint must be a SHA-256 hash (64 hex characters).");
        }

        // --- Receiver --------------------------------------------------------
        var r = o.Receiver;
        foreach (var (alias, path) in r.Destinations)
        {
            if (!NamePattern().IsMatch(alias))
                errors.Add($"P2P:Receiver:Destinations: invalid alias '{alias}'.");
            if (string.IsNullOrWhiteSpace(path))
                errors.Add($"P2P:Receiver:Destinations:{alias}: path is required.");
        }
        foreach (var ext in r.AllowedExtensions)
            if (!Regex.IsMatch(ext, @"^\.[A-Za-z0-9]{1,16}$"))
                errors.Add($"P2P:Receiver:AllowedExtensions: invalid extension '{ext}' (expected e.g. \".bak\").");
        if (r.MaxFileSizeMB < 0) errors.Add("P2P:Receiver:MaxFileSizeMB must be >= 0.");
        if (r.MaxChunkSizeMB is < 1 or > 64) errors.Add("P2P:Receiver:MaxChunkSizeMB must be between 1 and 64.");
        if (r.MinFreeDiskSpaceMB < 0) errors.Add("P2P:Receiver:MinFreeDiskSpaceMB must be >= 0.");
        if (r.IncompleteTransferExpiryHours < 1) errors.Add("P2P:Receiver:IncompleteTransferExpiryHours must be >= 1.");

        // --- Sender ----------------------------------------------------------
        var snd = o.Sender;
        if (snd.ChunkSizeMB is < 1 or > 64) errors.Add("P2P:Sender:ChunkSizeMB must be between 1 and 64.");
        if (snd.MaxRetries < 0) errors.Add("P2P:Sender:MaxRetries must be >= 0.");
        if (snd.RetryDelaySeconds < 1) errors.Add("P2P:Sender:RetryDelaySeconds must be >= 1.");
        if (snd.RequestTimeoutSeconds < 10) errors.Add("P2P:Sender:RequestTimeoutSeconds must be >= 10.");
        if (snd.MinFileAgeMinutes < 0) errors.Add("P2P:Sender:MinFileAgeMinutes must be >= 0.");
        if (snd.CatchUpMinutes < 0) errors.Add("P2P:Sender:CatchUpMinutes must be >= 0.");

        // --- Jobs ------------------------------------------------------------
        var jobNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var j in o.Jobs)
        {
            var id = $"P2P:Jobs:{j.Name}";
            if (!NamePattern().IsMatch(j.Name)) errors.Add($"P2P:Jobs: invalid job name '{j.Name}'.");
            else if (!jobNames.Add(j.Name)) errors.Add($"P2P:Jobs: duplicate job name '{j.Name}'.");
            if (string.IsNullOrWhiteSpace(j.SourceDirectory)) errors.Add($"{id}: SourceDirectory is required.");
            if (!NamePattern().IsMatch(j.RemoteDestination)) errors.Add($"{id}: RemoteDestination must be a destination alias of the receiving peer.");
            if (j.TargetPeers.Count == 0) errors.Add($"{id}: TargetPeers must contain at least one peer.");
            foreach (var tp in j.TargetPeers)
                if (o.FindPeer(tp) is null) errors.Add($"{id}: TargetPeers references unknown peer '{tp}'.");
            foreach (var pattern in j.FilePatterns)
                if (string.IsNullOrWhiteSpace(pattern) || pattern.IndexOfAny(['/', '\\']) >= 0 || pattern.Contains(".."))
                    errors.Add($"{id}: invalid file pattern '{pattern}'.");
            foreach (var t in j.Times)
                if (!TimeOnly.TryParseExact(t.Trim(), "HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out _))
                    errors.Add($"{id}: invalid time '{t}' (expected HH:mm, e.g. \"01:30\").");
            if (j.MaxFileAgeDays < 0) errors.Add($"{id}: MaxFileAgeDays must be >= 0.");
        }

        if (o.FileLog.RetentionDays < 1) errors.Add("P2P:FileLog:RetentionDays must be >= 1.");

        return errors;
    }
}
