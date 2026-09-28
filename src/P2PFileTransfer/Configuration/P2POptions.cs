namespace P2PFileTransfer.Configuration;

/// <summary>Root of the "P2P" section in appsettings.json.</summary>
public sealed class P2POptions
{
    public const string SectionName = "P2P";

    /// <summary>Unique name of this node. Peers identify (and optionally whitelist) senders by this name.</summary>
    public string NodeName { get; set; } = "";

    /// <summary>Folder for history, scheduler state and lock files. Relative paths are resolved against the executable folder.</summary>
    public string DataDirectory { get; set; } = "data";

    public SecurityOptions Security { get; set; } = new();
    public ReceiverOptions Receiver { get; set; } = new();
    public SenderOptions Sender { get; set; } = new();
    public FileLogOptions FileLog { get; set; } = new();
    public List<PeerOptions> Peers { get; set; } = [];
    public List<JobOptions> Jobs { get; set; } = [];

    public PeerOptions? FindPeer(string name) =>
        Peers.FirstOrDefault(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));
}

public sealed class SecurityOptions
{
    /// <summary>Shared secret. Every node that must talk to each other uses the same value (min. 32 characters).</summary>
    public string ApiKey { get; set; } = "";

    /// <summary>Maximum allowed difference between the sender's and receiver's clock.</summary>
    public int ClockSkewSeconds { get; set; } = 300;

    /// <summary>Reject any request that did not arrive over HTTPS.</summary>
    public bool RequireHttps { get; set; }

    /// <summary>Only accept requests whose node name is listed in <see cref="P2POptions.Peers"/>.</summary>
    public bool AcceptOnlyKnownPeers { get; set; } = true;

    /// <summary>IP addresses or CIDR ranges allowed to connect. Empty = any address.</summary>
    public List<string> AllowedIPs { get; set; } = [];

    public int MaxFailedAttempts { get; set; } = 5;
    public int FailedAttemptWindowMinutes { get; set; } = 10;
    public int BanMinutes { get; set; } = 30;

    /// <summary>Maximum requests per minute per client IP (0 = unlimited).</summary>
    public int RateLimitPerMinute { get; set; } = 3000;
}

public sealed class ReceiverOptions
{
    public bool Enabled { get; set; } = true;

    /// <summary>Destination alias -> local folder. Senders can only choose an alias, never a path.</summary>
    public Dictionary<string, string> Destinations { get; set; } = [];

    /// <summary>Store incoming files in a sub folder named after the sending node.</summary>
    public bool SeparateFolderPerSender { get; set; } = true;

    /// <summary>Allowed file extensions (e.g. ".bak"). Empty = any extension.</summary>
    public List<string> AllowedExtensions { get; set; } = [];

    /// <summary>Maximum accepted file size in MB (0 = unlimited).</summary>
    public long MaxFileSizeMB { get; set; }

    public int MaxChunkSizeMB { get; set; } = 16;
    public long MinFreeDiskSpaceMB { get; set; } = 1024;

    /// <summary>When false an existing file with the same name is kept and the new one gets a timestamp suffix.</summary>
    public bool OverwriteExisting { get; set; }

    public int IncompleteTransferExpiryHours { get; set; } = 48;
}

public sealed class SenderOptions
{
    public int ChunkSizeMB { get; set; } = 4;
    public int MaxRetries { get; set; } = 5;
    public int RetryDelaySeconds { get; set; } = 30;
    public int RequestTimeoutSeconds { get; set; } = 600;

    /// <summary>Files modified more recently than this are considered still being written and are skipped.</summary>
    public int MinFileAgeMinutes { get; set; } = 5;

    /// <summary>A scheduled run that was missed (service down) is still executed if at most this many minutes late.</summary>
    public int CatchUpMinutes { get; set; } = 120;
}

public sealed class PeerOptions
{
    public string Name { get; set; } = "";
    public string BaseUrl { get; set; } = "";

    /// <summary>Optional SHA-256 thumbprint of the peer's TLS certificate (certificate pinning, allows self-signed certs).</summary>
    public string CertificateThumbprint { get; set; } = "";

    /// <summary>Accept any TLS certificate. Not recommended — use <see cref="CertificateThumbprint"/> instead.</summary>
    public bool AllowInvalidCertificate { get; set; }
}

public sealed class JobOptions
{
    public string Name { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public string SourceDirectory { get; set; } = "";
    public List<string> FilePatterns { get; set; } = [];
    public bool IncludeSubdirectories { get; set; }
    public List<string> TargetPeers { get; set; } = [];

    /// <summary>Destination alias configured in the receiving peer's Receiver.Destinations.</summary>
    public string RemoteDestination { get; set; } = "";

    /// <summary>Local times of day ("HH:mm") at which the job runs.</summary>
    public List<string> Times { get; set; } = [];

    /// <summary>Days of the week on which the job runs. Empty = every day.</summary>
    public List<DayOfWeek> Days { get; set; } = [];

    /// <summary>Only send files modified within the last N days (0 = no limit).</summary>
    public int MaxFileAgeDays { get; set; }

    public IReadOnlyList<TimeOnly> ParsedTimes() =>
        Times.Select(t => TimeOnly.ParseExact(t.Trim(), "HH:mm", System.Globalization.CultureInfo.InvariantCulture))
             .Distinct().OrderBy(t => t).ToList();
}

public sealed class FileLogOptions
{
    public bool Enabled { get; set; } = true;
    public string Directory { get; set; } = "logs";
    public int RetentionDays { get; set; } = 30;
}
