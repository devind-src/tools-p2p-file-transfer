using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace P2PFileTransfer.Protocol;

public static class P2PHeaders
{
    public const string Node = "X-P2P-Node";
    public const string Timestamp = "X-P2P-Timestamp";
    public const string Nonce = "X-P2P-Nonce";
    public const string Signature = "X-P2P-Signature";
    public const string ResponseSignature = "X-P2P-Response-Signature";
}

public static class P2PRoutes
{
    public const string Ping = "/api/v1/ping";
    public const string Transfers = "/api/v1/transfers";
    public static string Chunk(string id, long offset) => $"{Transfers}/{id}/chunks/{offset}";
    public static string Complete(string id) => $"{Transfers}/{id}/complete";
}

public static class TransferStatus
{
    public const string Ready = "Ready";
    public const string AlreadyExists = "AlreadyExists";
    public const string Completed = "Completed";
}

public sealed record PingResponse(string Node, DateTimeOffset TimeUtc, string Version);

public sealed record InitTransferRequest(string FileName, long Size, string Sha256, string Destination);

public sealed record InitTransferResponse(string TransferId, string Status, long Offset, string? SavedAs);

public sealed record ChunkResponse(long Offset);

public sealed record CompleteResponse(string Status, string SavedAs);

public sealed record ErrorResponse(
    string Error,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] long? ExpectedOffset = null);

public static class ProtocolJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);
}

public static class AppInfo
{
    public static string Version { get; } =
        typeof(AppInfo).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0]
        ?? typeof(AppInfo).Assembly.GetName().Version?.ToString() ?? "0.0.0";
}
