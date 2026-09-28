using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using P2PFileTransfer.Configuration;
using P2PFileTransfer.Protocol;

namespace P2PFileTransfer.Security;

/// <summary>
/// Guards every request:
///  1. IP allow-list and temporary bans for brute-force attempts,
///  2. optional HTTPS enforcement,
///  3. HMAC-SHA256 signature over method, path, node, timestamp, nonce and body (API key never travels on the wire),
///  4. timestamp window + nonce cache against replay attacks,
///  5. optional allow-list of known peer node names,
/// and signs every authenticated response so the sender can verify it talks to a genuine peer.
/// </summary>
public sealed partial class AuthMiddleware(
    RequestDelegate next,
    P2POptions options,
    KeyMaterial keys,
    NonceCache nonces,
    ClientIpGuard guard,
    ILogger<AuthMiddleware> logger)
{
    public const string BodyItem = "p2p.body";
    public const string NodeItem = "p2p.node";

    [GeneratedRegex("^[A-Za-z0-9_-]{16,128}$")]
    private static partial Regex NoncePattern();

    private readonly long _maxBodyBytes = options.Receiver.MaxChunkSizeMB * 1024L * 1024L + PayloadCipher.Overhead + 64 * 1024;

    public async Task InvokeAsync(HttpContext ctx)
    {
        ctx.Response.OnStarting(() =>
        {
            var h = ctx.Response.Headers;
            h["X-Content-Type-Options"] = "nosniff";
            h["Cache-Control"] = "no-store";
            h["X-Frame-Options"] = "DENY";
            h["Content-Security-Policy"] = "default-src 'none'";
            h["Referrer-Policy"] = "no-referrer";
            return Task.CompletedTask;
        });

        var remote = ctx.Connection.RemoteIpAddress;
        if (remote is null)
        {
            await WriteError(ctx, StatusCodes.Status403Forbidden, "forbidden");
            return;
        }
        var ip = ClientIpGuard.Normalize(remote);

        if (!guard.IsAllowed(ip))
        {
            logger.LogWarning("Rejected request from {Ip}: address is not in AllowedIPs", ip);
            ctx.Abort();
            return;
        }

        if (guard.IsBanned(ip))
        {
            await WriteError(ctx, StatusCodes.Status403Forbidden, "forbidden");
            return;
        }

        if (!ctx.Request.Path.StartsWithSegments("/api", StringComparison.Ordinal))
        {
            guard.RecordFailure(ip, $"request to unknown path {Truncate(ctx.Request.Path.Value)}");
            await WriteError(ctx, StatusCodes.Status404NotFound, "not found");
            return;
        }

        if (options.Security.RequireHttps && !ctx.Request.IsHttps)
        {
            logger.LogWarning("Rejected plain HTTP request from {Ip} (RequireHttps is enabled)", ip);
            await WriteError(ctx, StatusCodes.Status403Forbidden, "https required");
            return;
        }

        var headers = ctx.Request.Headers;
        var node = headers[P2PHeaders.Node].ToString();
        var timestamp = headers[P2PHeaders.Timestamp].ToString();
        var nonce = headers[P2PHeaders.Nonce].ToString();
        var signature = headers[P2PHeaders.Signature].ToString();

        if (!OptionsValidator.NamePattern().IsMatch(node) || !NoncePattern().IsMatch(nonce) ||
            !long.TryParse(timestamp, NumberStyles.None, CultureInfo.InvariantCulture, out var unixSeconds) ||
            string.IsNullOrEmpty(signature))
        {
            guard.RecordFailure(ip, "missing or malformed authentication headers");
            await WriteError(ctx, StatusCodes.Status401Unauthorized, "unauthorized");
            return;
        }

        var body = await ReadBodyAsync(ctx.Request, _maxBodyBytes, ctx.RequestAborted);
        if (body is null)
        {
            await WriteError(ctx, StatusCodes.Status413PayloadTooLarge, "request body too large");
            return;
        }

        var path = ctx.Request.Path.Value ?? "";
        var expected = MessageSigner.SignRequest(keys.AuthKey, ctx.Request.Method, path, node, timestamp, nonce, body);
        if (!MessageSigner.IsValid(expected, signature))
        {
            guard.RecordFailure(ip, $"invalid signature / API key (node '{node}')");
            await WriteError(ctx, StatusCodes.Status401Unauthorized, "unauthorized");
            return;
        }

        // From here on the caller proved possession of the shared API key.
        var skew = Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - unixSeconds);
        if (skew > options.Security.ClockSkewSeconds)
        {
            logger.LogWarning("Rejected request from {Node} ({Ip}): clock difference {Skew}s exceeds {Max}s — check the time synchronisation (NTP) of both servers",
                node, ip, skew, options.Security.ClockSkewSeconds);
            await WriteError(ctx, StatusCodes.Status401Unauthorized, "request timestamp outside the allowed window (check server clocks)");
            return;
        }

        if (!nonces.TryUse(node, nonce))
        {
            guard.RecordFailure(ip, $"replayed request (node '{node}')");
            await WriteError(ctx, StatusCodes.Status401Unauthorized, "unauthorized");
            return;
        }

        if (options.Security.AcceptOnlyKnownPeers && options.FindPeer(node) is null)
        {
            logger.LogWarning("Rejected request from unknown node '{Node}' ({Ip}); add it to P2P:Peers or disable AcceptOnlyKnownPeers", node, ip);
            await WriteError(ctx, StatusCodes.Status403Forbidden, "node not allowed");
            return;
        }

        guard.RecordSuccess(ip);
        ctx.Items[BodyItem] = body;
        ctx.Items[NodeItem] = options.FindPeer(node)?.Name ?? node;

        await ExecuteAndSignAsync(ctx, nonce);
    }

    private async Task ExecuteAndSignAsync(HttpContext ctx, string requestNonce)
    {
        var originalBody = ctx.Response.Body;
        using var buffer = new MemoryStream();
        ctx.Response.Body = buffer;
        try
        {
            await next(ctx);
        }
        catch (Exception ex) when (!ctx.RequestAborted.IsCancellationRequested)
        {
            logger.LogError(ex, "Unhandled error while processing {Method} {Path}", ctx.Request.Method, ctx.Request.Path);
            buffer.SetLength(0);
            ctx.Response.StatusCode = StatusCodes.Status500InternalServerError;
            ctx.Response.ContentType = "application/json";
            await JsonSerializer.SerializeAsync(buffer, new ErrorResponse("internal error"), ProtocolJson.Options);
        }
        finally
        {
            ctx.Response.Body = originalBody;
        }

        var bytes = buffer.ToArray();
        ctx.Response.Headers[P2PHeaders.Node] = options.NodeName;
        ctx.Response.Headers[P2PHeaders.ResponseSignature] =
            MessageSigner.SignResponse(keys.AuthKey, options.NodeName, requestNonce, ctx.Response.StatusCode, bytes);
        ctx.Response.ContentLength = bytes.Length;
        await originalBody.WriteAsync(bytes, ctx.RequestAborted);
    }

    private static async Task<byte[]?> ReadBodyAsync(HttpRequest request, long maxBytes, CancellationToken ct)
    {
        if (request.ContentLength > maxBytes) return null;
        using var ms = new MemoryStream(request.ContentLength is long len && len > 0 ? (int)len : 0);
        var buffer = new byte[81920];
        int read;
        while ((read = await request.Body.ReadAsync(buffer, ct)) > 0)
        {
            if (ms.Length + read > maxBytes) return null;
            ms.Write(buffer, 0, read);
        }
        return ms.ToArray();
    }

    private static Task WriteError(HttpContext ctx, int status, string message)
    {
        ctx.Response.StatusCode = status;
        return ctx.Response.WriteAsJsonAsync(new ErrorResponse(message), ProtocolJson.Options);
    }

    private static string Truncate(string? value) =>
        value is null ? "" : value.Length <= 80 ? value : value[..80] + "...";
}

public static class AuthenticatedRequestExtensions
{
    public static byte[] GetVerifiedBody(this HttpContext ctx) =>
        ctx.Items[AuthMiddleware.BodyItem] as byte[] ?? throw new InvalidOperationException("Request was not authenticated.");

    public static string GetPeerNode(this HttpContext ctx) =>
        ctx.Items[AuthMiddleware.NodeItem] as string ?? throw new InvalidOperationException("Request was not authenticated.");
}
