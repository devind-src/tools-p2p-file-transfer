using System.Security.Cryptography;
using System.Text;

namespace P2PFileTransfer.Security;

/// <summary>
/// HMAC-SHA256 signatures over a canonical representation of each request and response.
/// Requests bind method, path, node, timestamp, nonce and a hash of the body; responses bind
/// the request nonce so they cannot be replayed or forged by a man in the middle.
/// </summary>
public static class MessageSigner
{
    public static string SignRequest(byte[] key, string method, string path, string node, string timestamp, string nonce, ReadOnlySpan<byte> body)
    {
        var canonical = string.Join('\n',
            "P2P-HMAC-SHA256-REQUEST",
            method.ToUpperInvariant(),
            path,
            node,
            timestamp,
            nonce,
            Convert.ToHexStringLower(SHA256.HashData(body)));
        return Sign(key, canonical);
    }

    public static string SignResponse(byte[] key, string node, string requestNonce, int statusCode, ReadOnlySpan<byte> body)
    {
        var canonical = string.Join('\n',
            "P2P-HMAC-SHA256-RESPONSE",
            node,
            requestNonce,
            statusCode.ToString(System.Globalization.CultureInfo.InvariantCulture),
            Convert.ToHexStringLower(SHA256.HashData(body)));
        return Sign(key, canonical);
    }

    /// <summary>Constant-time comparison of two base64 signatures.</summary>
    public static bool IsValid(string expected, string? provided)
    {
        if (string.IsNullOrEmpty(provided) || provided.Length > 128) return false;
        Span<byte> actual = stackalloc byte[96];
        if (!Convert.TryFromBase64String(provided, actual, out var written)) return false;
        var expectedBytes = Convert.FromBase64String(expected);
        return CryptographicOperations.FixedTimeEquals(expectedBytes, actual[..written]);
    }

    public static string NewNonce() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(18)).Replace('+', '-').Replace('/', '_');

    private static string Sign(byte[] key, string canonical) =>
        Convert.ToBase64String(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(canonical)));
}
