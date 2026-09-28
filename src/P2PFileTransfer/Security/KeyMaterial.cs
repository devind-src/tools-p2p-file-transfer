using System.Security.Cryptography;
using System.Text;
using P2PFileTransfer.Configuration;

namespace P2PFileTransfer.Security;

/// <summary>
/// Derives independent keys from the shared API key with HKDF-SHA256:
/// one for request/response signatures (HMAC) and one for payload encryption (AES-256-GCM).
/// The API key itself is never sent over the network.
/// </summary>
public sealed class KeyMaterial
{
    private static readonly byte[] Salt = "tools-p2p/file-transfer/v1"u8.ToArray();

    public byte[] AuthKey { get; }
    private readonly byte[] _encryptionKey;

    public KeyMaterial(P2POptions options) : this(options.Security.ApiKey) { }

    public KeyMaterial(string apiKey)
    {
        var ikm = Encoding.UTF8.GetBytes(apiKey);
        AuthKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 32, Salt, "hmac-authentication"u8.ToArray());
        _encryptionKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 32, Salt, "payload-encryption"u8.ToArray());
        CryptographicOperations.ZeroMemory(ikm);
    }

    /// <summary>Per-transfer encryption key, so each file is encrypted under its own key.</summary>
    public byte[] DeriveTransferKey(string transferId) =>
        HKDF.Expand(HashAlgorithmName.SHA256, _encryptionKey, 32, Encoding.UTF8.GetBytes("transfer:" + transferId));
}
