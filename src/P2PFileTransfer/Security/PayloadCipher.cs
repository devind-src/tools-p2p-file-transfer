using System.Security.Cryptography;
using System.Text;

namespace P2PFileTransfer.Security;

/// <summary>
/// AES-256-GCM encryption for file chunks. Layout: nonce(12) | ciphertext | tag(16).
/// The transfer id and offset are bound as associated data, so chunks cannot be reordered or moved between transfers.
/// File content is therefore confidential and tamper-proof even over plain HTTP.
/// </summary>
public static class PayloadCipher
{
    private const int NonceSize = 12;
    private const int TagSize = 16;
    public const int Overhead = NonceSize + TagSize;

    public static byte[] Encrypt(byte[] key, ReadOnlySpan<byte> plaintext, string transferId, long offset)
    {
        var output = new byte[Overhead + plaintext.Length];
        var nonce = output.AsSpan(0, NonceSize);
        RandomNumberGenerator.Fill(nonce);
        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, output.AsSpan(NonceSize, plaintext.Length), output.AsSpan(NonceSize + plaintext.Length, TagSize), Aad(transferId, offset));
        return output;
    }

    /// <exception cref="CryptographicException">Data was tampered with or encrypted with another key.</exception>
    public static byte[] Decrypt(byte[] key, ReadOnlySpan<byte> data, string transferId, long offset)
    {
        if (data.Length < Overhead) throw new CryptographicException("Encrypted chunk is too short.");
        var plaintext = new byte[data.Length - Overhead];
        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(data[..NonceSize], data.Slice(NonceSize, plaintext.Length), data[^TagSize..], plaintext, Aad(transferId, offset));
        return plaintext;
    }

    private static byte[] Aad(string transferId, long offset) =>
        Encoding.UTF8.GetBytes($"p2p-chunk|{transferId}|{offset.ToString(System.Globalization.CultureInfo.InvariantCulture)}");
}
