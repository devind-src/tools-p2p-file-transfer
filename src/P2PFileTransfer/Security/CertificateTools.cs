using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace P2PFileTransfer.Security;

public static class CertificateTools
{
    public static string NormalizeThumbprint(string value) =>
        new string(value.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();

    public static string Sha256Thumbprint(X509Certificate certificate) =>
        certificate.GetCertHashString(HashAlgorithmName.SHA256).ToUpperInvariant();

    /// <summary>Creates a self-signed TLS server certificate (RSA 3072, SHA-256) and exports it as a password-protected PFX.</summary>
    public static X509Certificate2 CreateSelfSigned(string commonName, IEnumerable<string> dnsNames, IEnumerable<IPAddress> ips, int years)
    {
        using var rsa = RSA.Create(3072);
        var request = new CertificateRequest($"CN={commonName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(commonName);
        foreach (var dns in dnsNames.Where(d => !string.Equals(d, commonName, StringComparison.OrdinalIgnoreCase))) san.AddDnsName(dns);
        foreach (var ip in ips) san.AddIpAddress(ip);
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        var now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddDays(-1), now.AddYears(years));
    }

    public static X509Certificate2 Load(string path, string? password) =>
        Path.GetExtension(path).ToLowerInvariant() is ".pfx" or ".p12"
            ? X509CertificateLoader.LoadPkcs12FromFile(path, password)
            : X509CertificateLoader.LoadCertificateFromFile(path);
}
