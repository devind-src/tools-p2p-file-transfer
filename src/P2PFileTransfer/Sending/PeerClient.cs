using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;
using System.Text.Json;
using P2PFileTransfer.Configuration;
using P2PFileTransfer.Protocol;
using P2PFileTransfer.Security;

namespace P2PFileTransfer.Sending;

public sealed class PeerException(string message, int statusCode = 0, long? expectedOffset = null, bool retryable = true, Exception? inner = null)
    : Exception(message, inner)
{
    public int StatusCode { get; } = statusCode;
    public long? ExpectedOffset { get; } = expectedOffset;
    public bool Retryable { get; } = retryable;
}

/// <summary>Signed HTTP client for one peer. Verifies the signature of every response.</summary>
public sealed class PeerClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly Uri _baseUri;
    private readonly P2POptions _options;
    private readonly KeyMaterial _keys;
    private readonly ILogger _logger;

    public PeerOptions Peer { get; }

    public PeerClient(PeerOptions peer, P2POptions options, KeyMaterial keys, ILogger logger)
    {
        Peer = peer;
        _options = options;
        _keys = keys;
        _logger = logger;
        _baseUri = new Uri(peer.BaseUrl.EndsWith('/') ? peer.BaseUrl : peer.BaseUrl + "/");

        var pin = CertificateTools.NormalizeThumbprint(peer.CertificateThumbprint);
        var handler = new SocketsHttpHandler
        {
            ConnectTimeout = TimeSpan.FromSeconds(30),
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                RemoteCertificateValidationCallback = (_, cert, _, errors) =>
                {
                    if (pin.Length > 0)
                    {
                        var ok = cert is not null && string.Equals(CertificateTools.Sha256Thumbprint(cert), pin, StringComparison.Ordinal);
                        if (!ok) _logger.LogError("TLS certificate of peer {Peer} does not match the pinned thumbprint", peer.Name);
                        return ok;
                    }
                    if (errors == SslPolicyErrors.None) return true;
                    if (peer.AllowInvalidCertificate)
                    {
                        _logger.LogWarning("Accepting invalid TLS certificate of peer {Peer} ({Errors}) because AllowInvalidCertificate is enabled", peer.Name, errors);
                        return true;
                    }
                    _logger.LogError("TLS certificate of peer {Peer} is not trusted ({Errors}); set CertificateThumbprint to pin a self-signed certificate", peer.Name, errors);
                    return false;
                },
            },
        };
        _http = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(options.Sender.RequestTimeoutSeconds),
            MaxResponseContentBufferSize = 1024 * 1024,
        };
        _http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("P2PFileTransfer", AppInfo.Version));
    }

    public bool IsHttps => _baseUri.Scheme == Uri.UriSchemeHttps;

    public Task<PingResponse> PingAsync(CancellationToken ct) =>
        SendAsync<PingResponse>(HttpMethod.Get, P2PRoutes.Ping, null, null, ct);

    public Task<InitTransferResponse> InitAsync(InitTransferRequest request, CancellationToken ct) =>
        SendAsync<InitTransferResponse>(HttpMethod.Post, P2PRoutes.Transfers,
            JsonSerializer.SerializeToUtf8Bytes(request, ProtocolJson.Options), "application/json", ct);

    public Task<ChunkResponse> PutChunkAsync(string transferId, long offset, byte[] encrypted, CancellationToken ct) =>
        SendAsync<ChunkResponse>(HttpMethod.Put, P2PRoutes.Chunk(transferId, offset), encrypted, "application/octet-stream", ct);

    public Task<CompleteResponse> CompleteAsync(string transferId, CancellationToken ct) =>
        SendAsync<CompleteResponse>(HttpMethod.Post, P2PRoutes.Complete(transferId), null, null, ct);

    private async Task<T> SendAsync<T>(HttpMethod method, string path, byte[]? body, string? contentType, CancellationToken ct)
    {
        body ??= [];
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        var nonce = MessageSigner.NewNonce();
        var signature = MessageSigner.SignRequest(_keys.AuthKey, method.Method, path, _options.NodeName, timestamp, nonce, body);

        // Paths are always relative to BaseUrl (supports a reverse-proxy prefix such as https://host/p2p/).
        using var request = new HttpRequestMessage(method, new Uri(_baseUri, path.TrimStart('/')));
        request.Headers.Add(P2PHeaders.Node, _options.NodeName);
        request.Headers.Add(P2PHeaders.Timestamp, timestamp);
        request.Headers.Add(P2PHeaders.Nonce, nonce);
        request.Headers.Add(P2PHeaders.Signature, signature);
        if (body.Length > 0 || method != HttpMethod.Get)
        {
            request.Content = new ByteArrayContent(body);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue(contentType ?? "application/octet-stream");
        }

        HttpResponseMessage response;
        try
        {
            response = await _http.SendAsync(request, HttpCompletionOption.ResponseContentRead, ct);
        }
        catch (HttpRequestException ex)
        {
            throw new PeerException($"connection to {Peer.Name} ({_baseUri}) failed: {ex.Message}", inner: ex);
        }
        catch (TaskCanceledException ex) when (!ct.IsCancellationRequested)
        {
            throw new PeerException($"request to {Peer.Name} timed out after {_http.Timeout.TotalSeconds:0}s", inner: ex);
        }

        using (response)
        {
            var bytes = await response.Content.ReadAsByteArrayAsync(ct);
            var status = (int)response.StatusCode;
            var responseSignature = response.Headers.TryGetValues(P2PHeaders.ResponseSignature, out var sv) ? sv.FirstOrDefault() : null;
            var responder = response.Headers.TryGetValues(P2PHeaders.Node, out var nv) ? nv.FirstOrDefault() ?? "" : "";

            if (responseSignature is null)
            {
                // Requests rejected by the peer's authentication layer are not signed.
                var message = TryReadError(bytes)?.Error ?? response.ReasonPhrase ?? "no response signature";
                var retryable = status is 0 or >= 500 or 408 or 429;
                throw new PeerException($"{Peer.Name} rejected the request: HTTP {status} {message}", status, retryable: retryable);
            }

            var expected = MessageSigner.SignResponse(_keys.AuthKey, responder, nonce, status, bytes);
            if (!MessageSigner.IsValid(expected, responseSignature))
                throw new PeerException($"response from {Peer.Name} has an invalid signature (wrong API key or tampered response)", status, retryable: false);

            if (!string.Equals(responder, Peer.Name, StringComparison.OrdinalIgnoreCase))
                _logger.LogWarning("Peer configured as {Peer} identifies itself as {Responder}", Peer.Name, responder);

            if (!response.IsSuccessStatusCode)
            {
                var error = TryReadError(bytes);
                var retryable = status is >= 500 or 408 or 409 or 423 or 429 && status != 507;
                throw new PeerException($"{Peer.Name} returned HTTP {status}: {error?.Error ?? response.ReasonPhrase}", status, error?.ExpectedOffset, retryable);
            }

            return JsonSerializer.Deserialize<T>(bytes, ProtocolJson.Options)
                   ?? throw new PeerException($"empty response from {Peer.Name}", status);
        }
    }

    private static ErrorResponse? TryReadError(byte[] bytes)
    {
        try { return bytes.Length == 0 ? null : JsonSerializer.Deserialize<ErrorResponse>(bytes, ProtocolJson.Options); }
        catch (JsonException) { return null; }
    }

    public void Dispose() => _http.Dispose();
}

/// <summary>One cached <see cref="PeerClient"/> per configured peer.</summary>
public sealed class PeerClientFactory(P2POptions options, KeyMaterial keys, ILoggerFactory loggerFactory) : IDisposable
{
    private readonly Dictionary<string, PeerClient> _clients = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _lock = new();

    public PeerClient Get(string peerName)
    {
        lock (_lock)
        {
            if (_clients.TryGetValue(peerName, out var client)) return client;
            var peer = options.FindPeer(peerName) ?? throw new InvalidOperationException($"Unknown peer '{peerName}'.");
            client = new PeerClient(peer, options, keys, loggerFactory.CreateLogger($"P2PFileTransfer.Peer.{peer.Name}"));
            _clients[peerName] = client;
            return client;
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            foreach (var c in _clients.Values) c.Dispose();
            _clients.Clear();
        }
    }
}
