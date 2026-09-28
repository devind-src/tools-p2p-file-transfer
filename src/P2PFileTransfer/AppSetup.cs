using System.Threading.RateLimiting;
using P2PFileTransfer.Configuration;
using P2PFileTransfer.Logging;
using P2PFileTransfer.Receiving;
using P2PFileTransfer.Security;
using P2PFileTransfer.Sending;
using P2PFileTransfer.Storage;

namespace P2PFileTransfer;

public static class AppSetup
{
    public static bool TryLoadOptions(IConfiguration configuration, out P2POptions options)
    {
        options = configuration.GetSection(P2POptions.SectionName).Get<P2POptions>() ?? new P2POptions();
        var errors = OptionsValidator.Validate(options);
        if (errors.Count == 0) return true;

        Console.Error.WriteLine($"Configuration error(s) in appsettings.json ({Path.Combine(AppContext.BaseDirectory, "appsettings.json")}):");
        foreach (var e in errors) Console.Error.WriteLine("  - " + e);
        return false;
    }

    public static void ConfigureLogging(ILoggingBuilder logging, P2POptions options)
    {
        logging.AddSimpleConsole(o =>
        {
            o.SingleLine = true;
            o.TimestampFormat = "yyyy-MM-dd HH:mm:ss ";
        });
        if (options.FileLog.Enabled)
            logging.AddProvider(new FileLoggerProvider(PathHelper.Resolve(options.FileLog.Directory), options.FileLog.RetentionDays));
    }

    /// <summary>Services shared by the service mode and the command line.</summary>
    public static void AddCoreServices(IServiceCollection services, P2POptions options)
    {
        services.AddSingleton(options);
        services.AddSingleton<KeyMaterial>();
        services.AddSingleton<SentHistory>();
        services.AddSingleton<ReceivedLog>();
        services.AddSingleton<PeerClientFactory>();
        services.AddSingleton<JobRunner>();
    }

    public static async Task<int> RunServiceAsync(string[] args)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = args,
            ContentRootPath = AppContext.BaseDirectory,
        });

        if (!TryLoadOptions(builder.Configuration, out var options)) return 1;
        ConfigureLogging(builder.Logging, options);
        AddCoreServices(builder.Services, options);

        builder.Services.AddSingleton<NonceCache>();
        builder.Services.AddSingleton<ClientIpGuard>();
        builder.Services.AddSingleton<TransferReceiver>();
        builder.Services.AddHostedService<SchedulerService>();
        builder.Services.AddHostedService<MaintenanceService>();

        if (options.Security.RateLimitPerMinute > 0)
        {
            builder.Services.AddRateLimiter(o =>
            {
                o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
                o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
                    RateLimitPartition.GetFixedWindowLimiter(
                        ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                        _ => new FixedWindowRateLimiterOptions
                        {
                            PermitLimit = options.Security.RateLimitPerMinute,
                            Window = TimeSpan.FromMinutes(1),
                            QueueLimit = 0,
                        }));
            });
        }

        builder.WebHost.ConfigureKestrel(k =>
        {
            k.AddServerHeader = false;
            k.Limits.MaxRequestBodySize = options.Receiver.MaxChunkSizeMB * 1024L * 1024L + PayloadCipher.Overhead + 64 * 1024;
            k.Limits.MaxRequestHeadersTotalSize = 16 * 1024;
            k.Limits.MaxRequestLineSize = 4 * 1024;
            k.Limits.MaxConcurrentConnections = 200;
            k.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(30);
            k.Limits.KeepAliveTimeout = TimeSpan.FromMinutes(2);
            k.ConfigureHttpsDefaults(h => h.SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13);
        });

        var app = builder.Build();
        if (options.Security.RateLimitPerMinute > 0) app.UseRateLimiter();
        app.UseMiddleware<AuthMiddleware>();
        app.MapP2PEndpoints();

        LogStartupSummary(app, options);
        await app.RunAsync();
        return 0;
    }

    private static void LogStartupSummary(WebApplication app, P2POptions options)
    {
        var log = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("P2PFileTransfer");
        log.LogInformation("P2PFileTransfer {Version} starting as node {Node} (data: {Data})",
            Protocol.AppInfo.Version, options.NodeName, PathHelper.Resolve(options.DataDirectory));

        if (options.Receiver.Enabled)
        {
            foreach (var (alias, path) in options.Receiver.Destinations)
                log.LogInformation("Receiving destination {Alias} -> {Path}", alias, PathHelper.Resolve(path));
            if (options.Receiver.Destinations.Count == 0)
                log.LogWarning("Receiver is enabled but no destinations are configured; incoming transfers will be rejected");
            if (options.Receiver.AllowedExtensions.Count == 0)
                log.LogWarning("Receiver:AllowedExtensions is empty; files with any extension are accepted");
        }
        else
        {
            log.LogInformation("Receiving is disabled on this node");
        }

        if (!options.Security.RequireHttps)
            log.LogInformation("RequireHttps is disabled: payloads are still AES-256-GCM encrypted and HMAC signed, but HTTPS is recommended");
        if (options.Security.AllowedIPs.Count == 0)
            log.LogWarning("Security:AllowedIPs is empty; any IP address may connect (authentication is still required)");
        foreach (var peer in options.Peers.Where(p => p.AllowInvalidCertificate))
            log.LogWarning("Peer {Peer} has AllowInvalidCertificate enabled; prefer CertificateThumbprint pinning", peer.Name);
    }
}
