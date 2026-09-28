using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using P2PFileTransfer.Configuration;
using P2PFileTransfer.Protocol;
using P2PFileTransfer.Security;
using P2PFileTransfer.Sending;

namespace P2PFileTransfer.Cli;

public static class CommandLine
{
    private const string Usage = """
        P2PFileTransfer - peer-to-peer file transfer between servers (HTTP/HTTPS, API key + HMAC)

        Usage:
          P2PFileTransfer                          Run as service: receive files + run scheduled jobs
          P2PFileTransfer --run-job <name|all>     Run job(s) now, then exit
          P2PFileTransfer --check                  Validate appsettings.json and test the connection to every peer
          P2PFileTransfer --history [job]          Show the history of sent files
          P2PFileTransfer --generate-key           Generate a strong random API key
          P2PFileTransfer --generate-cert <out.pfx> [--cn name] [--dns a,b] [--ip x,y] [--years 5]
                                                   Create a self-signed HTTPS certificate (password is asked, or P2P_CERT_PASSWORD)
          P2PFileTransfer --thumbprint <file.pfx|file.cer>
                                                   Print the SHA-256 thumbprint used for certificate pinning
          P2PFileTransfer --help                   Show this help
        """;

    public static bool IsCommand(string[] args) => args.Length > 0 && Known(args[0]);

    private static bool Known(string arg) => arg.ToLowerInvariant() is
        "--run-job" or "--check" or "--history" or "--generate-key" or "--generate-cert" or "--thumbprint" or "--help" or "-h" or "/?";

    public static async Task<int> RunAsync(string[] args)
    {
        try
        {
            return args[0].ToLowerInvariant() switch
            {
                "--generate-key" => GenerateKey(),
                "--generate-cert" => GenerateCertificate(args),
                "--thumbprint" => PrintThumbprint(args),
                "--run-job" => await RunJobsAsync(args),
                "--check" => await CheckAsync(),
                "--history" => await HistoryAsync(args),
                _ => PrintUsage(0),
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Console.Error.WriteLine("Error: " + ex.Message);
            return 1;
        }
    }

    public static int PrintUsage(int exitCode)
    {
        Console.WriteLine(Usage);
        return exitCode;
    }

    private static int GenerateKey()
    {
        var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48)).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        Console.WriteLine(key);
        Console.Error.WriteLine("Put this value in P2P:Security:ApiKey on EVERY node that must communicate. Keep it secret.");
        return 0;
    }

    private static int GenerateCertificate(string[] args)
    {
        if (args.Length < 2 || args[1].StartsWith("--", StringComparison.Ordinal)) return PrintUsage(2);
        var output = Path.GetFullPath(args[1]);
        var cn = Option(args, "--cn") ?? Environment.MachineName;
        var dns = Split(Option(args, "--dns"));
        var ips = Split(Option(args, "--ip")).Select(IPAddress.Parse).ToList();
        var years = int.TryParse(Option(args, "--years"), out var y) && y is > 0 and <= 30 ? y : 5;

        var password = Environment.GetEnvironmentVariable("P2P_CERT_PASSWORD");
        if (string.IsNullOrEmpty(password))
        {
            password = ReadPassword("PFX password: ");
            if (password != ReadPassword("Repeat password: ")) throw new InvalidOperationException("Passwords do not match.");
        }
        if (password.Length < 8) throw new InvalidOperationException("Password must be at least 8 characters.");
        if (File.Exists(output)) throw new InvalidOperationException($"'{output}' already exists.");

        using var cert = CertificateTools.CreateSelfSigned(cn, dns, ips, years);
        File.WriteAllBytes(output, cert.Export(X509ContentType.Pfx, password));

        Console.WriteLine($"Certificate : {output}");
        Console.WriteLine($"Subject     : {cert.Subject}");
        Console.WriteLine($"Valid until : {cert.NotAfter:yyyy-MM-dd}");
        Console.WriteLine($"SHA-256     : {CertificateTools.Sha256Thumbprint(cert)}");
        Console.WriteLine();
        Console.WriteLine("1. On THIS node, add to appsettings.json:");
        Console.WriteLine("""
             "Kestrel": { "Endpoints": { "Https": { "Url": "https://0.0.0.0:5443",
               "Certificate": { "Path": "<path to pfx>", "Password": "<password>" } } } }
           """);
        Console.WriteLine("2. On every OTHER node, set this peer's BaseUrl to https://... and");
        Console.WriteLine($"   \"CertificateThumbprint\": \"{CertificateTools.Sha256Thumbprint(cert)}\"");
        return 0;
    }

    private static int PrintThumbprint(string[] args)
    {
        if (args.Length < 2) return PrintUsage(2);
        var isPfx = Path.GetExtension(args[1]).ToLowerInvariant() is ".pfx" or ".p12";
        var password = isPfx ? Environment.GetEnvironmentVariable("P2P_CERT_PASSWORD") ?? ReadPassword("PFX password: ") : null;
        using var cert = CertificateTools.Load(args[1], password);
        Console.WriteLine($"Subject     : {cert.Subject}");
        Console.WriteLine($"Valid until : {cert.NotAfter:yyyy-MM-dd}");
        Console.WriteLine($"SHA-256     : {CertificateTools.Sha256Thumbprint(cert)}");
        return 0;
    }

    private static async Task<int> RunJobsAsync(string[] args)
    {
        if (args.Length < 2) return PrintUsage(2);
        using var host = BuildHost(out var options);
        if (host is null) return 1;

        var jobs = string.Equals(args[1], "all", StringComparison.OrdinalIgnoreCase)
            ? options.Jobs.Where(j => j.Enabled).ToList()
            : options.Jobs.Where(j => string.Equals(j.Name, args[1], StringComparison.OrdinalIgnoreCase)).ToList();
        if (jobs.Count == 0)
        {
            Console.Error.WriteLine($"No job named '{args[1]}'. Configured jobs: {string.Join(", ", options.Jobs.Select(j => j.Name))}");
            return 2;
        }

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        var runner = host.Services.GetRequiredService<JobRunner>();
        var exit = 0;
        foreach (var job in jobs)
        {
            var result = await runner.RunAsync(job, cts.Token);
            if (!result.Success) exit = 3;
        }
        return exit;
    }

    private static async Task<int> CheckAsync()
    {
        using var host = BuildHost(out var options);
        if (host is null) return 1;

        Console.WriteLine($"Configuration OK. Node: {options.NodeName}");
        Console.WriteLine($"Data directory: {PathHelper.Resolve(options.DataDirectory)}");
        foreach (var (alias, path) in options.Receiver.Destinations)
        {
            var resolved = PathHelper.Resolve(path);
            Console.WriteLine($"Destination '{alias}': {resolved} {(Directory.Exists(resolved) ? "" : "(will be created)")}");
        }
        foreach (var job in options.Jobs)
        {
            var src = PathHelper.Resolve(job.SourceDirectory);
            Console.WriteLine($"Job '{job.Name}': {src} {(Directory.Exists(src) ? "" : "(NOT FOUND)")} -> {string.Join(", ", job.TargetPeers)}:{job.RemoteDestination} at {string.Join(", ", job.Times)}");
        }

        var factory = host.Services.GetRequiredService<PeerClientFactory>();
        var failures = 0;
        foreach (var peer in options.Peers)
        {
            var client = factory.Get(peer.Name);
            var sw = Stopwatch.StartNew();
            try
            {
                var pong = await client.PingAsync(CancellationToken.None);
                var skew = Math.Round((pong.TimeUtc - DateTimeOffset.UtcNow).TotalSeconds);
                Console.WriteLine($"Peer {peer.Name,-20} OK   {sw.ElapsedMilliseconds} ms, remote node '{pong.Node}' v{pong.Version}, " +
                                  $"clock diff {skew:+0;-0;0}s, {(client.IsHttps ? "HTTPS" : "HTTP (payload encrypted)")}");
            }
            catch (Exception ex)
            {
                failures++;
                Console.WriteLine($"Peer {peer.Name,-20} FAIL {ex.Message}");
            }
        }
        return failures == 0 ? 0 : 3;
    }

    private static async Task<int> HistoryAsync(string[] args)
    {
        using var host = BuildHost(out _);
        if (host is null) return 1;
        var records = await host.Services.GetRequiredService<Storage.SentHistory>().ReadAllAsync(CancellationToken.None);
        var job = args.Length > 1 ? args[1] : null;
        foreach (var r in records.Where(r => job is null || string.Equals(r.Job, job, StringComparison.OrdinalIgnoreCase)).OrderBy(r => r.SentAtUtc))
            Console.WriteLine($"{r.SentAtUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}  {r.Job,-15} {r.Peer,-15} {r.Size,15:N0}  {r.SourcePath}");
        return 0;
    }

    private static IHost? BuildHost(out P2POptions options)
    {
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        {
            ContentRootPath = AppContext.BaseDirectory,
            DisableDefaults = false,
        });
        if (!AppSetup.TryLoadOptions(builder.Configuration, out options)) return null;
        builder.Logging.ClearProviders();
        AppSetup.ConfigureLogging(builder.Logging, options);
        AppSetup.AddCoreServices(builder.Services, options);
        return builder.Build();
    }

    private static string? Option(string[] args, string name)
    {
        var i = Array.FindIndex(args, a => string.Equals(a, name, StringComparison.OrdinalIgnoreCase));
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    private static string[] Split(string? value) =>
        string.IsNullOrWhiteSpace(value) ? [] : value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static string ReadPassword(string prompt)
    {
        Console.Write(prompt);
        if (Console.IsInputRedirected)
            return Console.ReadLine() ?? "";

        var chars = new List<char>();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) break;
            if (key.Key == ConsoleKey.Backspace) { if (chars.Count > 0) chars.RemoveAt(chars.Count - 1); continue; }
            if (!char.IsControl(key.KeyChar)) chars.Add(key.KeyChar);
        }
        Console.WriteLine();
        return new string([.. chars]);
    }
}
