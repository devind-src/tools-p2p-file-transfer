using System.Text;

namespace P2PFileTransfer.Logging;

/// <summary>Minimal daily-rolling file logger (logs/p2p-yyyyMMdd.log) with retention, built only on the framework.</summary>
[ProviderAlias("File")]
public sealed class FileLoggerProvider(string directory, int retentionDays) : ILoggerProvider
{
    private readonly Lock _lock = new();
    private DateOnly _lastCleanup;

    public ILogger CreateLogger(string categoryName) => new FileLogger(this, categoryName);

    internal void Write(string line)
    {
        lock (_lock)
        {
            try
            {
                Directory.CreateDirectory(directory);
                var today = DateOnly.FromDateTime(DateTime.Now);
                File.AppendAllText(Path.Combine(directory, $"p2p-{today:yyyyMMdd}.log"), line, Encoding.UTF8);
                if (_lastCleanup != today)
                {
                    _lastCleanup = today;
                    var cutoff = DateTime.Now.AddDays(-retentionDays);
                    foreach (var file in Directory.EnumerateFiles(directory, "p2p-*.log"))
                        if (File.GetLastWriteTime(file) < cutoff) File.Delete(file);
                }
            }
            catch (Exception) { /* logging must never crash the application */ }
        }
    }

    public void Dispose() { }

    private sealed class FileLogger(FileLoggerProvider provider, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;
            var level = logLevel switch
            {
                LogLevel.Trace => "TRC",
                LogLevel.Debug => "DBG",
                LogLevel.Information => "INF",
                LogLevel.Warning => "WRN",
                LogLevel.Error => "ERR",
                _ => "CRT",
            };
            var sb = new StringBuilder()
                .Append(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff", System.Globalization.CultureInfo.InvariantCulture))
                .Append(" [").Append(level).Append("] ")
                .Append(category).Append(": ")
                .Append(formatter(state, exception))
                .AppendLine();
            if (exception is not null) sb.AppendLine(exception.ToString());
            provider.Write(sb.ToString());
        }
    }
}
