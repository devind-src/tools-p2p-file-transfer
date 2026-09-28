using System.Text.Json;
using P2PFileTransfer.Configuration;

namespace P2PFileTransfer.Sending;

/// <summary>Runs each job daily at its configured times (local server time). Missed runs are caught up within CatchUpMinutes.</summary>
public sealed class SchedulerService(P2POptions options, JobRunner runner, ILogger<SchedulerService> logger) : BackgroundService
{
    private readonly string _statePath = Path.Combine(PathHelper.Resolve(options.DataDirectory), "scheduler-state.json");
    private readonly Dictionary<string, Task> _running = new(StringComparer.OrdinalIgnoreCase);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var jobs = options.Jobs.Where(j => j.Enabled && j.Times.Count > 0).ToList();
        if (jobs.Count == 0)
        {
            logger.LogInformation("No scheduled jobs configured; this node only receives files");
            return;
        }

        var state = LoadState();
        var now = DateTimeOffset.Now;
        foreach (var job in jobs)
        {
            state.TryAdd(job.Name, now);
            var days = job.Days.Count == 0 ? "every day" : string.Join(", ", job.Days);
            logger.LogInformation("Job {Job} scheduled at {Times} ({Days}) -> {Peers}",
                job.Name, string.Join(", ", job.ParsedTimes().Select(t => t.ToString("HH:mm"))), days, string.Join(", ", job.TargetPeers));
        }
        SaveState(state);

        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(20));
        try
        {
            do
            {
                now = DateTimeOffset.Now;
                foreach (var job in jobs)
                {
                    if (_running.TryGetValue(job.Name, out var task) && !task.IsCompleted) continue;

                    var due = FindDueSlot(job, now, state[job.Name]);
                    if (due is null) continue;

                    state[job.Name] = due.Value;
                    SaveState(state);
                    logger.LogInformation("Scheduled run of job {Job} for {Slot:yyyy-MM-dd HH:mm}", job.Name, due.Value);
                    _running[job.Name] = Task.Run(() => RunSafeAsync(job, stoppingToken), CancellationToken.None);
                }
            } while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }

        await Task.WhenAll(_running.Values);
    }

    private DateTimeOffset? FindDueSlot(JobOptions job, DateTimeOffset now, DateTimeOffset lastRun)
    {
        DateTimeOffset? best = null;
        var catchUp = TimeSpan.FromMinutes(Math.Max(options.Sender.CatchUpMinutes, 1));
        foreach (var date in new[] { DateOnly.FromDateTime(now.LocalDateTime), DateOnly.FromDateTime(now.LocalDateTime).AddDays(-1) })
        {
            if (job.Days.Count > 0 && !job.Days.Contains(date.DayOfWeek)) continue;
            foreach (var time in job.ParsedTimes())
            {
                var slot = new DateTimeOffset(date.ToDateTime(time, DateTimeKind.Local));
                if (slot <= now && slot > lastRun && now - slot <= catchUp && (best is null || slot > best))
                    best = slot;
            }
        }
        return best;
    }

    private async Task RunSafeAsync(JobOptions job, CancellationToken ct)
    {
        try
        {
            await runner.RunAsync(job, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            logger.LogWarning("Job {Job} was interrupted by shutdown; it will resume at the next run", job.Name);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Job {Job} failed", job.Name);
        }
    }

    private Dictionary<string, DateTimeOffset> LoadState()
    {
        try
        {
            if (File.Exists(_statePath))
                return new Dictionary<string, DateTimeOffset>(
                    JsonSerializer.Deserialize<Dictionary<string, DateTimeOffset>>(File.ReadAllBytes(_statePath)) ?? [],
                    StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is JsonException or IOException)
        {
            logger.LogWarning("Could not read scheduler state {Path}: {Error}", _statePath, ex.Message);
        }
        return new Dictionary<string, DateTimeOffset>(StringComparer.OrdinalIgnoreCase);
    }

    private void SaveState(Dictionary<string, DateTimeOffset> state)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_statePath)!);
            var tmp = _statePath + ".tmp";
            File.WriteAllBytes(tmp, JsonSerializer.SerializeToUtf8Bytes(state, new JsonSerializerOptions { WriteIndented = true }));
            File.Move(tmp, _statePath, overwrite: true);
        }
        catch (IOException ex)
        {
            logger.LogWarning("Could not save scheduler state {Path}: {Error}", _statePath, ex.Message);
        }
    }
}
