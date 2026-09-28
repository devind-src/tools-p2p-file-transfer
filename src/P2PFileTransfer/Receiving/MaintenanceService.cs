using P2PFileTransfer.Security;
using P2PFileTransfer.Storage;

namespace P2PFileTransfer.Receiving;

/// <summary>Hourly housekeeping: expired incomplete transfers, ban list and received log.</summary>
public sealed class MaintenanceService(TransferReceiver receiver, ClientIpGuard guard, ReceivedLog receivedLog, ILogger<MaintenanceService> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromHours(1));
        do
        {
            try
            {
                receiver.CleanupExpired();
                guard.Cleanup();
                await receivedLog.PruneAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Maintenance failed");
            }
        } while (await WaitAsync(timer, stoppingToken));
    }

    private static async Task<bool> WaitAsync(PeriodicTimer timer, CancellationToken ct)
    {
        try { return await timer.WaitForNextTickAsync(ct); }
        catch (OperationCanceledException) { return false; }
    }
}
