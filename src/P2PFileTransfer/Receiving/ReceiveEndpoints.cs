using P2PFileTransfer.Configuration;
using P2PFileTransfer.Protocol;

namespace P2PFileTransfer.Receiving;

public static class ReceiveEndpoints
{
    public static void MapP2PEndpoints(this WebApplication app)
    {
        app.MapGet(P2PRoutes.Ping, (P2POptions o) =>
            Results.Ok(new PingResponse(o.NodeName, DateTimeOffset.UtcNow, AppInfo.Version)));

        app.MapPost(P2PRoutes.Transfers, (HttpContext ctx, TransferReceiver receiver, CancellationToken ct) =>
            receiver.InitAsync(ctx, ct));

        app.MapPut(P2PRoutes.Transfers + "/{id}/chunks/{offset:long}", (string id, long offset, HttpContext ctx, TransferReceiver receiver, CancellationToken ct) =>
            receiver.ChunkAsync(ctx, id, offset, ct));

        app.MapPost(P2PRoutes.Transfers + "/{id}/complete", (string id, HttpContext ctx, TransferReceiver receiver, CancellationToken ct) =>
            receiver.CompleteAsync(ctx, id, ct));

        app.MapFallback((HttpContext ctx) =>
            Results.Json(new ErrorResponse("not found"), ProtocolJson.Options, statusCode: StatusCodes.Status404NotFound));
    }
}
