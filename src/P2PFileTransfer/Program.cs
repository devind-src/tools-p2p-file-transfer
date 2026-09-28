using P2PFileTransfer;
using P2PFileTransfer.Cli;

if (CommandLine.IsCommand(args))
    return await CommandLine.RunAsync(args);

if (args.Length > 0 && args[0].StartsWith("--", StringComparison.Ordinal))
    return CommandLine.PrintUsage(2);

return await AppSetup.RunServiceAsync(args);
