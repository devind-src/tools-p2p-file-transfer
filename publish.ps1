# Builds self-contained single-file executables (no .NET runtime needed on the servers).
param([string[]]$Runtimes = @("win-x64", "linux-x64"))
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
foreach ($r in $Runtimes) {
    dotnet publish src/P2PFileTransfer -c Release -r $r -o "publish/$r"
    if ($LASTEXITCODE -ne 0) { throw "publish failed for $r" }
}
Write-Host "Output in .\publish\"
