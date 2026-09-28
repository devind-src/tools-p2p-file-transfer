#Requires -RunAsAdministrator
param([string]$ServiceName = "P2PFileTransfer")

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne "Stopped") { Stop-Service -Name $ServiceName -Force }
    sc.exe delete $ServiceName | Out-Null
}
Get-NetFirewallRule -DisplayName $ServiceName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Write-Host "Service and firewall rule removed. The install folder (history, logs, config) was left untouched."
