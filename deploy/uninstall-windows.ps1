#Requires -RunAsAdministrator
param([string]$TaskName = "P2PFileTransfer")

Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Get-NetFirewallRule -DisplayName $TaskName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Get-Process -Name "P2PFileTransfer" -ErrorAction SilentlyContinue | Stop-Process -Force
Write-Host "Task and firewall rule removed. The install folder (history, logs, config) was left untouched."
