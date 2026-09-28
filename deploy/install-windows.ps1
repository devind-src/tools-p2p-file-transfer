#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Installs P2PFileTransfer as an always-running background task on Windows Server.

.DESCRIPTION
  - Registers a Task Scheduler task that starts at boot as SYSTEM and restarts automatically on failure
    (no extra service wrapper / third-party tool required).
  - Restricts the install folder (contains the API key) to SYSTEM and Administrators.
  - Opens the listening port in Windows Firewall, optionally only for the given peer IPs.

.EXAMPLE
  .\install-windows.ps1 -InstallDir C:\P2PFileTransfer -Port 5080 -RemoteAddress 192.168.1.20
#>
param(
    [string]$InstallDir = "C:\P2PFileTransfer",
    [int]$Port = 5080,
    [string[]]$RemoteAddress = @("Any"),
    [string]$TaskName = "P2PFileTransfer"
)

$ErrorActionPreference = "Stop"
$exe = Join-Path $InstallDir "P2PFileTransfer.exe"
if (-not (Test-Path $exe)) { throw "P2PFileTransfer.exe not found in $InstallDir. Copy the published files there first." }

Write-Host "Validating configuration..."
& $exe --check
if ($LASTEXITCODE -eq 1) { throw "appsettings.json is invalid. Fix the errors above and run this script again." }

Write-Host "Restricting permissions of $InstallDir to SYSTEM and Administrators..."
icacls $InstallDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null

Write-Host "Configuring Windows Firewall (TCP $Port)..."
Get-NetFirewallRule -DisplayName $TaskName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName $TaskName -Direction Inbound -Protocol TCP -LocalPort $Port `
    -RemoteAddress $RemoteAddress -Action Allow -Profile Any | Out-Null

Write-Host "Registering scheduled task '$TaskName'..."
$action    = New-ScheduledTaskAction -Execute $exe -WorkingDirectory $InstallDir
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
               -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
               -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 3
Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName, State | Format-Table
Write-Host "Installed. Logs: $(Join-Path $InstallDir 'logs')"
