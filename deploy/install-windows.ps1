#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Installs P2PFileTransfer as a Windows Service.

.DESCRIPTION
  - Registers a native Windows Service (automatic delayed start) with recovery actions:
    the service is restarted automatically if it stops unexpectedly.
  - Runs as LocalSystem by default, or as the account given with -Credential
    (e.g. a domain/service account that has access to the backup folders).
  - Restricts the install folder (contains the API key) to SYSTEM, Administrators and the service account.
  - Opens the listening port in Windows Firewall, optionally only for the given peer IPs.

.EXAMPLE
  .\install-windows.ps1 -InstallDir C:\P2PFileTransfer -Port 5080 -RemoteAddress 192.168.1.20

.EXAMPLE
  .\install-windows.ps1 -Credential (Get-Credential DOMAIN\svc-p2p)
#>
param(
    [string]$InstallDir = "C:\P2PFileTransfer",
    [int]$Port = 5080,
    [string[]]$RemoteAddress = @("Any"),
    [string]$ServiceName = "P2PFileTransfer",
    [pscredential]$Credential
)

$ErrorActionPreference = "Stop"
$exe = Join-Path $InstallDir "P2PFileTransfer.exe"
if (-not (Test-Path $exe)) { throw "P2PFileTransfer.exe not found in $InstallDir. Copy the published files there first." }

Write-Host "Validating configuration..."
& $exe --check
if ($LASTEXITCODE -eq 1) { throw "appsettings.json is invalid. Fix the errors above and run this script again." }

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Removing existing service '$ServiceName'..."
    if ($existing.Status -ne "Stopped") { Stop-Service -Name $ServiceName -Force }
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

Write-Host "Creating service '$ServiceName'..."
$params = @{
    Name           = $ServiceName
    BinaryPathName = "`"$exe`""
    DisplayName    = "P2P File Transfer"
    Description    = "Peer-to-peer transfer of database backup files between servers."
    StartupType    = "Automatic"
}
if ($Credential) { $params.Credential = $Credential }
New-Service @params | Out-Null

# Delayed auto start (network is up) + restart on failure (1 min, 1 min, 5 min; reset counter after 1 day).
sc.exe config $ServiceName start= delayed-auto | Out-Null
sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/300000 | Out-Null
sc.exe failureflag $ServiceName 1 | Out-Null

Write-Host "Restricting permissions of $InstallDir..."
$grants = @("*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F")
if ($Credential) { $grants += "$($Credential.UserName):(OI)(CI)M" }
icacls $InstallDir /inheritance:r /grant:r $grants | Out-Null

Write-Host "Configuring Windows Firewall (TCP $Port)..."
Get-NetFirewallRule -DisplayName $ServiceName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName $ServiceName -Direction Inbound -Protocol TCP -LocalPort $Port `
    -RemoteAddress $RemoteAddress -Action Allow -Profile Any -Program $exe | Out-Null

Start-Service -Name $ServiceName
Start-Sleep -Seconds 3
Get-Service -Name $ServiceName | Select-Object Name, Status, StartType | Format-Table
Write-Host "Installed. Logs: $(Join-Path $InstallDir 'logs') and Windows Event Log (Application, source '$ServiceName')."
