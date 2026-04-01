#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SentinelAI Agent Installer for Windows

.DESCRIPTION
    Installs the SentinelAI endpoint agent as a Windows Service.
    Must be run as Administrator.

.PARAMETER ServerIP
    The IP address of your SentinelAI server (backend + panel host).

.EXAMPLE
    .\Install-SentinelAgent.ps1 -ServerIP <YOUR_SERVER_IP>
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$ServerIP
)

$ErrorActionPreference = "Stop"

$InstallDir = "C:\Program Files\SentinelAI"
$ServiceName = "SentinelAIAgent"
$DisplayName = "SentinelAI Endpoint Agent"
$Description = "SentinelAI EDR endpoint telemetry collector and response agent"
$BinaryName = "sentinel-agent.exe"
$ConfigName = "agent.toml"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SentinelAI Agent Installer (Windows)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Server IP : $ServerIP"
Write-Host "Install to: $InstallDir"
Write-Host ""

# ---------------------------------------------------------------------------
# 1. Create installation directory
# ---------------------------------------------------------------------------
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Host "[+] Created $InstallDir" -ForegroundColor Green
} else {
    Write-Host "[*] $InstallDir already exists" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 2. Copy binary
# ---------------------------------------------------------------------------
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$SrcBinary = Join-Path $ScriptDir $BinaryName
$SrcConfig = Join-Path $ScriptDir $ConfigName

if (!(Test-Path $SrcBinary)) {
    Write-Host "[!] ERROR: $BinaryName not found in $ScriptDir" -ForegroundColor Red
    Write-Host "    Make sure sentinel-agent.exe is in the same folder as this script." -ForegroundColor Red
    exit 1
}

Copy-Item -Path $SrcBinary -Destination $InstallDir -Force
Write-Host "[+] Copied $BinaryName -> $InstallDir" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 3. Write configuration with server IP
# ---------------------------------------------------------------------------
$DestConfig = Join-Path $InstallDir $ConfigName

if (Test-Path $SrcConfig) {
    $ConfigContent = Get-Content $SrcConfig -Raw
    $ConfigContent = $ConfigContent -replace "SENTINEL_SERVER_IP", $ServerIP
    Set-Content -Path $DestConfig -Value $ConfigContent -Encoding UTF8
    Write-Host "[+] Configuration written to $DestConfig" -ForegroundColor Green
} else {
    # Generate minimal config if template not found
    $MinimalConfig = @"
backend_url = "http://${ServerIP}:8000/api/v1"
heartbeat_interval_secs = 15
telemetry_batch_size = 50

[collectors]
process_enabled = true
filesystem_enabled = true
network_enabled = true
system_info_enabled = true

watch_paths = ["C:\\Users", "C:\\Windows\\System32", "C:\\Windows\\Temp"]
hash_extensions = ["exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js"]
"@
    Set-Content -Path $DestConfig -Value $MinimalConfig -Encoding UTF8
    Write-Host "[+] Generated minimal config at $DestConfig" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 4. Create data directory for agent state
# ---------------------------------------------------------------------------
$DataDir = Join-Path $env:ProgramData "SentinelAI"
if (!(Test-Path $DataDir)) {
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
    Write-Host "[+] Created data dir $DataDir" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 5. Add firewall rules (outbound to server)
# ---------------------------------------------------------------------------
$FwRuleName = "SentinelAI Agent Outbound"
$ExistingRule = Get-NetFirewallRule -DisplayName $FwRuleName -ErrorAction SilentlyContinue
if (!$ExistingRule) {
    New-NetFirewallRule -DisplayName $FwRuleName `
        -Direction Outbound `
        -Action Allow `
        -Program (Join-Path $InstallDir $BinaryName) `
        -Protocol TCP `
        -Enabled True | Out-Null
    Write-Host "[+] Firewall rule created" -ForegroundColor Green
} else {
    Write-Host "[*] Firewall rule already exists" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 6. Install as Windows Service using sc.exe
#    The agent binary natively supports the Windows SCM protocol.
#    When launched by SCM it registers as a service; when launched
#    from a console it runs interactively.
#    Runs as LocalSystem for WFP (Windows Filtering Platform) access.
# ---------------------------------------------------------------------------
$ExistingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if ($ExistingService) {
    Write-Host "[*] Stopping existing service..." -ForegroundColor Yellow
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
    Write-Host "[+] Old service removed" -ForegroundColor Green
}

$BinaryFullPath = Join-Path $InstallDir $BinaryName
$BinaryPath = "`"$BinaryFullPath`""
sc.exe create $ServiceName binPath= $BinaryPath start= auto obj= "LocalSystem" DisplayName= "`"$DisplayName`"" | Out-Null
sc.exe description $ServiceName "`"$Description`"" | Out-Null
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

Write-Host "[+] Windows Service '$ServiceName' created (LocalSystem for WFP access)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 6b. Lock down installation directory ACLs
#     Only SYSTEM and Administrators can read/write the agent directory.
# ---------------------------------------------------------------------------
try {
    $acl = Get-Acl $InstallDir
    $acl.SetAccessRuleProtection($true, $false)  # Disable inheritance
    
    # SYSTEM: Full Control
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $acl.AddAccessRule($systemRule)
    
    # Administrators: Full Control
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $acl.AddAccessRule($adminRule)
    
    Set-Acl -Path $InstallDir -AclObject $acl
    Write-Host "[+] ACLs locked down (SYSTEM + Administrators only)" -ForegroundColor Green
} catch {
    Write-Host "[!] Warning: Could not lock down ACLs: $_" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 7. Start the service
# ---------------------------------------------------------------------------
try {
    Start-Service -Name $ServiceName -ErrorAction Stop
    Write-Host "[+] Service started successfully!" -ForegroundColor Green
} catch {
    Write-Host "[!] Service failed to start: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  1. Check Windows Event Viewer > Application log for details"
    Write-Host "  2. Test manually:  & '$BinaryFullPath'"
    Write-Host "     (The agent will detect it was not launched by SCM and run in console mode)"
    Write-Host "  3. Verify network connectivity:  Test-NetConnection $ServerIP -Port 8000"
    Write-Host ""
}

# ---------------------------------------------------------------------------
# 8. Verify
# ---------------------------------------------------------------------------
Start-Sleep -Seconds 3
$Svc = Get-Service -Name $ServiceName
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Installation Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Service Name  : $ServiceName"
Write-Host "  Service Status: $($Svc.Status)"
Write-Host "  Install Path  : $InstallDir"
Write-Host "  Config File   : $DestConfig"
Write-Host "  Server URL    : http://${ServerIP}:8000/api/v1"
Write-Host ""
Write-Host "  Management commands:"
Write-Host "    Stop  : Stop-Service $ServiceName"
Write-Host "    Start : Start-Service $ServiceName"
Write-Host "    Status: Get-Service $ServiceName"
Write-Host "    Logs  : Get-WinEvent -LogName Application | Where-Object {`$_.ProviderName -eq '$ServiceName'}"
Write-Host "    Remove: sc.exe delete $ServiceName"
Write-Host ""
