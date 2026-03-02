#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Uninstalls the SentinelAI Agent from Windows.
#>

$ServiceName = "SentinelAIAgent"
$InstallDir = "C:\Program Files\SentinelAI"
$FwRuleName = "SentinelAI Agent Outbound"

Write-Host ""
Write-Host "Uninstalling SentinelAI Agent..." -ForegroundColor Yellow
Write-Host ""

# Stop and remove service
$Svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($Svc) {
    if ($Svc.Status -eq "Running") {
        Stop-Service -Name $ServiceName -Force
        Write-Host "[+] Service stopped" -ForegroundColor Green
        Start-Sleep -Seconds 2
    }
    sc.exe delete $ServiceName | Out-Null
    Write-Host "[+] Service removed" -ForegroundColor Green
} else {
    Write-Host "[*] Service not found" -ForegroundColor Yellow
}

# Remove firewall rule
$Rule = Get-NetFirewallRule -DisplayName $FwRuleName -ErrorAction SilentlyContinue
if ($Rule) {
    Remove-NetFirewallRule -DisplayName $FwRuleName
    Write-Host "[+] Firewall rule removed" -ForegroundColor Green
}

# Remove installation directory
if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force
    Write-Host "[+] Removed $InstallDir" -ForegroundColor Green
}

Write-Host ""
Write-Host "SentinelAI Agent uninstalled." -ForegroundColor Green
Write-Host ""
