# SentinelAI Agent — Windows Deployment

## Quick Install

1. Copy the entire `windows/` folder to the target Windows machine
2. Open **PowerShell as Administrator**
3. Run the installer, replacing the IP with your SentinelAI server:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Install-SentinelAgent.ps1 -ServerIP 192.168.2.83
```

The agent will:
- Install to `C:\Program Files\SentinelAI\`
- Register as a Windows Service (auto-start on boot)
- Create an outbound firewall rule
- Begin sending telemetry to the server immediately

## Manual Run (No Service)

For testing without installing as a service:

```powershell
cd C:\path\to\windows\
# Edit agent.toml — replace SENTINEL_SERVER_IP with your server IP
.\sentinel-agent.exe
```

## Contents

| File | Purpose |
|------|---------|
| `sentinel-agent.exe` | Agent binary (x86_64 PE32+) |
| `agent.toml` | Configuration template |
| `Install-SentinelAgent.ps1` | Automated installer |
| `Uninstall-SentinelAgent.ps1` | Clean uninstaller |

## Management

```powershell
# Check status
Get-Service SentinelAIAgent

# Stop / Start / Restart
Stop-Service SentinelAIAgent
Start-Service SentinelAIAgent
Restart-Service SentinelAIAgent

# View logs
Get-WinEvent -LogName Application | Where-Object {$_.ProviderName -eq 'SentinelAIAgent'} | Select-Object -First 20

# Uninstall
.\Uninstall-SentinelAgent.ps1
```

## Config Location

After installation, the config lives at:
```
C:\Program Files\SentinelAI\agent.toml
```

Edit it and restart the service to apply changes:
```powershell
Restart-Service SentinelAIAgent
```

## Network Requirements

The agent needs outbound TCP access to the server on port **8000**.
Ensure no firewall blocks `sentinel-agent.exe → <server_ip>:8000`.

## Monitored Paths (Default)

- `C:\Users` — User activity
- `C:\Windows\System32` — System binary changes
- `C:\Windows\Temp` — Temp file activity
- `C:\ProgramData` — Application data changes
