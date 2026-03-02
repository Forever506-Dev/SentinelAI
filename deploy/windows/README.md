<div align="center">

# 🪟 SentinelAI Agent — Windows Deployment

![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white)

</div>

<br/>

---

<br/>

## ⚡ Quick Install

1. Copy the entire `windows/` folder to the target Windows machine
2. Open **PowerShell as Administrator**
3. Run the installer:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Install-SentinelAgent.ps1 -ServerIP 192.168.2.83
```

> **The agent will:**
> - Install to `C:\Program Files\SentinelAI\`
> - Register as a **Windows Service** (auto-start on boot)
> - Create an outbound firewall rule
> - Begin sending telemetry to the server immediately

<br/>

---

<br/>

## 🧪 Manual Run (No Service)

For testing without installing as a service:

```powershell
cd C:\path\to\windows\

# Edit agent.toml — replace SENTINEL_SERVER_IP with your server IP
.\sentinel-agent.exe
```

<br/>

---

<br/>

## 📦 Contents

| File | Purpose |
|:-----|:--------|
| `sentinel-agent.exe` | Agent binary (x86_64 PE32+) |
| `agent.toml` | Configuration template |
| `Install-SentinelAgent.ps1` | Automated installer script |
| `Uninstall-SentinelAgent.ps1` | Clean uninstaller script |

<br/>

---

<br/>

## 🔧 Service Management

```powershell
# Check status
Get-Service SentinelAIAgent

# Stop / Start / Restart
Stop-Service SentinelAIAgent
Start-Service SentinelAIAgent
Restart-Service SentinelAIAgent

# View logs
Get-WinEvent -LogName Application |
  Where-Object { $_.ProviderName -eq 'SentinelAIAgent' } |
  Select-Object -First 20

# Full uninstall
.\Uninstall-SentinelAgent.ps1
```

<br/>

---

<br/>

## ⚙️ Configuration

After installation, the config lives at:

```
C:\Program Files\SentinelAI\agent.toml
```

Edit it and restart the service to apply changes:

```powershell
Restart-Service SentinelAIAgent
```

<br/>

---

<br/>

## 🌐 Network Requirements

The agent needs **outbound TCP** access to the server on port **8000**.

Ensure no firewall blocks `sentinel-agent.exe → <server_ip>:8000`.

<br/>

---

<br/>

## 📂 Monitored Paths (Default)

| Path | What It Watches |
|:-----|:----------------|
| `C:\Users` | User activity and file changes |
| `C:\Windows\System32` | System binary modifications |
| `C:\Windows\Temp` | Temp file creation and activity |
| `C:\ProgramData` | Application data changes |
