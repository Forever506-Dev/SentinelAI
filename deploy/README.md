<div align="center">

# 🚀 SentinelAI Agent — Remote Deployment Guide

![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![macOS](https://img.shields.io/badge/macOS-000000?style=for-the-badge&logo=apple&logoColor=white)

</div>

<br/>

---

<br/>

## 🏗️ Architecture

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Endpoint A  │    │  Endpoint B  │    │  Endpoint C  │
│  (agent)     │    │  (agent)     │    │  (agent)     │
└──────┬───────┘    └──────┬───────┘    └──────┬───────┘
       │ HTTPS             │ HTTPS             │ HTTPS
       └───────────────────┼───────────────────┘
                           │
                    ┌──────▼───────┐
                    │   Server     │
                    │  Backend     │  :8000
                    │  Panel       │  :3000
                    │  Postgres    │  :5432
                    │  Redis       │  :6379
                    │  Elastic     │  :9200
                    └──────────────┘
```

All agents report to **one central server**. The web panel on `:3000` shows consolidated telemetry from every endpoint.

<br/>

---

<br/>

## 🐧 Quick Deploy — Linux → Linux

### On the server

```bash
# Copy the compiled agent binary into the deploy folder
cp agent/target/release/sentinel-agent deploy/

# Make install script executable
chmod +x deploy/install_agent.sh
```

### On a remote endpoint

Transfer the `deploy/` folder to the target machine, then run the installer:

```bash
# From the server — copy deploy folder to remote host
scp -r deploy/ user@REMOTE_IP:/tmp/sentinelai-deploy/

# SSH into the remote machine
ssh user@REMOTE_IP

# Run the installer (replace with your server's LAN IP)
cd /tmp/sentinelai-deploy
sudo ./install_agent.sh <YOUR_SERVER_IP>
```

> **The agent will:**
> 1. Install to `/opt/sentinelai/`
> 2. Register with your backend automatically
> 3. Start sending telemetry (processes, files, network, system info)
> 4. Run as a systemd service (auto-restart on boot)

<br/>

---

<br/>

## 🔧 Managing Remote Agents

```bash
# View live logs
journalctl -u sentinel-agent -f

# Restart / Stop
sudo systemctl restart sentinel-agent
sudo systemctl stop sentinel-agent

# Full uninstall
sudo systemctl stop sentinel-agent
sudo systemctl disable sentinel-agent
sudo rm /etc/systemd/system/sentinel-agent.service
sudo rm -rf /opt/sentinelai
sudo systemctl daemon-reload
```

<br/>

---

<br/>

## 🌍 Cross-Platform Compilation

### Linux x86_64 — Pre-built

The binary in `deploy/` is already compiled for Linux x86_64. No extra steps needed.

<br/>

### Linux ARM64 — Raspberry Pi / ARM servers

```bash
rustup target add aarch64-unknown-linux-gnu
sudo apt install gcc-aarch64-linux-gnu

CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
  cargo build --release --target aarch64-unknown-linux-gnu

cp target/aarch64-unknown-linux-gnu/release/sentinel-agent deploy/
```

<br/>

### Windows — Cross-compile from Linux

```bash
rustup target add x86_64-pc-windows-gnu
sudo apt install mingw-w64

cargo build --release --target x86_64-pc-windows-gnu
# Binary: target/x86_64-pc-windows-gnu/release/sentinel-agent.exe
```

Place `sentinel-agent.exe` + `agent.toml` on the Windows machine. See [windows/README.md](windows/README.md) for the full Windows guide.

<br/>

### macOS

```bash
# Must be built on a macOS machine (or use cross/osxcross):
cargo build --release
# Binary: target/release/sentinel-agent
```

<br/>

---

<br/>

## ⚙️ Configuration

Edit `/opt/sentinelai/agent.toml` on each endpoint:

| Setting | Description |
|:--------|:------------|
| `backend_url` | **Required** — Server IP + port 8000 |
| `heartbeat_interval_secs` | How often (seconds) to send heartbeat |
| `telemetry_batch_size` | Events batched before sending |
| `watch_paths` | Filesystem paths to monitor |
| `collectors.*_enabled` | Toggle individual collectors on/off |

<br/>

---

<br/>

## 🔒 Firewall Notes

The server needs these ports open for agent connections:

| Port | Service | Required By |
|:-----|:--------|:------------|
| `8000` | Backend API | All agents |
| `3000` | Web Panel | Browser only |

```bash
# If using ufw on the server:
sudo ufw allow 8000/tcp comment "SentinelAI Backend API"
sudo ufw allow 3000/tcp comment "SentinelAI Web Panel"
```
