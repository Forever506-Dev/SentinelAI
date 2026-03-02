# SentinelAI Agent — Remote Deployment Guide

## Architecture

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Endpoint A  │    │  Endpoint B  │    │  Endpoint C  │
│  (agent)     │    │  (agent)     │    │  (agent)     │
└──────┬───────┘    └──────┬───────┘    └──────┬───────┘
       │ HTTP              │ HTTP              │ HTTP
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

All agents report to **one central server** (your laptop at `192.168.2.83`).
The web panel on `:3000` shows consolidated telemetry from every endpoint.

## Quick Deploy (Linux → Linux)

### On the server (this laptop)

```bash
# Copy the compiled agent binary into the deploy folder
cp agent/target/release/sentinel-agent deploy/

# Make install script executable
chmod +x deploy/install_agent.sh
```

### On a remote endpoint

Transfer the `deploy/` folder to the target machine (via scp, USB, etc):

```bash
# From the server — copy deploy folder to remote host
scp -r deploy/ user@REMOTE_IP:/tmp/sentinelai-deploy/

# SSH into the remote machine
ssh user@REMOTE_IP

# Run the installer (replace with your server's LAN IP)
cd /tmp/sentinelai-deploy
sudo ./install_agent.sh 192.168.2.83
```

The agent will:
1. Install to `/opt/sentinelai/`
2. Register with your backend automatically
3. Start sending telemetry (processes, files, network, system info)
4. Run as a systemd service (auto-restart on boot)

## Managing Remote Agents

```bash
# View live logs
journalctl -u sentinel-agent -f

# Restart
sudo systemctl restart sentinel-agent

# Stop
sudo systemctl stop sentinel-agent

# Uninstall
sudo systemctl stop sentinel-agent
sudo systemctl disable sentinel-agent
sudo rm /etc/systemd/system/sentinel-agent.service
sudo rm -rf /opt/sentinelai
sudo systemctl daemon-reload
```

## Cross-Platform Deployment

### Linux (x86_64) — Pre-built
The binary in `deploy/` is already compiled for Linux x86_64.

### Linux (ARM64) — e.g. Raspberry Pi
```bash
# On the server, cross-compile:
rustup target add aarch64-unknown-linux-gnu
sudo apt install gcc-aarch64-linux-gnu
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
  cargo build --release --target aarch64-unknown-linux-gnu
cp target/aarch64-unknown-linux-gnu/release/sentinel-agent deploy/
```

### Windows
```bash
# Cross-compile from Linux:
rustup target add x86_64-pc-windows-gnu
sudo apt install mingw-w64
cargo build --release --target x86_64-pc-windows-gnu
# Binary: target/x86_64-pc-windows-gnu/release/sentinel-agent.exe
```
On Windows, place `sentinel-agent.exe` + `agent.toml` in a folder
and register as a Windows Service or run as a scheduled task.

### macOS
```bash
# Must be built on a macOS machine (or use cross/osxcross):
cargo build --release
# Binary: target/release/sentinel-agent
```

## Configuration

Edit `/opt/sentinelai/agent.toml` on each endpoint:

| Setting | Description |
|---------|-------------|
| `backend_url` | **Must** point to your server IP + port 8000 |
| `heartbeat_interval_secs` | How often (seconds) to send heartbeat |
| `telemetry_batch_size` | Events batched before sending |
| `watch_paths` | Filesystem paths to monitor |
| `collectors.*_enabled` | Toggle individual collectors |

## Firewall Notes

The server needs port **8000** (backend API) open for agent connections.
Port **3000** (web panel) only needs to be reachable from your browser.

```bash
# If using ufw on the server:
sudo ufw allow 8000/tcp comment "SentinelAI Backend API"
sudo ufw allow 3000/tcp comment "SentinelAI Web Panel"
```
