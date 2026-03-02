#!/usr/bin/env bash
# ================================================================
# SentinelAI Agent — Remote Install Script (Linux)
#
# Usage:
#   ./install_agent.sh <SERVER_IP>
#
# Example:
#   ./install_agent.sh 192.168.2.83
#
# This script:
#   1. Creates /opt/sentinelai/
#   2. Copies the agent binary + config
#   3. Installs a systemd service
#   4. Starts and enables the agent
# ================================================================

set -euo pipefail

# ── Argument: server IP ──────────────────────────────────────────
SERVER_IP="${1:-}"
if [[ -z "$SERVER_IP" ]]; then
    echo "Usage: $0 <SENTINEL_SERVER_IP>"
    echo "  e.g. $0 192.168.2.83"
    exit 1
fi

INSTALL_DIR="/opt/sentinelai"
SERVICE_NAME="sentinel-agent"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "╔══════════════════════════════════════════════════╗"
echo "║     SentinelAI Agent Installer (Linux)          ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║  Server:  http://${SERVER_IP}:8000/api/v1       ║"
echo "║  Install: ${INSTALL_DIR}                        ║"
echo "╚══════════════════════════════════════════════════╝"
echo

# ── Check root ───────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "[!] This script must be run as root (or with sudo)."
    exit 1
fi

# ── Check binary exists ─────────────────────────────────────────
BINARY="${SCRIPT_DIR}/sentinel-agent"
if [[ ! -f "$BINARY" ]]; then
    echo "[!] Agent binary not found at: $BINARY"
    echo "    Build it first:  cd agent && cargo build --release"
    echo "    Then copy it:    cp agent/target/release/sentinel-agent deploy/"
    exit 1
fi

# ── Create install directory ─────────────────────────────────────
echo "[*] Creating ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"

# ── Copy binary ─────────────────────────────────────────────────
echo "[*] Installing agent binary..."
cp -f "${BINARY}" "${INSTALL_DIR}/sentinel-agent"
chmod 755 "${INSTALL_DIR}/sentinel-agent"

# ── Generate config from template ───────────────────────────────
TEMPLATE="${SCRIPT_DIR}/agent.toml.template"
CONFIG="${INSTALL_DIR}/agent.toml"

if [[ -f "$CONFIG" ]]; then
    echo "[*] Existing config found — backing up to ${CONFIG}.bak"
    cp "${CONFIG}" "${CONFIG}.bak"
fi

echo "[*] Writing config (server: ${SERVER_IP})..."
sed "s/SENTINEL_SERVER_IP/${SERVER_IP}/g" "${TEMPLATE}" > "${CONFIG}"
chmod 644 "${CONFIG}"

# ── Install systemd service ─────────────────────────────────────
SERVICE_SRC="${SCRIPT_DIR}/sentinel-agent.service"
SERVICE_DST="/etc/systemd/system/${SERVICE_NAME}.service"

echo "[*] Installing systemd service..."
cp -f "${SERVICE_SRC}" "${SERVICE_DST}"
chmod 644 "${SERVICE_DST}"

# ── Enable and start ────────────────────────────────────────────
echo "[*] Reloading systemd and starting agent..."
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"

sleep 2

# ── Status ──────────────────────────────────────────────────────
if systemctl is-active --quiet "${SERVICE_NAME}"; then
    echo
    echo "✓ SentinelAI Agent is running!"
    echo
    systemctl status "${SERVICE_NAME}" --no-pager -l | head -20
else
    echo
    echo "✗ Agent failed to start. Check logs:"
    echo "    journalctl -u ${SERVICE_NAME} -f"
fi

echo
echo "Useful commands:"
echo "  journalctl -u ${SERVICE_NAME} -f          # live logs"
echo "  systemctl status ${SERVICE_NAME}           # status"
echo "  systemctl restart ${SERVICE_NAME}          # restart"
echo "  systemctl stop ${SERVICE_NAME}             # stop"
echo "  cat ${INSTALL_DIR}/agent.toml              # view config"
