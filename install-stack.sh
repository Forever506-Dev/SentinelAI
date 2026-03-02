#!/usr/bin/env bash
# ============================================================
# SentinelAI — One-Click Infrastructure Installer (Linux/macOS)
# ============================================================
#
# Usage:
#   ./install-stack.sh                    # Core stack
#   ./install-stack.sh --profile all      # Everything
#   ./install-stack.sh --rebuild          # Force rebuild
#   ./install-stack.sh --down             # Stop stack
#   ./install-stack.sh --nuke             # Stop + destroy data
#
# ============================================================

set -euo pipefail

# ── Configuration ────────────────────────────────────────────
PROFILE="core"
REBUILD=false
ACTION="up"
TIMEOUT=180

# ── Colors ───────────────────────────────────────────────────
if command -v tput &>/dev/null && [ -t 1 ]; then
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    YELLOW=$(tput setaf 3)
    CYAN=$(tput setaf 6)
    DIM=$(tput dim)
    RESET=$(tput sgr0)
else
    RED="" GREEN="" YELLOW="" CYAN="" DIM="" RESET=""
fi

# ── Helpers ──────────────────────────────────────────────────
banner()  { echo -e "\n${CYAN}╔══════════════════════════════════════════╗${RESET}"; \
            echo -e "${CYAN}║  SentinelAI — Infrastructure Installer   ║${RESET}"; \
            echo -e "${CYAN}║  EDR Platform Stack (Docker Compose)     ║${RESET}"; \
            echo -e "${CYAN}╚══════════════════════════════════════════╝${RESET}\n"; }
step()    { echo -e "${GREEN}[*]${RESET} $1"; }
ok()      { echo -e "${GREEN}[✓]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
err()     { echo -e "${RED}[✗]${RESET} $1"; }

# ── Parse arguments ──────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)  PROFILE="$2"; shift 2 ;;
        --rebuild)  REBUILD=true; shift ;;
        --down)     ACTION="down"; shift ;;
        --nuke)     ACTION="nuke"; shift ;;
        --help|-h)
            echo "Usage: $0 [--profile core|monitoring|microservices|all] [--rebuild] [--down] [--nuke]"
            exit 0
            ;;
        *)
            err "Unknown argument: $1"
            exit 1
            ;;
    esac
done

# ── Find project root ───────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"

if [ ! -f "$PROJECT_ROOT/docker-compose.yml" ]; then
    PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
fi
if [ ! -f "$PROJECT_ROOT/docker-compose.yml" ]; then
    err "Cannot find docker-compose.yml. Run this script from the project root."
    exit 1
fi

cd "$PROJECT_ROOT"

banner

# ── Step 1: Check Docker ────────────────────────────────────
step "Checking Docker..."
if ! command -v docker &>/dev/null; then
    err "Docker is not installed."
    warn "Install Docker using the official script:"
    echo "    curl -fsSL https://get.docker.com | sh"
    echo "    sudo usermod -aG docker \$USER"
    echo "    # Log out and back in, then re-run this script."
    exit 1
fi
ok "Docker found: $(docker --version)"

# ── Step 2: Check Docker Compose v2 ─────────────────────────
step "Checking Docker Compose v2..."
if ! docker compose version &>/dev/null; then
    err "Docker Compose v2 is not available."
    warn "Install it via Docker's official method:"
    echo "    sudo apt-get install docker-compose-plugin"
    exit 1
fi
ok "Docker Compose found: $(docker compose version)"

# ── Step 3: Check Docker daemon ──────────────────────────────
step "Checking Docker daemon..."
if ! docker info &>/dev/null 2>&1; then
    err "Docker daemon is not running."
    warn "Start it with: sudo systemctl start docker"
    exit 1
fi
ok "Docker daemon is running."

# ── Handle --down / --nuke ───────────────────────────────────
if [ "$ACTION" = "down" ]; then
    step "Stopping SentinelAI stack (keeping data volumes)..."
    docker compose down
    ok "Stack stopped. Data volumes preserved."
    exit 0
fi

if [ "$ACTION" = "nuke" ]; then
    warn "This will DESTROY all SentinelAI data volumes (databases, indices, certs)!"
    read -rp "Type 'YES' to confirm: " confirm
    if [ "$confirm" != "YES" ]; then
        step "Aborted."
        exit 0
    fi
    docker compose --profile all down -v
    ok "Stack stopped and all data volumes destroyed."
    exit 0
fi

# ── Step 4: Bootstrap .env ───────────────────────────────────
step "Checking environment configuration..."
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp ".env.example" ".env"
        ok "Created .env from .env.example"
        warn "Review and update secrets in .env before production use!"
    else
        warn "No .env.example found. Proceeding with Docker Compose defaults."
    fi
else
    ok ".env file already exists."
fi

# ── Step 5: Build compose command ────────────────────────────
COMPOSE_CMD=(docker compose)
if [ "$PROFILE" != "core" ]; then
    COMPOSE_CMD+=(--profile "$PROFILE")
fi
COMPOSE_CMD+=(up -d --build)
if [ "$REBUILD" = true ]; then
    COMPOSE_CMD+=(--force-recreate)
fi

step "Starting SentinelAI stack (profile: $PROFILE)..."
echo "  ${DIM}Command: ${COMPOSE_CMD[*]}${RESET}"
"${COMPOSE_CMD[@]}"

# ── Step 6: Wait for health checks ──────────────────────────
step "Waiting for services to become healthy..."
elapsed=0
interval=5

while [ "$elapsed" -lt "$TIMEOUT" ]; do
    sleep "$interval"
    elapsed=$((elapsed + interval))

    total=$(docker compose ps -q 2>/dev/null | wc -l)
    running=$(docker compose ps --status running -q 2>/dev/null | wc -l)

    printf "\r  ${DIM}[%d/%ds] %d/%d services ready...${RESET}" "$elapsed" "$TIMEOUT" "$running" "$total"

    if [ "$running" -ge "$total" ] && [ "$total" -gt 0 ]; then
        echo ""
        ok "All $total services are running!"
        break
    fi
done

if [ "$elapsed" -ge "$TIMEOUT" ]; then
    echo ""
    warn "Timeout reached. Some services may still be starting."
    warn "Run 'docker compose ps' to check status."
fi

# ── Step 7: Print status ────────────────────────────────────
echo ""
step "Service Status:"
echo ""
docker compose ps
echo ""

# ── Step 8: Show logs (brief) ───────────────────────────────
step "Recent logs (last 15 lines):"
echo ""
docker compose logs --tail 15
echo ""

# ── Step 9: Print access URLs ───────────────────────────────
echo -e "${GREEN}╔══════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}║          SentinelAI Access Points        ║${RESET}"
echo -e "${GREEN}╠══════════════════════════════════════════╣${RESET}"
echo -e "${GREEN}║  Backend API:    http://localhost:8000    ║${RESET}"
echo -e "${GREEN}║  API Docs:       http://localhost:8000/api/docs ║${RESET}"
echo -e "${GREEN}║  Web Panel:      http://localhost:3000    ║${RESET}"
echo -e "${GREEN}║  NATS Monitor:   http://localhost:8222    ║${RESET}"
if [ "$PROFILE" = "monitoring" ] || [ "$PROFILE" = "all" ]; then
    echo -e "${GREEN}║  Kibana:         http://localhost:5601    ║${RESET}"
fi
if [ "$PROFILE" = "microservices" ] || [ "$PROFILE" = "all" ]; then
    echo -e "${GREEN}║  Ingestion gRPC: localhost:50051          ║${RESET}"
    echo -e "${GREEN}║  Enrollment:     localhost:50052          ║${RESET}"
fi
echo -e "${GREEN}╚══════════════════════════════════════════╝${RESET}"
echo ""
ok "SentinelAI is ready."
echo ""
echo -e "${DIM}  Useful commands:${RESET}"
echo -e "${DIM}    docker compose ps              — Service status${RESET}"
echo -e "${DIM}    docker compose logs -f backend  — Follow backend logs${RESET}"
echo -e "${DIM}    docker compose down             — Stop stack${RESET}"
echo -e "${DIM}    docker compose down -v          — Stop + destroy data${RESET}"
echo ""
