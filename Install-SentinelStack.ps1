<#
.SYNOPSIS
    SentinelAI — One-Click Infrastructure Installer (Windows)

.DESCRIPTION
    Builds and starts the complete SentinelAI backend stack using Docker Compose.
    Checks prerequisites, bootstraps configuration, builds containers,
    waits for health checks, and displays access information.

.PARAMETER Profile
    Docker Compose profile to activate.
    Options: core (default), monitoring, microservices, all

.PARAMETER Rebuild
    Force rebuild of all container images.

.PARAMETER Down
    Stop and remove the running stack (keeps volumes).

.PARAMETER Nuke
    Stop and remove the running stack AND destroy all data volumes.

.EXAMPLE
    .\Install-SentinelStack.ps1
    .\Install-SentinelStack.ps1 -Profile all
    .\Install-SentinelStack.ps1 -Rebuild
    .\Install-SentinelStack.ps1 -Down
#>

[CmdletBinding()]
param(
    [ValidateSet("core", "monitoring", "microservices", "all")]
    [string]$Profile = "core",

    [switch]$Rebuild,
    [switch]$Down,
    [switch]$Nuke
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# ── Helpers ──────────────────────────────────────────────────
function Write-Banner {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║  SentinelAI — Infrastructure Installer   ║" -ForegroundColor Cyan
    Write-Host "  ║  EDR Platform Stack (Docker Compose)     ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step([string]$msg) {
    Write-Host "[*] " -ForegroundColor Green -NoNewline
    Write-Host $msg
}

function Write-Warn([string]$msg) {
    Write-Host "[!] " -ForegroundColor Yellow -NoNewline
    Write-Host $msg
}

function Write-Err([string]$msg) {
    Write-Host "[✗] " -ForegroundColor Red -NoNewline
    Write-Host $msg
}

function Write-Ok([string]$msg) {
    Write-Host "[✓] " -ForegroundColor Green -NoNewline
    Write-Host $msg
}

# ── Locate project root (where docker-compose.yml lives) ────
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = $ScriptDir
# If this script is inside a subfolder, walk up
if (-not (Test-Path (Join-Path $ProjectRoot "docker-compose.yml"))) {
    $ProjectRoot = Split-Path -Parent $ScriptDir
}
if (-not (Test-Path (Join-Path $ProjectRoot "docker-compose.yml"))) {
    Write-Err "Cannot find docker-compose.yml. Run this script from the project root."
    exit 1
}

Push-Location $ProjectRoot

try {
    Write-Banner

    # ── Step 1: Check Docker ─────────────────────────────────
    Write-Step "Checking Docker Desktop..."
    try {
        $dockerVersion = docker --version 2>&1
        Write-Ok "Docker found: $dockerVersion"
    }
    catch {
        Write-Err "Docker is not installed or not in PATH."
        Write-Warn "Download Docker Desktop from: https://www.docker.com/products/docker-desktop/"
        exit 1
    }

    # ── Step 2: Check Docker Compose v2 ──────────────────────
    Write-Step "Checking Docker Compose..."
    try {
        $composeVersion = docker compose version 2>&1
        Write-Ok "Docker Compose found: $composeVersion"
    }
    catch {
        Write-Err "Docker Compose v2 is not available."
        Write-Warn "Ensure Docker Desktop is updated (Compose v2 is built-in)."
        exit 1
    }

    # ── Step 3: Check Docker is running ──────────────────────
    Write-Step "Checking Docker daemon..."
    try {
        docker info 2>&1 | Out-Null
        Write-Ok "Docker daemon is running."
    }
    catch {
        Write-Err "Docker daemon is not running. Please start Docker Desktop."
        exit 1
    }

    # ── Handle -Down / -Nuke ─────────────────────────────────
    if ($Down) {
        Write-Step "Stopping SentinelAI stack (keeping data volumes)..."
        docker compose down
        Write-Ok "Stack stopped. Data volumes preserved."
        exit 0
    }

    if ($Nuke) {
        Write-Warn "This will DESTROY all SentinelAI data volumes (databases, indices, certs)!"
        $confirm = Read-Host "Type 'YES' to confirm"
        if ($confirm -ne "YES") {
            Write-Step "Aborted."
            exit 0
        }
        docker compose --profile all down -v
        Write-Ok "Stack stopped and all data volumes destroyed."
        exit 0
    }

    # ── Step 4: Bootstrap .env ───────────────────────────────
    Write-Step "Checking environment configuration..."
    if (-not (Test-Path ".env")) {
        if (Test-Path ".env.example") {
            Copy-Item ".env.example" ".env"
            Write-Ok "Created .env from .env.example"
            Write-Warn "Review and update secrets in .env before production use!"
        }
        else {
            Write-Warn "No .env.example found. Proceeding with Docker Compose defaults."
        }
    }
    else {
        Write-Ok ".env file already exists."
    }

    # ── Step 5: Build compose command ────────────────────────
    $composeArgs = @("compose")
    if ($Profile -ne "core") {
        $composeArgs += "--profile"
        $composeArgs += $Profile
    }
    $composeArgs += "up"
    $composeArgs += "-d"
    if ($Rebuild) {
        $composeArgs += "--build"
        $composeArgs += "--force-recreate"
    }
    else {
        $composeArgs += "--build"
    }

    Write-Step "Starting SentinelAI stack (profile: $Profile)..."
    Write-Host "  Command: docker $($composeArgs -join ' ')" -ForegroundColor DarkGray
    & docker @composeArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Docker Compose failed with exit code $LASTEXITCODE"
        exit 1
    }

    # ── Step 6: Wait for health checks ───────────────────────
    Write-Step "Waiting for services to become healthy..."
    $timeout = 180  # seconds
    $elapsed = 0
    $interval = 5

    while ($elapsed -lt $timeout) {
        Start-Sleep -Seconds $interval
        $elapsed += $interval

        $status = docker compose ps --format json 2>&1 | ConvertFrom-Json -ErrorAction SilentlyContinue
        if (-not $status) { continue }

        # Handle both array and single object
        if ($status -isnot [array]) { $status = @($status) }

        $total = $status.Count
        $healthy = ($status | Where-Object { $_.Health -eq "healthy" -or $_.State -eq "running" }).Count

        Write-Host "`r  [$elapsed/${timeout}s] $healthy/$total services ready..." -NoNewline -ForegroundColor DarkGray

        if ($healthy -ge $total -and $total -gt 0) {
            Write-Host ""
            Write-Ok "All $total services are running!"
            break
        }
    }

    if ($elapsed -ge $timeout) {
        Write-Host ""
        Write-Warn "Timeout reached. Some services may still be starting."
        Write-Warn "Run 'docker compose ps' to check status."
    }

    # ── Step 7: Print status table ───────────────────────────
    Write-Host ""
    Write-Step "Service Status:"
    Write-Host ""
    docker compose ps
    Write-Host ""

    # ── Step 8: Show logs (brief) ────────────────────────────
    Write-Step "Recent logs (last 15 lines):"
    Write-Host ""
    docker compose logs --tail 15
    Write-Host ""

    # ── Step 9: Print access URLs ────────────────────────────
    Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║          SentinelAI Access Points        ║" -ForegroundColor Green
    Write-Host "  ╠══════════════════════════════════════════╣" -ForegroundColor Green
    Write-Host "  ║  Backend API:    http://localhost:8000    ║" -ForegroundColor Green
    Write-Host "  ║  API Docs:       http://localhost:8000/api/docs ║" -ForegroundColor Green
    Write-Host "  ║  Web Panel:      http://localhost:3000    ║" -ForegroundColor Green
    Write-Host "  ║  NATS Monitor:   http://localhost:8222    ║" -ForegroundColor Green
    if ($Profile -eq "monitoring" -or $Profile -eq "all") {
        Write-Host "  ║  Kibana:         http://localhost:5601    ║" -ForegroundColor Green
    }
    if ($Profile -eq "microservices" -or $Profile -eq "all") {
        Write-Host "  ║  Ingestion gRPC: localhost:50051          ║" -ForegroundColor Green
        Write-Host "  ║  Enrollment:     localhost:50052          ║" -ForegroundColor Green
    }
    Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Ok "SentinelAI is ready."
    Write-Host ""
    Write-Host "  Useful commands:" -ForegroundColor DarkGray
    Write-Host "    docker compose ps              — Service status" -ForegroundColor DarkGray
    Write-Host "    docker compose logs -f backend  — Follow backend logs" -ForegroundColor DarkGray
    Write-Host "    docker compose down             — Stop stack" -ForegroundColor DarkGray
    Write-Host "    docker compose down -v          — Stop + destroy data" -ForegroundColor DarkGray
    Write-Host ""
}
finally {
    Pop-Location
}
