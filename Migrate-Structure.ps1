<#
.SYNOPSIS
    SentinelAI — Repository Restructure Migration Script

.DESCRIPTION
    Migrates the current flat SentinelAI_v3 repository layout into the
    SentinelAI_Distribution structure with clear separation of:
      - Windows/Linux endpoint artifacts
      - Infrastructure services
      - Docker/deployment configs
      - Documentation and tools

    Agent v2 is preserved alongside v1 until validated.

.PARAMETER DryRun
    Show what would be moved without actually doing it.

.PARAMETER TargetDir
    Destination root for the new layout.
    Defaults to SentinelAI_Distribution in the parent directory.

.EXAMPLE
    .\Migrate-Structure.ps1 -DryRun           # Preview changes
    .\Migrate-Structure.ps1                    # Execute migration
    .\Migrate-Structure.ps1 -TargetDir "D:\SentinelAI_Distribution"
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$DryRun,

    [string]$TargetDir = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# ── Resolve paths ────────────────────────────────────────────
$SourceRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not (Test-Path (Join-Path $SourceRoot "docker-compose.yml"))) {
    $SourceRoot = (Get-Location).Path
}
if (-not (Test-Path (Join-Path $SourceRoot "docker-compose.yml"))) {
    Write-Error "Run this script from the SentinelAI_v3 project root."
    exit 1
}

if ([string]::IsNullOrEmpty($TargetDir)) {
    $TargetDir = Join-Path (Split-Path -Parent $SourceRoot) "SentinelAI_Distribution"
}

# ── Helpers ──────────────────────────────────────────────────
function Write-Action([string]$verb, [string]$from, [string]$to) {
    $prefix = if ($DryRun) { "[DRY-RUN]" } else { "[MOVE]" }
    $color = if ($DryRun) { "Yellow" } else { "Green" }
    Write-Host "  $prefix " -ForegroundColor $color -NoNewline
    Write-Host "$verb: " -NoNewline
    Write-Host "$from" -ForegroundColor Cyan -NoNewline
    Write-Host " → " -NoNewline
    Write-Host "$to" -ForegroundColor White
}

function Ensure-Dir([string]$path) {
    if (-not $DryRun) {
        New-Item -ItemType Directory -Force -Path $path | Out-Null
    }
}

function Move-Item-Safe([string]$source, [string]$dest) {
    $srcPath = Join-Path $SourceRoot $source
    $dstPath = Join-Path $TargetDir $dest

    if (-not (Test-Path $srcPath)) {
        Write-Host "  [SKIP] " -ForegroundColor DarkGray -NoNewline
        Write-Host "Not found: $source" -ForegroundColor DarkGray
        return
    }

    Write-Action "Move" $source $dest

    if (-not $DryRun) {
        $dstParent = Split-Path -Parent $dstPath
        Ensure-Dir $dstParent
        Copy-Item -Path $srcPath -Destination $dstPath -Recurse -Force
    }
}

function Copy-File-Safe([string]$source, [string]$dest) {
    $srcPath = Join-Path $SourceRoot $source
    $dstPath = Join-Path $TargetDir $dest

    if (-not (Test-Path $srcPath)) {
        Write-Host "  [SKIP] " -ForegroundColor DarkGray -NoNewline
        Write-Host "Not found: $source" -ForegroundColor DarkGray
        return
    }

    Write-Action "Copy" $source $dest

    if (-not $DryRun) {
        $dstParent = Split-Path -Parent $dstPath
        Ensure-Dir $dstParent
        Copy-Item -Path $srcPath -Destination $dstPath -Force
    }
}

# ── Banner ───────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  SentinelAI — Repository Restructure Migration      ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Source: $SourceRoot" -ForegroundColor DarkGray
Write-Host "  Target: $TargetDir" -ForegroundColor DarkGray
if ($DryRun) {
    Write-Host "  Mode:   DRY RUN (no files will be moved)" -ForegroundColor Yellow
}
else {
    Write-Host "  Mode:   LIVE (files will be copied to target)" -ForegroundColor Green
}
Write-Host ""

# ── Create directory skeleton ────────────────────────────────
Write-Host "Creating directory structure..." -ForegroundColor White
$dirs = @(
    "Windows\Agent",
    "Windows\Agent-v2",
    "Windows\DesktopApp",
    "Linux\Agent",
    "Linux\Agent-v2",
    "Linux\App",
    "Infrastructure\Backend",
    "Infrastructure\Panel",
    "Infrastructure\Services\ingestion-gateway",
    "Infrastructure\Services\detection-engine",
    "Infrastructure\Services\enrichment-service",
    "Infrastructure\Services\enrollment-service",
    "Infrastructure\Docker",
    "Infrastructure\Config\elasticsearch",
    "Infrastructure\Config\nats",
    "Infrastructure\Proto",
    "Infrastructure\DeploymentScripts",
    "Docs",
    "Tools",
    ".github\workflows"
)

foreach ($d in $dirs) {
    $fullPath = Join-Path $TargetDir $d
    if ($DryRun) {
        Write-Host "  [DIR] $d" -ForegroundColor DarkGray
    }
    else {
        Ensure-Dir $fullPath
    }
}

Write-Host ""

# ============================================================
# Windows Endpoint Artifacts
# ============================================================
Write-Host "── Windows Endpoint ──" -ForegroundColor White
Move-Item-Safe "agent"                              "Windows\Agent"
Move-Item-Safe "docs\architecture\agent_v2"         "Windows\Agent-v2"
Move-Item-Safe "desktop"                            "Windows\DesktopApp"
Copy-File-Safe "deploy\windows\Install-SentinelAgent.ps1"  "Windows\Install.ps1"
Copy-File-Safe "deploy\windows\Uninstall-SentinelAgent.ps1" "Windows\Uninstall.ps1"
Copy-File-Safe "deploy\windows\agent.toml"          "Windows\Agent\agent.toml.windows"
Write-Host ""

# ============================================================
# Linux Endpoint Artifacts
# ============================================================
Write-Host "── Linux Endpoint ──" -ForegroundColor White
Move-Item-Safe "agent"                              "Linux\Agent"
Move-Item-Safe "docs\architecture\agent_v2"         "Linux\Agent-v2"
Copy-File-Safe "deploy\install_agent.sh"            "Linux\install_agent.sh"
Copy-File-Safe "deploy\agent.toml.template"         "Linux\Agent\agent.toml.template"
Copy-File-Safe "deploy\sentinel-agent.service"      "Linux\sentinel-agent.service"

# Placeholder for Linux desktop app
if (-not $DryRun) {
    $placeholder = Join-Path $TargetDir "Linux\App\README.md"
    if (-not (Test-Path $placeholder)) {
        Set-Content -Path $placeholder -Value @"
# SentinelAI Linux Desktop App

Placeholder directory for a future Linux desktop application.
Currently, the web panel (Infrastructure/Panel) serves as the primary UI.
"@
    }
}
else {
    Write-Host "  [DRY-RUN] Create: Linux\App\README.md (placeholder)" -ForegroundColor Yellow
}
Write-Host ""

# ============================================================
# Infrastructure
# ============================================================
Write-Host "── Infrastructure ──" -ForegroundColor White
Move-Item-Safe "backend"                            "Infrastructure\Backend"
Move-Item-Safe "panel"                              "Infrastructure\Panel"

# v2 Microservices (promoted from docs/architecture/services)
Move-Item-Safe "docs\architecture\services\ingestion-gateway"  "Infrastructure\Services\ingestion-gateway"
Move-Item-Safe "docs\architecture\services\detection-engine"   "Infrastructure\Services\detection-engine"
Move-Item-Safe "docs\architecture\services\enrichment-service" "Infrastructure\Services\enrichment-service"
Move-Item-Safe "docs\architecture\services\enrollment-service" "Infrastructure\Services\enrollment-service"

# Docker configs
Move-Item-Safe "docker"                             "Infrastructure\Docker"
Copy-File-Safe "docker-compose.yml"                 "Infrastructure\Docker\docker-compose.yml"
Copy-File-Safe ".env.example"                       "Infrastructure\Docker\.env.example"

# Also keep docker-compose.yml at root as a convenience redirect
Copy-File-Safe "docker-compose.yml"                 "docker-compose.yml"
Copy-File-Safe ".env.example"                       ".env.example"

# ES and NATS configs
Move-Item-Safe "docs\architecture\deployment\config\elasticsearch"  "Infrastructure\Config\elasticsearch"
Move-Item-Safe "docs\architecture\deployment\config\nats"           "Infrastructure\Config\nats"

# Proto files
Copy-File-Safe "shared\proto\sentinel.proto"                       "Infrastructure\Proto\sentinel.proto"
Copy-File-Safe "docs\architecture\proto\sentinel_v2.proto"         "Infrastructure\Proto\sentinel_v2.proto"
Copy-File-Safe "buf.yaml"                                          "Infrastructure\Proto\buf.yaml"
Copy-File-Safe "buf.gen.yaml"                                      "Infrastructure\Proto\buf.gen.yaml"

# Deployment scripts
Copy-File-Safe "deploy\install_agent.sh"                           "Infrastructure\DeploymentScripts\install_agent.sh"
Copy-File-Safe "deploy\windows\Install-SentinelAgent.ps1"          "Infrastructure\DeploymentScripts\Install-SentinelAgent.ps1"
Copy-File-Safe "deploy\windows\Uninstall-SentinelAgent.ps1"        "Infrastructure\DeploymentScripts\Uninstall-SentinelAgent.ps1"
Copy-File-Safe "Install-SentinelStack.ps1"                         "Infrastructure\DeploymentScripts\Install-SentinelStack.ps1"
Copy-File-Safe "install-stack.sh"                                  "Infrastructure\DeploymentScripts\install-stack.sh"
Write-Host ""

# ============================================================
# Documentation
# ============================================================
Write-Host "── Documentation ──" -ForegroundColor White
Move-Item-Safe "docs"                               "Docs"
Copy-File-Safe "README.md"                          "Docs\README.md"
Copy-File-Safe "deploy\README.md"                   "Docs\deploy-README.md"
Copy-File-Safe "deploy\windows\README.md"           "Docs\deploy-windows-README.md"
Write-Host ""

# ============================================================
# Tools (loose scripts)
# ============================================================
Write-Host "── Tools (utility scripts) ──" -ForegroundColor White
$scripts = @(
    "gen_agents.py", "gen_analysis.py", "gen_executor.py",
    "gen_fix_analysis.py", "gen_frontend.py", "gen_frontend2.py",
    "gen_llm_engine.py", "gen_main_update.py", "gen_main.py",
    "gen_osint_routes.py", "gen_osint_service.py", "gen_transport.py",
    "write_api.py", "write_dashboard.py", "write_layout_fix.py", "write_panel.py",
    "test_all.py", "test_auth_full.py", "test_auth.py",
    "test_register.py", "test_uuid.py"
)
foreach ($s in $scripts) {
    Copy-File-Safe $s "Tools\$s"
}
Write-Host ""

# ============================================================
# CI/CD + Proto
# ============================================================
Write-Host "── CI/CD ──" -ForegroundColor White
Move-Item-Safe ".github"                            ".github"
Copy-File-Safe "buf.yaml"                           "buf.yaml"
Copy-File-Safe "buf.gen.yaml"                       "buf.gen.yaml"
Move-Item-Safe "scripts"                            "scripts"
Write-Host ""

# ============================================================
# Root files
# ============================================================
Write-Host "── Root files ──" -ForegroundColor White
Copy-File-Safe ".gitignore"                         ".gitignore"
Copy-File-Safe "README.md"                          "README.md"
Copy-File-Safe "Install-SentinelStack.ps1"          "Install-SentinelStack.ps1"
Copy-File-Safe "install-stack.sh"                   "install-stack.sh"
Write-Host ""

# ── Summary ──────────────────────────────────────────────────
Write-Host "══════════════════════════════════════════════════════" -ForegroundColor Cyan
if ($DryRun) {
    Write-Host "  DRY RUN complete. No files were moved." -ForegroundColor Yellow
    Write-Host "  Re-run without -DryRun to execute the migration." -ForegroundColor Yellow
}
else {
    Write-Host "  Migration complete!" -ForegroundColor Green
    Write-Host "  New structure created at: $TargetDir" -ForegroundColor Green
    Write-Host ""
    Write-Host "  IMPORTANT: The original files are still in place." -ForegroundColor Yellow
    Write-Host "  Verify the new structure, then delete the old layout manually." -ForegroundColor Yellow
}
Write-Host "══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
