# SentinelAI — AI-Powered Endpoint Detection & Response Platform

<p align="center">
  <strong>Autonomous Threat Detection · LLM-Powered Analysis · Cross-Platform Agents</strong>
</p>

---

## Overview

SentinelAI is an open-source, AI-augmented EDR platform that combines traditional endpoint telemetry with Large Language Model (LLM) intelligence to detect, analyze, and respond to cybersecurity threats in real-time.

### Key Capabilities

- **Cross-Platform Agent** — Lightweight Rust-based agent for Windows, Linux, macOS, and Android
- **AI Threat Analysis** — LLM-powered threat correlation, anomaly detection, and natural language investigation
- **MITRE ATT&CK Mapping** — Automatic technique/tactic classification for every alert
- **Vulnerability Enrichment** — Real-time CVE/NVD database integration
- **Live Telemetry Dashboard** — Real-time process, network, and filesystem monitoring via WebSocket
- **Autonomous Response** — Configurable automated containment actions (process kill, network isolation, quarantine)
- **Multi-Tenant** — Manage thousands of endpoints from a single panel
- **Desktop & Web** — Tauri-powered desktop app + Next.js web panel

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        SentinelAI Platform                       │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐    ┌──────────────────┐    ┌────────────────┐  │
│  │  Web Panel   │    │   Desktop App    │    │  Mobile App    │  │
│  │  (Next.js)   │    │   (Tauri 2.0)    │    │  (Future)      │  │
│  └──────┬───────┘    └───────┬──────────┘    └───────┬────────┘  │
│         │                    │                       │           │
│         └────────────┬───────┘───────────────────────┘           │
│                      ▼                                           │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              Backend API (FastAPI + Python)                │   │
│  │  ┌──────────┐ ┌───────────┐ ┌──────────┐ ┌───────────┐  │   │
│  │  │ REST API │ │ WebSocket │ │ Auth/JWT │ │ gRPC Svc  │  │   │
│  │  └──────────┘ └───────────┘ └──────────┘ └───────────┘  │   │
│  │  ┌──────────────────────────────────────────────────┐    │   │
│  │  │            Intelligence Services                  │    │   │
│  │  │  ┌─────────┐ ┌──────────┐ ┌───────────────────┐ │    │   │
│  │  │  │ LLM     │ │ Threat   │ │ MITRE ATT&CK      │ │    │   │
│  │  │  │ Engine  │ │ Analyzer │ │ Correlation Engine │ │    │   │
│  │  │  └─────────┘ └──────────┘ └───────────────────┘ │    │   │
│  │  │  ┌─────────┐ ┌──────────┐ ┌───────────────────┐ │    │   │
│  │  │  │ NVD/CVE │ │ YARA     │ │ Behavioral        │ │    │   │
│  │  │  │ Lookup  │ │ Rules    │ │ Analytics         │ │    │   │
│  │  │  └─────────┘ └──────────┘ └───────────────────┘ │    │   │
│  │  └──────────────────────────────────────────────────┘    │   │
│  └──────────────────────────┬───────────────────────────────┘   │
│                             │                                    │
│  ┌──────────────────────────┼───────────────────────────────┐   │
│  │         Data Layer       │                                │   │
│  │  ┌──────────┐ ┌─────────┴──┐ ┌─────────────────────┐    │   │
│  │  │PostgreSQL│ │   Redis    │ │   Elasticsearch      │    │   │
│  │  │(Metadata)│ │(Cache/PubS)│ │   (Log Search)       │    │   │
│  │  └──────────┘ └────────────┘ └─────────────────────┘    │   │
│  └──────────────────────────────────────────────────────────┘   │
│                             ▲                                    │
│                             │  TLS / mTLS                        │
│         ┌───────────────────┼────────────────────┐               │
│         ▼                   ▼                    ▼               │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────┐       │
│  │ Agent       │   │ Agent       │   │ Agent           │       │
│  │ (Windows)   │   │ (Linux)     │   │ (macOS/Android) │       │
│  │ Rust Binary │   │ Rust Binary │   │ Rust Binary     │       │
│  └─────────────┘   └─────────────┘   └─────────────────┘       │
└──────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
sentinelai/
├── agent/                  # Rust cross-platform endpoint agent
│   ├── src/
│   │   ├── collector/      # Telemetry collectors (process, fs, net)
│   │   ├── detection/      # Local detection engine (YARA, rules)
│   │   ├── transport/      # Backend communication (REST, gRPC)
│   │   └── main.rs
│   └── Cargo.toml
├── backend/                # Python FastAPI backend
│   ├── app/
│   │   ├── api/routes/     # REST API endpoints
│   │   ├── core/           # Config, security, database
│   │   ├── models/         # SQLAlchemy ORM models
│   │   ├── schemas/        # Pydantic validation schemas
│   │   └── services/       # Business logic & AI services
│   └── pyproject.toml
├── panel/                  # Next.js web dashboard
│   ├── src/
│   │   ├── app/            # App Router pages
│   │   ├── components/     # React components
│   │   └── lib/            # Utilities & API client
│   └── package.json
├── desktop/                # Tauri desktop application
│   └── src-tauri/
├── shared/                 # Shared protocol definitions
│   └── proto/              # Protobuf schemas
├── docker-compose.yml      # Infrastructure stack
└── docs/                   # Documentation
```

---

## Quick Start

### Prerequisites
- **Rust** 1.75+ (agent)
- **Python** 3.11+ (backend)
- **Node.js** 20+ (panel)
- **Docker & Docker Compose** (infrastructure)

### 1. Start Infrastructure
```bash
docker-compose up -d
```

### 2. Start Backend
```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

### 3. Start Web Panel
```bash
cd panel
npm install
npm run dev
```

### 4. Build & Run Agent
```bash
cd agent
cargo build --release
./target/release/sentinel-agent --config agent.toml
```

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Agent | Rust + Tokio | Cross-platform endpoint telemetry |
| Backend | Python FastAPI | REST API, WebSocket, business logic |
| AI/ML | LangChain + OpenAI/Anthropic | Threat analysis, NL investigation |
| Web Panel | Next.js 14 + TypeScript + Tailwind | Real-time dashboard |
| Desktop | Tauri 2.0 | Native desktop app (Win/Mac/Linux) |
| Database | PostgreSQL | Relational data, agent metadata |
| Cache | Redis | Real-time pub/sub, session cache |
| Search | Elasticsearch | Log search, full-text telemetry |
| Protocol | Protocol Buffers | Agent ↔ Backend communication |

---

## License

MIT License — See [LICENSE](LICENSE) for details.
