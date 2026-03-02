# SentinelAI Architecture Document

## 1. System Overview

SentinelAI is a modular, AI-augmented Endpoint Detection & Response (EDR) platform
designed for real-time threat detection, investigation, and autonomous response.

### Design Principles

1. **Defense in Depth** — Multiple detection layers (signature, behavioral, AI)
2. **Zero Trust Agent Communication** — mTLS between all agents and backend
3. **Offline Resilience** — Agents operate independently when disconnected
4. **LLM-Augmented, Not LLM-Dependent** — AI enhances but never replaces deterministic rules
5. **Extensible Plugin Architecture** — Custom collectors, detectors, and response actions

---

## 2. Agent Architecture (Rust)

### 2.1 Collectors
Each collector runs as an independent async task reporting to a local event bus:

| Collector | Data | Platform |
|-----------|------|----------|
| `ProcessCollector` | Process creation/termination, command lines, parent chains | All |
| `FilesystemCollector` | File create/modify/delete, hash computation | All |
| `NetworkCollector` | TCP/UDP connections, DNS queries, socket states | All |
| `SystemInfoCollector` | CPU, memory, disk, OS version, hostname | All |
| `RegistryCollector` | Registry key changes (HKLM, HKCU) | Windows |
| `SyslogCollector` | Syslog/journald events | Linux/macOS |
| `AuthCollector` | Login events, privilege escalation | All |

### 2.2 Local Detection Engine
Before sending telemetry to the backend, the agent runs local detection:

- **YARA Scanner** — Scans new/modified files against YARA rule sets
- **Sigma Rules** — Evaluates process/network events against Sigma rules
- **Behavioral Rules** — Simple heuristics (e.g., process injection patterns)
- **IOC Matching** — Hash/IP/domain matching against cached IOC feeds

### 2.3 Transport Layer
- Primary: HTTPS REST with JSON payloads (simple, debuggable)
- Secondary: gRPC with Protobuf (high-throughput telemetry streaming)
- Fallback: Local disk queue when backend is unreachable
- Authentication: mTLS with per-agent certificates

### 2.4 Agent Lifecycle
```
Install → Register → Heartbeat Loop → Collect → Detect → Report → [Response Actions]
                         ↑                                              │
                         └──────────── Policy Updates ←─────────────────┘
```

---

## 3. Backend Architecture (Python FastAPI)

### 3.1 API Layer
- **REST API** — CRUD for agents, alerts, users, policies
- **WebSocket** — Real-time telemetry streaming to dashboard
- **gRPC Service** — High-throughput agent telemetry ingestion

### 3.2 Intelligence Services

#### LLM Engine (`services/llm_engine.py`)
- Supports multiple providers: OpenAI, Anthropic, local (Ollama)
- Structured output for consistent threat classification
- Context-aware analysis with conversation memory
- Rate limiting and cost tracking

#### Threat Analyzer (`services/threat_analyzer.py`)
- Combines LLM analysis with deterministic rules
- Multi-stage pipeline: Triage → Enrich → Correlate → Classify → Respond
- Confidence scoring with explainability

#### MITRE ATT&CK Integration (`services/mitre_attack.py`)
- Maps alerts to ATT&CK techniques and tactics
- Attack chain reconstruction
- Coverage gap analysis

#### Vulnerability Database (`services/vuln_database.py`)
- NVD/CVE real-time lookup and caching
- Software inventory correlation
- CVSS scoring and prioritization
- Exploit availability tracking (ExploitDB, Metasploit)

#### Correlation Engine (`services/correlation_engine.py`)
- Cross-agent event correlation
- Temporal pattern matching
- Kill chain progression detection
- Alert deduplication and grouping

### 3.3 Data Models

```
User ──┬── manages ──→ AgentGroup ──┬── contains ──→ Agent
       │                             │
       └── views ───→ Alert ←───── triggers ←── Event
                        │
                        ├── mapped_to ──→ MitreTechnique
                        ├── enriched_by → CveRecord
                        └── analyzed_by → LlmAnalysis
```

---

## 4. Web Panel Architecture (Next.js)

### 4.1 Pages
- `/dashboard` — Overview: agent count, alert severity breakdown, threat map
- `/agents` — Agent inventory, status, last seen, OS distribution
- `/agents/[id]` — Individual agent detail: live telemetry, installed software
- `/alerts` — Alert queue with filtering, sorting, bulk actions
- `/alerts/[id]` — Alert detail: timeline, MITRE mapping, LLM analysis
- `/analysis` — AI investigation: natural language query interface
- `/hunting` — Threat hunting: query across all telemetry
- `/policies` — Detection policies and response playbooks
- `/settings` — User management, API keys, integrations

### 4.2 Real-Time Features
- WebSocket connection for live telemetry updates
- Server-Sent Events for alert notifications
- Optimistic UI updates with React Query

---

## 5. Desktop App Architecture (Tauri 2.0)

Shares the Next.js panel frontend, wrapped in Tauri for:
- Native OS notifications for critical alerts
- System tray icon with quick status
- Local agent management (install/configure agent on same machine)
- Offline dashboard caching

---

## 6. Security Considerations

1. **Agent-Backend Communication** — mTLS with certificate pinning
2. **API Authentication** — JWT with refresh tokens, RBAC
3. **Data at Rest** — AES-256 encryption for sensitive telemetry
4. **Data in Transit** — TLS 1.3 minimum
5. **LLM Data Privacy** — No PII sent to external LLMs; local LLM option
6. **Agent Integrity** — Signed binaries, self-integrity checks
7. **Audit Logging** — All admin actions logged immutably

---

## 7. Deployment Options

### Development
```bash
docker-compose up -d  # PostgreSQL, Redis, Elasticsearch
cd backend && uvicorn app.main:app --reload
cd panel && npm run dev
cd agent && cargo run
```

### Production
- Kubernetes with Helm charts
- Horizontal scaling of backend API
- Elasticsearch cluster for telemetry
- Redis Sentinel for HA caching
- Agent auto-update via backend policy push
