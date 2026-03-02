# SentinelAI — Threat Model & Security Architecture

> Version 2.0 · Companion to `00-ARCHITECTURE-REDESIGN.md` Part 5

---

## 1. System Boundary & Trust Zones

```
┌──────────────────────────────────────────────────────────────────────┐
│ ZONE 0 — Endpoint Kernel                                             │
│  ┌────────────────────┐                                              │
│  │ ETW Provider / eBPF│  ← tamper target #1                         │
│  └────────┬───────────┘                                              │
├───────────┼──────────────────────────────────────────────────────────┤
│ ZONE 1 — Endpoint User-Space (Agent Process)                         │
│  ┌────────▼───────────┐  ┌──────────┐  ┌─────────┐                  │
│  │ Collector Registry  │→ │ Pipeline │→ │Transport│── mTLS ──►       │
│  └────────────────────┘  └──────────┘  └─────────┘                  │
│  ┌────────────────────┐  ┌──────────────────────┐                    │
│  │ Self-Protection     │  │ Local Detection      │                    │
│  └────────────────────┘  └──────────────────────┘                    │
├──────────────────────────────────────────────────────────────────────┤
│ ZONE 2 — Network Transit (mTLS encrypted, certificate-pinned)        │
├──────────────────────────────────────────────────────────────────────┤
│ ZONE 3 — Backend DMZ (Ingestion Gateway)                             │
│  ┌────────────────────────┐                                          │
│  │ gRPC termination       │  ← exposed to internet                   │
│  │ Certificate validation │                                          │
│  │ Rate limiting          │                                          │
│  └───────────┬────────────┘                                          │
├──────────────┼───────────────────────────────────────────────────────┤
│ ZONE 4 — Backend Internal (NATS, Detection, Storage, API)            │
│  ┌───────────▼────────────┐  ┌──────────┐  ┌────────┐  ┌─────┐     │
│  │ NATS JetStream         │→ │ Detection│→ │Storage │→ │ API │     │
│  └────────────────────────┘  └──────────┘  └────────┘  └─────┘     │
│  ┌────────────────────────┐  ┌──────────┐                            │
│  │ Enrollment Service     │  │ AI Svc   │                            │
│  └────────────────────────┘  └──────────┘                            │
├──────────────────────────────────────────────────────────────────────┤
│ ZONE 5 — Data Plane (PostgreSQL, Elasticsearch, S3/MinIO)            │
├──────────────────────────────────────────────────────────────────────┤
│ ZONE 6 — Management Plane (Panel UI, Admin API)                      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 2. Threat Actors

| Actor           | Capability  | Motivation            | Access Level                     |
|-----------------|-------------|------------------------|----------------------------------|
| **APT / Nation-State** | High   | Persistent access, espionage | Kernel + userspace + network |
| **Ransomware Operator** | Medium | Disable EDR before encryption | Userspace + maybe kernel    |
| **Red Team / Pentester** | Medium | Prove EDR bypass       | Userspace                        |
| **Insider Threat**      | Medium | Data exfiltration, sabotage | Backend access, agent policy  |
| **Supply Chain**         | High  | Backdoor agent updates | Build pipeline                    |
| **Noisy Attacker**       | Low   | Flood/DoS              | Network                          |

---

## 3. STRIDE Threat Matrix

### 3.1 Agent (Zone 1)

| # | STRIDE | Threat | Attack Vector | Impact | Mitigation | Residual Risk |
|---|--------|--------|---------------|--------|------------|---------------|
| A1 | **T** Tampering | Kill agent process | `taskkill /F`, `kill -9` | Telemetry blackout | PPL on Windows; BPF-LSM `task_kill` hook on Linux; watchdog service with `RestartSec=0` | Medium — kernel-level attacker can still unload PPL |
| A2 | **T** Tampering | Patch agent binary on disk | Overwrite sentinel-agent.exe | Backdoored agent | Binary hash verification on startup + periodic; PPL prevents write while running; immutable deploy | Low |
| A3 | **T** Tampering | Unhook ETW providers | `NtTraceControl` patch, provider disable | Blind to process/file events | Agent monitors its own ETW session health via `EventTraceProperties`; reports provider drop as tamper event | Medium — kernel patch can bypass |
| A4 | **T** Tampering | Unload eBPF programs | `bpf(BPF_PROG_DETACH)` | Blind to kernel events | BPF-LSM prevents unauthorized detach; agent monitors `/sys/kernel/debug/tracing/enabled_functions` | Medium |
| A5 | **S** Spoofing | Inject false telemetry | Compromise another process, send fake events to agent pipe | Poisoned detection | Agent accepts events only from its own kernel providers (ETW session handle / eBPF ringbuf fd); no user-space intake | Low |
| A6 | **I** Info Disclosure | Read agent config / certs | File system access to cert store | mTLS impersonation | Certs stored in OS keychain (Windows DPAPI, Linux kernel keyring); file permissions 0600 | Low |
| A7 | **D** DoS | Flood agent with events | Trigger massive file I/O, process spawns | Pipeline overload, event drop | Backpressure: bounded channels → aggregation → sampling; disk buffer absorbs bursts | Low — events drop but agent survives |
| A8 | **E** Elevation | Exploit agent vulnerability | Memory corruption in event parsing | Kernel access via PPL process | Rust memory safety; `#[deny(unsafe_code)]` in pipeline modules; fuzzing CI | Low |

### 3.2 Transport (Zone 2)

| # | STRIDE | Threat | Attack Vector | Impact | Mitigation | Residual Risk |
|---|--------|--------|---------------|--------|------------|---------------|
| T1 | **S** Spoofing | MitM backend endpoint | DNS hijack, BGP hijack | Agent sends telemetry to attacker | mTLS with certificate pinning (agent pins backend CA fingerprint); TOFU on enrollment | Low |
| T2 | **T** Tampering | Modify events in transit | Network tap + inject | Corrupted telemetry | TLS 1.3 AEAD encryption; per-batch HMAC in protobuf envelope | Very Low |
| T3 | **I** Info Disclosure | Intercept telemetry | Passive network capture | Endpoint data leaked | TLS 1.3 forward secrecy; no plaintext fallback | Very Low |
| T4 | **R** Repudiation | Agent denies sending event | Claim event was fabricated | Forensic integrity | Per-agent certificate identity; sequence numbers with server-side gap detection | Low |
| T5 | **D** DoS | Block agent→backend traffic | Firewall, DNS sinkhole | Telemetry blackout | Agent detects disconnect → buffers to local redb (72h capacity); alerts on reconnect gap | Low — bounded by disk space |

### 3.3 Backend (Zones 3–5)

| # | STRIDE | Threat | Attack Vector | Impact | Mitigation | Residual Risk |
|---|--------|--------|---------------|--------|------------|---------------|
| B1 | **S** Spoofing | Rogue agent enrollment | Stolen enrollment token | Unauthorized agent in tenant | One-time enrollment tokens with 5-minute TTL; token bound to machine hardware fingerprint | Low |
| B2 | **T** Tampering | Modify detection rules | Compromise API service | Attacker disables their detection | Rule changes require signed payload from admin with MFA; audit trail in append-only log | Low |
| B3 | **T** Tampering | Modify stored telemetry | Compromise ES/PG | Forensic tampering | ES indices are append-only (no update/delete API exposed); PG has row-level audit triggers | Medium — DB admin can still modify |
| B4 | **I** Info Disclosure | Tenant data cross-leak | Multi-tenant query bug | Data breach across tenants | Mandatory `tenant_id` filter injected at query layer (not user-controllable); ES index-per-tenant for large tenants | Low |
| B5 | **D** DoS | Event flood from compromised agent | Replay or amplify events | Backend overload | Per-agent rate limit at ingestion gateway (configurable, default 500 events/sec); NATS per-subject rate limits | Low |
| B6 | **D** DoS | NATS partition or crash | Network split, OOM | Event processing halt | NATS clustering (3 nodes); JetStream replication factor 3; circuit breaker in ingestion gateway | Low |
| B7 | **E** Elevation | Exploit ingestion gateway | gRPC deserialization vuln | Backend access | Ingestion gateway is isolated container; minimal permissions; protobuf strict parsing; no dynamic fields | Low |

### 3.4 Management Plane (Zone 6)

| # | STRIDE | Threat | Attack Vector | Impact | Mitigation | Residual Risk |
|---|--------|--------|---------------|--------|------------|---------------|
| M1 | **S** Spoofing | Stolen admin credentials | Phishing, credential stuffing | Full platform access | MFA mandatory; short-lived JWT (15min); refresh token rotation; IP allowlisting | Low |
| M2 | **T** Tampering | Modify agent policy to disable collection | Admin panel manipulation | Endpoint blinding | Policy changes logged to immutable audit trail; require 2-person approval for high-impact changes (kill collection) | Low |
| M3 | **I** Info Disclosure | Panel XSS leaks session | Reflected/stored XSS | Session hijack | CSP headers; HttpOnly + Secure + SameSite cookies; React auto-escaping; regular SAST | Low |

---

## 4. Attack Trees

### 4.1 Goal: Blind EDR on a Single Endpoint

```
Blind EDR
├── Kill agent process
│   ├── taskkill /F /IM sentinel-agent.exe
│   │   └── BLOCKED by PPL (Windows) / BPF-LSM (Linux)
│   ├── Use kernel driver to terminate PPL
│   │   └── Requires vulnerable signed driver (BYOVD)
│   │       └── MITIGATED by HVCI + driver blocklist
│   └── Exploit agent vulnerability for self-termination
│       └── MITIGATED by Rust memory safety + fuzzing
│
├── Disable telemetry providers
│   ├── Disable ETW session via NtTraceControl
│   │   └── DETECTED by ETW health monitoring → tamper event
│   ├── Unload eBPF programs
│   │   └── BLOCKED by BPF-LSM
│   └── Corrupt ETW provider registration
│       └── DETECTED by periodic provider enumeration
│
├── Block network transport
│   ├── Firewall rule blocking backend IP
│   │   └── MITIGATED by local disk buffer (72h); tamper event on disconnect
│   ├── DNS poisoning of backend hostname
│   │   └── MITIGATED by certificate pinning (connection will fail cleanly)
│   └── Proxy/MITM to drop events silently
│       └── DETECTED by backend gap detection (missing sequence numbers)
│
└── Evade detection rules
    ├── Encode/obfuscate commands
    │   └── MITIGATED by command-line deobfuscation in enrichment service
    ├── Use LOLBins for lateral movement
    │   └── DETECTED by behavioral correlation rules
    └── Timestomp to evade time-based correlation
        └── MITIGATED by monotonic_ns timestamps (cannot be stomped)
```

### 4.2 Goal: Exfiltrate Data from Backend

```
Exfiltrate backend data
├── Compromise API service
│   ├── Exploit FastAPI vulnerability
│   │   └── MITIGATED by WAF, dependency scanning, minimal attack surface
│   ├── SQL injection on PostgreSQL
│   │   └── MITIGATED by parameterized queries (asyncpg), no raw SQL
│   └── SSRF to internal services
│       └── MITIGATED by network segmentation (API cannot reach ES directly)
│
├── Compromise ingestion gateway
│   ├── Send malformed protobuf
│   │   └── MITIGATED by strict protobuf parsing, no dynamic fields
│   └── Exploit gRPC vulnerability
│       └── MITIGATED by tonic/hyper with regular updates
│
├── Direct database access
│   ├── Compromise ES node
│   │   └── MITIGATED by no public exposure, mTLS between services, encryption at rest
│   └── Compromise PG
│       └── MITIGATED by scram-sha-256, network isolation, encrypted storage
│
└── Compromise NATS
    ├── Subscribe to telemetry stream
    │   └── BLOCKED by NATS account isolation (STORAGE account cannot read TELEMETRY_RAW)
    └── Extract JetStream file store
        └── MITIGATED by filesystem encryption, container isolation
```

---

## 5. Enrollment Security Deep-Dive

### 5.1 Flow

```
Admin                  Backend (Enrollment Svc)              Agent
  │                         │                                  │
  │── Generate Token ──────►│                                  │
  │   (tenant_id, role,     │                                  │
  │    hardware_fingerprint,│                                  │
  │    expires_in: 5min)    │                                  │
  │◄── Token ──────────────│                                  │
  │                         │                                  │
  │── Deliver token to ─────────────────────────────────────►│
  │   endpoint (out-of-band)│                                  │
  │                         │                                  │
  │                         │◄── EnrollmentRequest ───────────│
  │                         │    (token, CSR, hw_fingerprint)  │
  │                         │                                  │
  │                         │── Validate:                      │
  │                         │   1. Token not expired           │
  │                         │   2. Token not already used      │
  │                         │   3. hw_fingerprint matches      │
  │                         │   4. CSR key size ≥ 2048         │
  │                         │                                  │
  │                         │── Sign CSR with tenant sub-CA ──►│
  │                         │                                  │
  │                         │── EnrollmentResponse ──────────►│
  │                         │   (signed_cert, ca_chain,        │
  │                         │    initial_policy,               │
  │                         │    cert_renewal_before)          │
  │                         │                                  │
```

### 5.2 Token Security Properties

| Property | Value | Rationale |
|----------|-------|-----------|
| Format | UUID v4 + HMAC-SHA256 | Unguessable, tamper-evident |
| TTL | 5 minutes | Minimize window for token theft |
| Single-use | Yes (marked consumed on first use) | Prevent replay |
| Hardware binding | SHA-256(SMBIOS UUID ∥ MAC addresses ∥ disk serial) | Prevent token migration to different machine |
| Storage | Argon2id hash in PostgreSQL | Prevent DB dump → token recovery |

### 5.3 Certificate Lifecycle

| Phase | Timing | Mechanism |
|-------|--------|-----------|
| Issuance | Enrollment | Agent generates RSA-2048 or ECDSA-P256 keypair; backend signs CSR |
| Renewal | 7 days before expiry | Agent sends `CertificateRenewalRequest` with current cert; backend issues new cert |
| Rotation | Immediate on renewal | Agent atomically swaps cert in memory; no connection drop |
| Revocation | On agent decommission | Backend publishes revoked serial to NATS → ingestion gateway rejects |
| Emergency revoke | Compromise detected | Admin revokes via API; propagated to all gateways within 30s via NATS |

---

## 6. Multi-Tenant Isolation

### 6.1 Isolation Boundaries

```
┌─────────────────────────────────────────────────┐
│ Tenant A                                         │
│  ├── Agent certs signed by Tenant-A sub-CA      │
│  ├── NATS subject: telemetry.tenant-a.>         │
│  ├── ES index: sentinel-telemetry-tenant-a-*    │
│  ├── PG schema: tenant_a                        │
│  └── Detection rules: tenant-a/rules/           │
├─────────────────────────────────────────────────┤
│ Tenant B                                         │
│  ├── Agent certs signed by Tenant-B sub-CA      │
│  ├── NATS subject: telemetry.tenant-b.>         │
│  ├── ES index: sentinel-telemetry-tenant-b-*    │
│  ├── PG schema: tenant_b                        │
│  └── Detection rules: tenant-b/rules/           │
└─────────────────────────────────────────────────┘
```

### 6.2 Cross-Tenant Attack Mitigations

| Attack | Mitigation |
|--------|------------|
| Tenant A agent queries Tenant B data | Ingestion gateway extracts `tenant_id` from mTLS cert CN; cannot be overridden by agent payload |
| API user queries across tenants | Mandatory `tenant_id` filter injected by auth middleware; not controllable by query parameter |
| NATS subscription to other tenant | NATS account permissions restrict subscription patterns per tenant |
| Detection rule poisoning across tenants | Rules stored in tenant-scoped directory; rule upload requires tenant-admin role |
| ES index aliasing exploit | Index templates enforce `tenant_id` in index name; no cross-tenant aliases |

---

## 7. Supply Chain Security

### 7.1 Agent Binary Distribution

| Control | Implementation |
|---------|----------------|
| Reproducible builds | Nix-based build environment; `cargo-auditable` for dependency tracking |
| Binary signing | Ed25519 signature with offline key; agent verifies update signature before applying |
| Update delivery | Signed update manifest over gRPC command channel; agent downloads from CDN, verifies hash + signature |
| Dependency audit | `cargo-deny` in CI: license check, vulnerability check, duplicate detection |
| SBOM | CycloneDX SBOM generated per release; stored alongside release artifacts |

### 7.2 Backend Container Images

| Control | Implementation |
|---------|----------------|
| Base images | Distroless or Alpine with pinned digests (not tags) |
| Image signing | Cosign + Sigstore for all production images |
| Vulnerability scanning | Trivy in CI; block deployment on Critical/High CVEs |
| Runtime immutability | Read-only root filesystem; no shell in production containers |
| Secrets | No secrets in images; injected via Kubernetes Secrets or Vault |

---

## 8. Cryptographic Inventory

| Use Case | Algorithm | Key Size | Rationale |
|----------|-----------|----------|-----------|
| Agent↔Backend transport | TLS 1.3 (AEAD) | N/A | Forward secrecy, no downgrade |
| Agent certificate | ECDSA P-256 or RSA-2048 | 256-bit / 2048-bit | Balance security/performance |
| CA hierarchy | RSA-4096 (root) → RSA-2048 (tenant sub-CA) | 4096 / 2048 | Long-lived root |
| Enrollment token HMAC | HMAC-SHA256 | 256-bit | Token integrity |
| Token storage | Argon2id | 256-bit output | Offline brute-force resistance |
| Binary update signature | Ed25519 | 256-bit | Fast verification, high security |
| Process GUID | SHA-256(agent_guid ∥ pid ∥ start_time_ns) | 256-bit | Collision resistance |
| IOC bloom filter | SipHash (internal) | 128-bit | Non-cryptographic but keyed |
| Event compression | zstd (not crypto) | N/A | Bandwidth reduction |
| Backend inter-service | mTLS with internal CA | ECDSA P-256 | Service mesh security |

---

## 9. Security Monitoring & Alerting

### 9.1 Meta-Security Events (Monitoring the Monitor)

The EDR itself must be monitored. These events should trigger **Severity: Critical** alerts:

| Event | Source | Indicates |
|-------|--------|-----------|
| Agent heartbeat gap > 5 minutes | Ingestion gateway | Agent killed/blocked |
| Sequence number gap in batch | Ingestion gateway | Events dropped or tampered |
| ETW/eBPF provider health = unhealthy | Agent self-report | Telemetry blind spot |
| Binary integrity check failure | Agent self-report | Agent binary tampered |
| Certificate renewal failure | Enrollment service | mTLS about to expire |
| Enrollment token brute-force (>5 failures/min) | Enrollment service | Token guessing attack |
| NATS consumer lag > 10,000 messages | NATS monitoring | Processing bottleneck |
| Detection rule update from unexpected source | API audit log | Rule tampering |
| Admin login from new IP/device | API audit log | Credential compromise |
| Cross-tenant data access attempt | API audit log | Isolation breach attempt |

### 9.2 Alert Response Playbooks

```yaml
# Example: Agent Heartbeat Gap
trigger: agent_heartbeat_gap > 300s
severity: critical
automated_response:
  - check_agent_last_known_state
  - check_network_connectivity (ping/traceroute from nearby agent)
  - if agent_was_healthy_before:
      - escalate_to_soc_tier2
      - attempt_remote_wake (WoL if configured)
  - if agent_reported_tamper_before_disconnect:
      - escalate_to_soc_tier1
      - isolate_endpoint (network quarantine via switch ACL)
      - create_incident
```

---

## 10. Compliance Mapping

| Requirement | Framework | How Addressed |
|-------------|-----------|---------------|
| Encryption in transit | SOC2 CC6.1, PCI 4.1, HIPAA §164.312(e) | TLS 1.3 mTLS on all channels |
| Encryption at rest | SOC2 CC6.1, PCI 3.4, HIPAA §164.312(a) | ES/PG encrypted volumes; LUKS or BitLocker on endpoints |
| Access control | SOC2 CC6.3, PCI 7.1, HIPAA §164.312(a) | RBAC + tenant isolation + MFA |
| Audit logging | SOC2 CC7.2, PCI 10.1, HIPAA §164.312(b) | Immutable audit trail for all admin actions |
| Data retention | SOC2 CC7.4, PCI 3.1, HIPAA §164.530(j) | ILM policy: hot(3d)→warm(30d)→cold(90d)→frozen(365d)→delete |
| Incident response | SOC2 CC7.3, PCI 12.10, HIPAA §164.308(a)(6) | Automated alert playbooks + SOC escalation |
| Vulnerability management | SOC2 CC7.1, PCI 6.1 | cargo-deny, Trivy, SBOM generation per release |
| Change management | SOC2 CC8.1, PCI 6.4 | Signed updates, 2-person rule approval, audit trail |

---

## 11. Residual Risks & Accepted Limitations

| Risk | Severity | Reason for Acceptance | Monitoring |
|------|----------|----------------------|------------|
| BYOVD attack bypasses PPL | Medium | Cannot prevent all signed vulnerable drivers; requires HVCI which not all hardware supports | Driver load events monitored; known vulnerable driver hashes in IOC list |
| Kernel-level rootkit hides from ETW/eBPF | High | Cannot detect what kernel-level attacker hides; would require hardware-based attestation | Out-of-band integrity verification (remote attestation roadmap item) |
| Insider with DB admin access modifies stored events | Medium | Operational necessity for DB maintenance | Append-only audit log + periodic hash chain verification (roadmap) |
| Zero-day in Rust stdlib or dependency | Low | Accepted risk in any software; mitigated by rapid patching | cargo-deny alerts, GitHub Dependabot |
| NATS total cluster failure | Low | Mitigated by 3-node cluster + disk buffer on agents | NATS cluster monitoring; agent buffer capacity alerts |

---

## Appendix A: Security Testing Requirements

### A.1 Agent Security Tests (CI/CD)

```
☐ Fuzzing: libfuzzer on protobuf deserialization (1M iterations/run)
☐ Fuzzing: AFL++ on event normalization pipeline
☐ Memory safety: cargo-miri on all non-FFI code paths
☐ Dependency audit: cargo-deny (advisories, licenses, duplicates)
☐ Binary hardness: checksec.py on release binary (PIE, RELRO, stack canary, NX)
☐ Static analysis: cargo-clippy with #[deny(clippy::all, clippy::pedantic)]
☐ Integration: Kill agent process → verify restart + tamper event
☐ Integration: Block backend traffic → verify disk buffering + recovery
☐ Integration: Inject 100k events/sec → verify backpressure + no OOM
```

### A.2 Backend Security Tests

```
☐ OWASP ZAP scan on API endpoints
☐ SQLi testing on all query parameters (sqlmap)
☐ mTLS verification: reject connections without valid agent cert
☐ Cross-tenant test: verify tenant A cannot access tenant B data
☐ Rate limit test: verify per-agent throttling at ingestion gateway
☐ NATS ACL test: verify account isolation (consumer A cannot subscribe to B)
☐ Chaos engineering: kill NATS node → verify failover + no data loss
☐ Chaos engineering: kill ES node → verify write buffer + recovery
☐ Load test: 50k simulated agents, 5k events/sec sustained for 1 hour
```

---

*This threat model should be reviewed and updated quarterly, or whenever
a significant architecture change is made.*
