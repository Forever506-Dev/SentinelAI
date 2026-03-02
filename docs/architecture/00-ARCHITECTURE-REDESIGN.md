# SentinelAI — Production-Grade EDR Architecture Redesign

**Version**: 2.0  
**Date**: 2026-02-27  
**Classification**: Internal / Architecture  
**Author**: Principal Security Architect  

---

## Executive Summary

This document specifies the complete architectural redesign of SentinelAI from a
prototype EDR into a production-grade, adversary-resilient endpoint detection and
response platform. The redesign addresses seven critical deficiencies in the
current architecture:

1. **No kernel-level telemetry** — polling sysinfo crate misses transient processes
2. **HTTP REST transport** — unbuffered, no backpressure, no streaming
3. **Monolithic backend** — ingestion, detection, AI, and API in one process
4. **No event bus** — Redis pub/sub is fire-and-forget with no durability
5. **No mutual authentication** — JWT-only, no agent certificate pinning
6. **No anti-tamper** — agent can be trivially killed or events suppressed
7. **No horizontal scaling** — single backend process bottleneck

### Target Parameters

| Metric | Target |
|---|---|
| Endpoints | 10,000 – 50,000 |
| Events/sec (sustained) | 5,000 – 20,000 |
| Event latency (ingest → alert) | < 2 seconds (P95) |
| Agent CPU overhead | < 3% steady, < 8% burst |
| Agent memory footprint | < 50 MB RSS |
| Data retention (hot) | 30 days |
| Data retention (warm) | 90 days |
| Data retention (cold) | 1 year |

---

## Table of Contents

1. [Part 1 — Agent Redesign](#part-1--agent-redesign)
2. [Part 2 — Secure Event Stream Architecture](#part-2--secure-event-stream-architecture)
3. [Part 3 — Event Schema Design](#part-3--event-schema-design)
4. [Part 4 — Detection Engine Design](#part-4--detection-engine-design)
5. [Part 5 — Security Hardening](#part-5--security-hardening)
6. [Part 6 — Performance & Resilience](#part-6--performance--resilience)

---

# Part 1 — Agent Redesign

## 1.1 Current State Analysis

The current agent (`sentinel-agent` v0.1.0) has these deficiencies:

| Problem | Impact |
|---|---|
| `sysinfo` crate polling at intervals | Misses processes that spawn and exit between polls |
| No ETW on Windows | Cannot observe kernel-level process creation, DLL loads, registry writes |
| No eBPF on Linux | Relies on `/proc` scanning, misses short-lived processes |
| HTTP REST transport | No streaming, no backpressure, 10s flush interval |
| `DetectionEngine` defined but never instantiated in `main.rs` | Local detection is dead code |
| No self-protection | `taskkill /f sentinel-agent.exe` terminates the agent |
| Command polling every 2s | Wastes bandwidth, adds latency |
| Flat module structure | No platform abstraction, hard to add macOS/Android |

## 1.2 Redesigned Folder Structure

```
sentinel-agent/
├── Cargo.toml
├── build.rs                          # Platform-conditional compilation
├── agent.toml                        # Runtime configuration
├── certs/                            # mTLS certificates (enrolled)
│   ├── agent.crt
│   ├── agent.key
│   └── ca.crt
├── src/
│   ├── main.rs                       # Entry point, orchestrator
│   ├── config.rs                     # TOML + env config
│   │
│   ├── collector/                    # Telemetry providers
│   │   ├── mod.rs                    # TelemetryProvider trait
│   │   ├── registry.rs              # Collector registry & lifecycle
│   │   ├── etw/                      # Windows ETW providers
│   │   │   ├── mod.rs
│   │   │   ├── process_provider.rs  # Microsoft-Windows-Kernel-Process
│   │   │   ├── file_provider.rs     # Microsoft-Windows-Kernel-File
│   │   │   ├── network_provider.rs  # Microsoft-Windows-Kernel-Network
│   │   │   ├── registry_provider.rs # Microsoft-Windows-Kernel-Registry
│   │   │   └── dns_provider.rs      # Microsoft-Windows-DNS-Client
│   │   ├── ebpf/                     # Linux eBPF programs
│   │   │   ├── mod.rs
│   │   │   ├── process_probe.rs     # tracepoint/syscalls/sys_enter_execve
│   │   │   ├── file_probe.rs        # tracepoint/syscalls/sys_enter_openat
│   │   │   ├── network_probe.rs     # kprobe/tcp_connect, kprobe/udp_sendmsg
│   │   │   └── bpf/                 # Compiled eBPF bytecode (.o)
│   │   │       ├── process.bpf.c
│   │   │       ├── file.bpf.c
│   │   │       └── network.bpf.c
│   │   ├── android/                  # Android fallback
│   │   │   ├── mod.rs
│   │   │   ├── audit_provider.rs    # SELinux audit log parser
│   │   │   └── proc_provider.rs     # /proc fallback with inotify
│   │   └── fallback/                 # Graceful degradation
│   │       ├── mod.rs
│   │       └── polling_provider.rs  # sysinfo-based (current behavior)
│   │
│   ├── event_pipeline/               # Normalization & routing
│   │   ├── mod.rs                    # EventPipeline trait
│   │   ├── normalizer.rs            # Raw → NormalizedEvent
│   │   ├── enricher.rs              # Add process GUID, user SID, hashes
│   │   ├── filter.rs                # Rate limiting, dedup, noise reduction
│   │   ├── aggregator.rs            # Batch assembly with backpressure
│   │   └── ring_buffer.rs           # Lock-free SPSC ring buffer
│   │
│   ├── local_detection/              # On-agent detection
│   │   ├── mod.rs
│   │   ├── engine.rs                # Rule evaluation engine
│   │   ├── rules/
│   │   │   ├── mod.rs
│   │   │   ├── sigma.rs             # Sigma rule loader & evaluator
│   │   │   ├── yara.rs              # YARA scanning integration
│   │   │   └── heuristic.rs         # Built-in heuristics
│   │   └── alert_manager.rs         # Local alert dedup & priority queue
│   │
│   ├── transport/                    # Backend communication
│   │   ├── mod.rs                    # TransportClient trait
│   │   ├── grpc_client.rs           # gRPC + mTLS streaming
│   │   ├── quic_client.rs           # QUIC fallback for hostile networks
│   │   ├── buffer.rs                # Persistent on-disk event buffer
│   │   ├── enrollment.rs            # CSR generation & cert bootstrap
│   │   └── tls.rs                   # Certificate management
│   │
│   ├── self_protection/              # Anti-tamper & resilience
│   │   ├── mod.rs                    # SelfProtection trait
│   │   ├── windows/
│   │   │   ├── mod.rs
│   │   │   ├── service_guard.rs     # SCM Protected Process Light
│   │   │   ├── etw_guardian.rs      # ETW session tamper detection
│   │   │   ├── integrity.rs         # Binary self-hash verification
│   │   │   └── edr_registration.rs  # Early Launch Anti-Malware (ELAM)
│   │   ├── linux/
│   │   │   ├── mod.rs
│   │   │   ├── ebpf_guardian.rs     # BPF program pin monitoring
│   │   │   ├── cgroup_shield.rs     # cgroup-based OOM protection
│   │   │   └── integrity.rs         # Binary self-hash verification
│   │   └── common/
│   │       ├── mod.rs
│   │       ├── heartbeat_watchdog.rs # Detects own process suspension
│   │       └── canary.rs            # Canary events to detect suppression
│   │
│   └── platform/                     # OS abstraction layer
│       ├── mod.rs                    # Platform detection & feature gates
│       ├── windows.rs               # Windows-specific APIs
│       ├── linux.rs                 # Linux-specific APIs
│       ├── macos.rs                 # macOS-specific APIs (future)
│       └── android.rs              # Android-specific APIs (future)
```

## 1.3 Core Trait Definitions

### TelemetryProvider

```rust
/// A platform-specific telemetry source that produces raw events.
///
/// Implementors: ETW providers (Windows), eBPF probes (Linux),
/// audit log parsers (Android), polling fallback.
#[async_trait]
pub trait TelemetryProvider: Send + Sync + 'static {
    /// Human-readable name for logging ("etw::process", "ebpf::execve")
    fn name(&self) -> &str;

    /// Event types this provider can emit.
    fn capabilities(&self) -> &[EventCategory];

    /// Start the provider. Must not block — spawn internal tasks.
    /// Events are pushed into the provided ring buffer.
    async fn start(
        &mut self,
        sink: EventSink,
        cancel: CancellationToken,
    ) -> Result<(), ProviderError>;

    /// Gracefully stop. Flush any pending events.
    async fn stop(&mut self) -> Result<(), ProviderError>;

    /// Health check — returns false if the provider has been tampered with
    /// (e.g., ETW session was killed, eBPF program was detached).
    async fn is_healthy(&self) -> bool;

    /// Return provider-specific metrics (events/sec, drops, errors).
    fn metrics(&self) -> ProviderMetrics;
}
```

### EventPipeline

```rust
/// Normalizes, enriches, filters, and batches raw telemetry events
/// before handing them to the transport layer.
#[async_trait]
pub trait EventPipeline: Send + Sync + 'static {
    /// Consume raw events from providers, produce normalized batches.
    async fn run(
        &mut self,
        source: EventSource,
        detection_tx: mpsc::Sender<NormalizedEvent>,
        transport_tx: mpsc::Sender<EventBatch>,
        cancel: CancellationToken,
    ) -> Result<(), PipelineError>;

    /// Current pipeline throughput and backpressure state.
    fn metrics(&self) -> PipelineMetrics;

    /// Update filtering rules at runtime (from backend policy push).
    fn update_filter_policy(&mut self, policy: FilterPolicy);
}
```

### TransportClient

```rust
/// Handles all communication with the SentinelAI backend.
///
/// Supports mTLS gRPC (primary), QUIC (fallback), and persistent
/// disk buffering when the backend is unreachable.
#[async_trait]
pub trait TransportClient: Send + Sync + 'static {
    /// Establish connection (mTLS handshake, certificate validation).
    async fn connect(&mut self) -> Result<(), TransportError>;

    /// Stream a batch of events. Returns backpressure signal.
    async fn send_batch(
        &self,
        batch: EventBatch,
    ) -> Result<BackpressureSignal, TransportError>;

    /// Open bidirectional command channel.
    async fn command_stream(
        &self,
    ) -> Result<(CommandReceiver, ResponseSender), TransportError>;

    /// Perform certificate rotation if the current cert is near expiry.
    async fn rotate_certificate(&mut self) -> Result<(), TransportError>;

    /// Connection state (connected, reconnecting, buffering).
    fn state(&self) -> ConnectionState;
}
```

### SelfProtection

```rust
/// Platform-specific anti-tamper mechanisms.
///
/// These mechanisms are defense-in-depth — they increase the cost
/// of disabling the agent but cannot prevent a kernel-level attacker.
#[async_trait]
pub trait SelfProtection: Send + Sync + 'static {
    /// Initialize protection mechanisms (must be called early in startup).
    async fn initialize(&mut self) -> Result<(), ProtectionError>;

    /// Periodic integrity verification.
    async fn verify_integrity(&self) -> IntegrityReport;

    /// Check if telemetry providers are still attached and healthy.
    async fn verify_providers(&self) -> Vec<ProviderHealthStatus>;

    /// Called when tamper is detected — triggers alert and recovery.
    async fn on_tamper_detected(
        &self,
        tamper_type: TamperType,
    ) -> TamperResponse;
}
```

## 1.4 Windows ETW Architecture (No Kernel Hooking)

### Why ETW, Not Kernel Hooks

| Approach | Risk | SentinelAI Position |
|---|---|---|
| Kernel driver (minifilter, NDIS) | BSOD risk, WHQL signing required, CrowdStrike-class failures | **Rejected** |
| User-mode API hooking (IAT/EAT) | Trivially bypassed by direct syscalls, unstable | **Rejected** |
| ETW (kernel providers) | Microsoft-supported, stable ABI, no BSOD risk | **Selected** |
| WMI event subscriptions | High overhead, 1-second minimum granularity | **Rejected** |

### ETW Provider Selection

```
┌──────────────────────────────────────────────────────────────┐
│                    ETW Kernel Sessions                        │
├──────────────────────────────────────────────────────────────┤
│  Provider GUID                     │ Events                  │
│  ─────────────────────────────────│────────────────────────  │
│  Microsoft-Windows-Kernel-Process  │ ProcessStart/Stop,      │
│  {22FB2CD6-...}                    │ ImageLoad, ThreadStart   │
│                                    │                          │
│  Microsoft-Windows-Kernel-File     │ Create, Delete, Rename,  │
│  {EDD08927-...}                    │ Read, Write, SetInfo     │
│                                    │                          │
│  Microsoft-Windows-Kernel-Network  │ TcpIp Connect/Accept,   │
│  {7DD42A49-...}                    │ Send/Recv, DNS queries   │
│                                    │                          │
│  Microsoft-Windows-Kernel-Registry │ CreateKey, SetValue,     │
│  {70EB4F03-...}                    │ DeleteKey, QueryValue    │
│                                    │                          │
│  Microsoft-Windows-DNS-Client      │ DNS query/response       │
│  {1C95126E-...}                    │ with full domain names   │
│                                    │                          │
│  Microsoft-Windows-Security-Auditing│ Logon/Logoff events     │
│  {54849625-...}                    │ (requires admin)         │
└──────────────────────────────────────────────────────────────┘
          │
          │  Real-time ETW consumer (TdhGetEventInformation)
          ▼
┌──────────────────────────────────────────────────────────────┐
│                 ETW Consumer Thread Pool                       │
│                                                                │
│  • One consumer per session (avoid cross-session blocking)     │
│  • ProcessTrace() runs on dedicated OS thread (blocking API)   │
│  • Events parsed via TDH, pushed into lock-free ring buffer    │
│  • Ring buffer → Tokio async pipeline                          │
└──────────────────────────────────────────────────────────────┘
```

### ETW Implementation Pattern

```rust
// Pseudocode — actual implementation uses windows-rs crate
// with EVENT_TRACE_PROPERTIES and OpenTrace/ProcessTrace.

pub struct EtwProcessProvider {
    session_handle: TRACEHANDLE,
    consumer_handle: TRACEHANDLE,
    ring_buffer: Arc<RingBuffer<RawEvent>>,
    thread_handle: Option<JoinHandle<()>>,
}

impl EtwProcessProvider {
    pub fn new(ring_buffer: Arc<RingBuffer<RawEvent>>) -> Result<Self, EtwError> {
        // 1. Create a real-time ETW trace session
        //    SESSION_NAME = "SentinelAI-Process-v2"
        //    FLAGS = EVENT_TRACE_REAL_TIME_MODE
        //
        // 2. Enable the Microsoft-Windows-Kernel-Process provider
        //    GUID = {22FB2CD6-0048-11D1-A27D-00C04FC9A524} -- (fictional, real GUID differs)
        //    LEVEL = TRACE_LEVEL_INFORMATION
        //    MATCH_ANY_KEYWORD = 0x10 (WINEVENT_KEYWORD_PROCESS)
        //
        // 3. Register event callback
        //    The callback deserializes the ETW event structure,
        //    extracts PID, PPID, ImageFileName, CommandLine,
        //    and pushes a RawEvent into the ring buffer.
        //
        // 4. Start ProcessTrace on a dedicated OS thread
        //    (ProcessTrace is a blocking Win32 call)
    }
}
```

### Preventing ETW Tampering

An attacker who gains admin/SYSTEM can attempt:

| Attack | Detection | Response |
|---|---|---|
| `logman stop SentinelAI-Process` | ETW Guardian polls `QueryAllTraces()` every 5s; detects missing session | Immediately restart session + emit `TAMPER_ETW_SESSION_KILLED` alert |
| `NtSetInformationThread(EtwpStopTrace)` from kernel | Canary event injection: agent writes known canary events at intervals; if canaries stop arriving, the session is dead | Restart session + alert |
| Patching `EtwEventWrite` in `ntdll.dll` | The agent's own ETW session directly reads from kernel buffers, not ntdll; patching ntdll only affects userspace callers | No impact on SentinelAI (we read kernel buffers) |
| Killing the ETW consumer thread | Heartbeat watchdog monitors thread liveness via `WaitForSingleObject` with timeout | Respawn consumer thread + alert |

**Key principle**: ETW kernel-mode providers deliver events directly from the
kernel into the agent's trace buffer. An attacker must have kernel-level access
to suppress these events — at which point no user-mode EDR can defend anyway.
The goal is to **maximize the cost** of evasion, not to achieve impossibility.

## 1.5 Linux eBPF Architecture

### eBPF Program Selection

```
┌──────────────────────────────────────────────────────────────┐
│                      eBPF Programs                            │
├──────────────────────────────────────────────────────────────┤
│  Hook Point                        │ Data Captured            │
│  ─────────────────────────────────│────────────────────────  │
│  tracepoint/syscalls/sys_enter_execve │ PID, PPID, filename, │
│  tracepoint/sched/sched_process_exec  │ argv, envp           │
│                                        │                      │
│  tracepoint/syscalls/sys_enter_openat  │ dirfd, pathname,     │
│  tracepoint/syscalls/sys_exit_openat   │ flags, mode, return  │
│                                        │                      │
│  kprobe/tcp_v4_connect                 │ saddr, daddr, sport, │
│  kretprobe/tcp_v4_connect              │ dport, retval        │
│  kprobe/udp_sendmsg                    │                      │
│                                        │                      │
│  tracepoint/syscalls/sys_enter_unlinkat│ pathname, flags      │
│                                        │                      │
│  LSM/bprm_check_security (5.7+)       │ Binary execution     │
│                                        │ (LSM hook, most      │
│                                        │  tamper-resistant)    │
└──────────────────────────────────────────────────────────────┘
          │
          │  BPF ring buffer (bpf_ringbuf_output)
          ▼
┌──────────────────────────────────────────────────────────────┐
│              Userspace Ring Buffer Consumer                    │
│                                                                │
│  • libbpf-rs for program loading & management                  │
│  • BPF_MAP_TYPE_RINGBUF for zero-copy event transfer           │
│  • Consumer runs in dedicated Tokio task with epoll             │
│  • Events: struct with PID, TGID, UID, comm[16], filename      │
│  • Overflow policy: drop oldest (BPF_RB_NO_WAKEUP for batch)   │
└──────────────────────────────────────────────────────────────┘
```

### eBPF Program Example (Process Execution)

```c
// process.bpf.c — compiled to BPF bytecode, loaded at agent startup
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct event {
    u32 pid;
    u32 tgid;
    u32 ppid;
    u32 uid;
    u64 timestamp_ns;   // ktime_get_boot_ns()
    char comm[16];
    char filename[256];
    u8  event_type;     // 1=exec, 2=exit
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16 MB ring buffer
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    task = (struct task_struct *)bpf_get_current_task();

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->timestamp_ns = bpf_ktime_get_boot_ns();
    e->event_type = 1;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(
        &e->filename, sizeof(e->filename),
        (const char *)ctx->args[0]
    );

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### Preventing eBPF Unloading

| Attack | Detection | Response |
|---|---|---|
| `bpftool prog detach` or `close(bpf_fd)` | Pin all BPF programs to `/sys/fs/bpf/sentinel/`. Monitor pin directory with inotify. If pins disappear, program was detached. | Re-load & re-attach + emit `TAMPER_BPF_DETACHED` alert |
| Overwriting ring buffer map | Use `BPF_F_RDONLY_PROG` flag; ring buffer is kernel memory, not writable from userspace | N/A — not possible from userspace |
| Killing agent process (fd closes → BPF detaches) | BPF pins survive process death. Systemd `Restart=always` with watchdog. Secondary canary process monitors agent. | Systemd restarts agent; BPF programs are still pinned |
| `rmmod bpf` | Not possible on modern kernels (BPF is compiled in, not a module) | N/A |
| Unloading via `CAP_SYS_ADMIN` | Requires root. eBPF `expected_attach_type` + LSM hooks (BPF_PROG_TYPE_LSM) can block unauthorized BPF operations on kernel ≥5.7 | Deploy LSM-BPF policy that restricts BPF program management to SentinelAI's UID |

## 1.6 Android Feasibility Analysis

### eBPF on Android

| Android Version | eBPF Support | Notes |
|---|---|---|
| Android 12+ (kernel 5.10+) | Full BPF ring buffer | Requires `CAP_BPF` or root |
| Android 9–11 (kernel 4.14–5.4) | Limited eBPF | `BPF_PROG_TYPE_TRACEPOINT` available but restricted |
| Android 8 and below | None | No BPF support |

**Recommendation**: eBPF is viable only for managed device deployments (MDM-enrolled,
with SELinux policy modifications). For general BYOD, use the fallback model.

### Secure Fallback Telemetry (Android)

```
┌──────────────────────────────────────────────────────────────┐
│                Android Telemetry Stack                         │
├──────────────────────────────────────────────────────────────┤
│                                                                │
│  Primary: SELinux Audit Log Parser                             │
│  ────────────────────────────────                              │
│  • Read /dev/audit (requires audit group membership or root)   │
│  • Parse AVC denial messages for unauthorized access attempts  │
│  • Parse SYSCALL audit records for process execution           │
│                                                                │
│  Secondary: /proc Filesystem Polling                           │
│  ──────────────────────────────────                            │
│  • /proc/[pid]/stat — process state, ppid, utime              │
│  • /proc/[pid]/cmdline — command line arguments                │
│  • /proc/[pid]/exe — symlink to executable                    │
│  • /proc/net/tcp — TCP connection table                       │
│  • /proc/net/udp — UDP connection table                       │
│  • inotify on /proc for process creation (limited)            │
│                                                                │
│  Tertiary: Android-specific APIs                               │
│  ──────────────────────────────                                │
│  • UsageStatsManager — app usage (requires permission)         │
│  • PackageManager — installed apps, APK hashes                 │
│  • ConnectivityManager — network state changes                 │
│  • AccessibilityService — screen content (MDM only)            │
│                                                                │
│  Limitations:                                                  │
│  • No kernel-level visibility without root/MDM                 │
│  • SELinux neverallow rules block many /proc reads in enforcing│
│  • Cannot monitor other apps' file access without root         │
│  • Battery optimization may suspend the agent                  │
│                                                                │
│  Mitigation:                                                   │
│  • Register as Device Owner via MDM for full /proc access      │
│  • Use WorkManager for reliable periodic collection            │
│  • Use foreground service with persistent notification         │
│  • Battery optimization whitelist via Settings.ACTION_...      │
└──────────────────────────────────────────────────────────────┘
```

## 1.7 Agent Anti-Tamper Summary

### Preventing Agent Kill Attempts

**Windows:**
1. Run as a Windows Service with `SERVICE_SID_TYPE = SERVICE_SID_TYPE_UNRESTRICTED`
2. Set service failure recovery: restart on first, second, third failure (0ms delay)
3. Register as Protected Process Light (PPL) via ELAM driver certificate:
   - PPL processes cannot be opened with `PROCESS_TERMINATE` by non-PPL processes
   - Requires an ELAM certificate from Microsoft (production) or test signing (dev)
4. Set process mitigation policy: `SetProcessMitigationPolicy(ProcessSignaturePolicy)` 
   to prevent unsigned DLL injection
5. Set DACL on agent process: deny `PROCESS_TERMINATE` to Everyone except SYSTEM

**Linux:**
1. Run via systemd with `Restart=always`, `RestartSec=1`, `WatchdogSec=30`
2. Set `OOMScoreAdj=-900` to resist OOM killer
3. Use `prctl(PR_SET_DUMPABLE, 0)` to prevent ptrace attachment
4. Deploy cgroup with memory reservation to prevent resource starvation
5. Secondary watchdog process (minimal binary) monitors agent via pidfd

### Preventing Event Flooding Attacks

An adversary may generate millions of events/sec to overwhelm the pipeline:

```
┌──────────────────────────────────────────────────────────────┐
│              Event Flooding Countermeasures                    │
├──────────────────────────────────────────────────────────────┤
│                                                                │
│  Layer 1: Kernel-side filtering (eBPF)                         │
│  • Rate-limit per-PID event emission in BPF program            │
│  • BPF map with per-PID token bucket (refill 100/sec)          │
│  • If bucket empty, drop event but increment drop counter      │
│                                                                │
│  Layer 2: Ring buffer overflow policy                          │
│  • BPF ring buffer: drop oldest on overflow                    │
│  • ETW: EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING + large buffer  │
│  • Always track drop count for reporting to backend            │
│                                                                │
│  Layer 3: Event pipeline deduplication                          │
│  • Bloom filter for recent (process, action) tuples            │
│  • Suppress identical events within 1s window                  │
│  • Collapse repeated file write events into "N writes in Xs"   │
│                                                                │
│  Layer 4: Backpressure to transport                            │
│  • Bounded channel between pipeline and transport              │
│  • If channel full, pipeline drops lowest-severity events first│
│  • Always preserve: process exec, file create in temp dirs,    │
│    network connect to external IPs, auth failures              │
│                                                                │
│  Layer 5: Flood detection alert                                │
│  • If drop rate exceeds threshold, emit EVENT_FLOOD alert      │
│  • Include: source PID, event type, drop rate, duration        │
│  • This alert itself is high-priority and never dropped         │
└──────────────────────────────────────────────────────────────┘
```

---

# Part 2 — Secure Event Stream Architecture

## 2.1 Current Backend Problems

The current `app/main.py` is a monolith:

```
FastAPI Process
├── POST /agents/telemetry     → Writes to PostgreSQL
│                               → Spawns asyncio task for detection
│                               → Detection calls LLM (blocks event loop)
│                               → Publishes alert to Redis pub/sub
├── GET  /alerts               → Reads from PostgreSQL
├── WebSocket /ws/live         → Subscribes to Redis pub/sub (NO AUTH)
├── POST /analysis/investigate → Calls LLM with tool-use loop
└── ... all in one process
```

**Problems at scale:**

| Issue | Impact at 5k events/sec |
|---|---|
| `asyncio` single-threaded event loop | LLM calls (~2-5s) block telemetry ingestion |
| PostgreSQL for hot telemetry storage | Write amplification; PG not designed for append-only high-throughput |
| Redis pub/sub (fire-and-forget) | Subscriber disconnects = lost alerts. No replay. No persistence. |
| No horizontal scaling | One process handles all ingestion, detection, AI, and API |
| Background task detection | Detection failure crashes the entire backend |
| No backpressure | Agent floods → OOM on backend |

## 2.2 Why Redis Pub/Sub Is Insufficient at Scale

Redis pub/sub has fundamental limitations for an event-driven security platform:

1. **No persistence**: Messages exist only in memory during delivery. If a subscriber
   is disconnected when a critical alert is published, that alert is lost forever.
   In an EDR, this means missed detections.

2. **No replay**: A new detection service instance cannot consume historical events.
   After a deployment or restart, all in-flight events are gone.

3. **No consumer groups**: Every subscriber receives every message. You cannot
   parallelize consumption across multiple detection engine instances.

4. **No backpressure**: Redis will buffer messages for slow subscribers until it
   runs out of memory, then starts disconnecting clients. At 5k events/sec with
   a slow AI consumer, this happens within minutes.

5. **No ordering guarantees across shards**: Redis Cluster pub/sub does not
   guarantee cross-shard ordering. Security event correlation requires ordering.

6. **No acknowledgment**: The publisher has no way to know if consumers processed
   the message. No retry mechanism.

Redis Streams (with XREAD/XACK) partially address points 1-3 and 6, but still
lack the operational maturity, multi-tenancy, and clustering model needed.

## 2.3 Why NATS JetStream Over Kafka

| Criterion | Kafka | NATS JetStream | Winner |
|---|---|---|---|
| Operational complexity | High (ZooKeeper/KRaft, topic partitions, ISR) | Low (single binary, embedded RAFT) | NATS |
| Latency (P99) | 5-15ms | 1-3ms | NATS |
| Memory footprint per broker | 1-4 GB JVM heap | 50-200 MB | NATS |
| On-prem deployment | Heavy; needs dedicated Kafka cluster | Embeddable; 3-node cluster in 10 min | NATS |
| Multi-tenancy | Topic ACLs, quotas | Accounts with isolated JetStream domains | NATS |
| Request/reply (command channel) | Not native; requires additional infra | Built-in with headers | NATS |
| At-least-once delivery | Yes | Yes (JetStream consumers) | Tie |
| Exactly-once semantics | Yes (idempotent producer) | Message dedup window | Tie |
| Throughput ceiling | Higher (millions/sec per cluster) | ~1M msg/sec per server (sufficient) | Kafka |
| Client libraries | Mature | Mature (nats.rs, nats-py) | Tie |

**Verdict**: For an EDR platform targeting 5k-20k events/sec with on-prem deployment
requirements, NATS JetStream provides equivalent durability with dramatically lower
operational overhead. Kafka's throughput ceiling is unnecessary, and its operational
complexity is a liability for on-prem customers without dedicated platform teams.

## 2.4 Microservice Architecture

```
                                    ┌─────────────────────────────────────┐
                                    │        NATS JetStream Cluster       │
                                    │        (3 nodes, R3 replication)    │
                                    │                                     │
                                    │  Streams:                           │
                                    │  ├─ TELEMETRY.raw.*                 │
                                    │  ├─ TELEMETRY.normalized.*          │
                                    │  ├─ DETECTION.alerts.*              │
                                    │  ├─ ENRICHMENT.requests.*           │
                                    │  ├─ COMMANDS.{agent_id}             │
                                    │  └─ SYSTEM.health.*                 │
                                    └──────────┬──────────────────────────┘
                                               │
                 ┌─────────────────────────────┼─────────────────────────────┐
                 │                             │                             │
    ┌────────────▼─────────────┐  ┌────────────▼─────────────┐  ┌───────────▼──────────────┐
    │   Ingestion Gateway      │  │   Detection Engine        │  │   Enrichment Service     │
    │   (Stateless, N replicas)│  │   (Rust, N replicas)      │  │   (Python, N replicas)   │
    │                          │  │                            │  │                          │
    │ • mTLS termination       │  │ • NATS consumer group      │  │ • MITRE ATT&CK mapping   │
    │ • Agent cert validation  │  │ • Sigma rule engine        │  │ • CVE/NVD lookup         │
    │ • Protobuf decode        │  │ • YARA scanning            │  │ • YARA file scanning     │
    │ • Schema validation      │  │ • Correlation windows      │  │ • GeoIP enrichment       │
    │ • Rate limiting per agent│  │ • Risk scoring             │  │ • Threat intel feeds     │
    │ • Publish to NATS        │  │ • Alert generation         │  │                          │
    │                          │  │ • NEVER blocks ingestion   │  │                          │
    │ Protocol: gRPC + mTLS    │  │                            │  │                          │
    │ Scales: horizontal       │  │ Scales: horizontal         │  │ Scales: horizontal       │
    └──────────────────────────┘  └────────────────────────────┘  └──────────────────────────┘
                 │                             │                             │
                 │                             │                             │
    ┌────────────▼─────────────┐  ┌────────────▼─────────────┐  ┌───────────▼──────────────┐
    │   Storage Service        │  │   API Service             │  │   AI Analysis Service    │
    │   (Go or Rust)           │  │   (FastAPI, N replicas)   │  │   (Python, isolated)     │
    │                          │  │                            │  │                          │
    │ • NATS consumer          │  │ • REST API for Panel       │  │ • LLM-powered analysis   │
    │ • Elasticsearch writer   │  │ • WebSocket (authed)       │  │ • Investigation engine   │
    │ • PostgreSQL writer      │  │ • RBAC enforcement         │  │ • Report generation      │
    │ • Bulk indexing           │  │ • Query Elasticsearch      │  │ • Tool-use loops         │
    │ • Index lifecycle mgmt   │  │ • No direct DB writes      │  │ • Sandboxed execution    │
    │ • Hot/warm/cold rotation │  │ • Reads only               │  │ • Rate limited           │
    │                          │  │                            │  │                          │
    │ Scales: vertical (write) │  │ Scales: horizontal         │  │ Scales: queue-based      │
    │ + horizontal (read)      │  │                            │  │ (1 per LLM backend)      │
    └──────────────────────────┘  └────────────────────────────┘  └──────────────────────────┘
```

### Service Boundaries

| Service | Language | State | Scaling Model | NATS Role |
|---|---|---|---|---|
| **Ingestion Gateway** | Rust | Stateless | Horizontal (N replicas behind LB) | Publisher: `TELEMETRY.raw.{agent_id}` |
| **Detection Engine** | Rust | In-memory rule state | Horizontal (NATS queue group) | Consumer: `TELEMETRY.normalized.*`, Publisher: `DETECTION.alerts.*` |
| **Enrichment Service** | Python | Cache (Redis) | Horizontal (NATS queue group) | Consumer: `ENRICHMENT.requests.*`, Publisher: `TELEMETRY.normalized.*` |
| **Storage Service** | Rust/Go | Connection pools | Vertical + read replicas | Consumer: `TELEMETRY.normalized.*`, `DETECTION.alerts.*` |
| **API Service** | Python (FastAPI) | Stateless | Horizontal | Consumer: `DETECTION.alerts.*` (for WebSocket push) |
| **AI Analysis Service** | Python | Stateless | Queue-based (1:1 with LLM backend) | Consumer: `ANALYSIS.requests.*` |

### Horizontal Scaling via NATS Queue Groups

```
NATS JetStream subject: TELEMETRY.normalized.*

Consumer Group: "detection-engines"
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ Detection Pod 1  │  │ Detection Pod 2  │  │ Detection Pod 3  │
│ (processes 1/3)  │  │ (processes 1/3)  │  │ (processes 1/3)  │
└─────────────────┘  └─────────────────┘  └─────────────────┘

Each message delivered to EXACTLY ONE consumer in the group.
Adding Pod 4 automatically rebalances — no reconfiguration needed.
```

## 2.5 Full Event Lifecycle

```
1. SYSCALL                    2. KERNEL TELEMETRY           3. AGENT NORMALIZATION
   ─────────                     ──────────────────            ────────────────────
   User calls                    Windows: ETW delivers         Raw event → NormalizedEvent:
   CreateProcessW()              EVENT_RECORD to consumer      • Assign event GUID (UUIDv7)
   ──────┐                       thread via ProcessTrace()     • Assign process GUID
         │                                                     • Resolve user SID → username
         │                       Linux: eBPF tracepoint        • Compute SHA256 if file
         ▼                       fires, pushes struct to       • Add monotonic + wall clock
   ┌───────────┐                 BPF_MAP_TYPE_RINGBUF          • Normalize paths
   │  Kernel   │────────────────────────────┐                  • Apply noise filter
   │           │                            │                  • Run local detection (fast)
   └───────────┘                            ▼                  
                                   ┌─────────────────┐         
                                   │  Ring Buffer     │──────▶ Event Pipeline
                                   │  (16 MB, SPSC)   │         
                                   └─────────────────┘         

4. mTLS STREAM                5. NATS INGEST               6. DETECTION
   ──────────────                ─────────────                 ──────────
   Agent batches events          Ingestion gateway:            Detection engine consumes
   (max 100 or 5s timer)        • Validates agent cert CN     from NATS queue group:
   ───────┐                     • Decodes protobuf            • Sigma rule evaluation
          │                     • Rate-limits per agent_id    • Multi-event correlation
          │  gRPC stream        • Publishes to NATS           • Sliding window joins
          │  (mTLS, H2)           TELEMETRY.raw.{agent_id}   • MITRE ATT&CK tagging
          ▼                                                   • Risk score computation
   ┌──────────────┐             ┌──────────────────┐          
   │  Ingestion   │──protobuf──▶│  NATS JetStream  │──────▶ Detection Engine
   │  Gateway     │             │  (R3, 72h retain)│         
   └──────────────┘             └──────────────────┘         

7. ENRICHMENT                 8. STORAGE                   9. UI ALERT
   ───────────                   ─────────                    ────────
   Enrichment service:           Storage service:             API service:
   • MITRE technique details     • Bulk index to ES           • Subscribes to
   • CVE matching                  (hot: 30d, warm: 90d)       DETECTION.alerts.*
   • GeoIP for external IPs     • Write alert to PG          • Pushes via WebSocket
   • Threat intel IOC matching   • Write event metadata         to authenticated panel
   • YARA scan on file events      to PG (for relational     • Panel displays alert
                                   queries)                    with full context
   Publishes enriched event      • Manages ILM rollover
   back to NATS for storage                                  Analyst receives alert
                                                              within ~2s of syscall
```

---

# Part 3 — Event Schema Design

## 3.1 Design Principles

1. **Process GUID, not just PID**: PIDs are recycled. A process GUID is a
   deterministic hash of `(agent_id, pid, process_start_time_ns)` — globally
   unique and correlatable across events.

2. **Parent correlation**: Every process event includes the parent's GUID,
   enabling kill-chain reconstruction.

3. **Monotonic timestamps**: Wall clock can be NTP-adjusted. Monotonic clock
   preserves event ordering within a single agent.

4. **Separate raw and normalized**: Raw events are stored as-is for forensic
   integrity. Normalized events are optimized for querying and detection.

5. **Risk score at creation time**: The detection engine assigns a risk score
   (0-100) based on rule matches. This enables fast filtering in the UI.

## 3.2 Protobuf Schema

See `docs/architecture/proto/sentinel_v2.proto` for the full schema.

Key additions over v1:
- `host_guid` — stable agent identity (survives reinstall if enrolled)
- `process_guid` — deterministic, globally unique process identifier
- `parent_process_guid` — for kill-chain correlation
- `user_sid` / `user_uid` — OS-native user identity
- `integrity_level` — Windows integrity level (System/High/Medium/Low/Untrusted)
- `timestamp_monotonic_ns` — monotonic clock for ordering
- `event_source` — which telemetry provider generated this event
- `risk_score` — 0-100, assigned by local detection
- `mitre_techniques` — repeated field for multiple technique tags

## 3.3 Avoiding Elasticsearch Mapping Explosion

**Problem**: The current `raw_payload: JSONB` field, if indexed into Elasticsearch
as a dynamic mapping, will create a new field for every unique key in every event.
At 5k events/sec with diverse event types, this rapidly exceeds ES's default
1000-field limit and causes mapping explosion.

**Solution**: Strict index templates with explicit mappings.

```json
{
  "index_patterns": ["sentinel-telemetry-*"],
  "template": {
    "settings": {
      "index.mapping.total_fields.limit": 200,
      "index.mapping.depth.limit": 3,
      "index.mapping.nested_objects.limit": 10
    },
    "mappings": {
      "dynamic": "strict",
      "properties": {
        "event_id":          { "type": "keyword" },
        "event_type":        { "type": "keyword" },
        "event_action":      { "type": "keyword" },
        "agent_id":          { "type": "keyword" },
        "host_guid":         { "type": "keyword" },
        "hostname":          { "type": "keyword" },
        "process_guid":      { "type": "keyword" },
        "parent_process_guid": { "type": "keyword" },
        "process_name":      { "type": "keyword" },
        "command_line":       { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 1024 }}},
        "file_path":          { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 512 }}},
        "sha256":             { "type": "keyword" },
        "user":               { "type": "keyword" },
        "user_sid":           { "type": "keyword" },
        "integrity_level":    { "type": "keyword" },
        "source_ip":          { "type": "ip" },
        "dest_ip":            { "type": "ip" },
        "source_port":        { "type": "integer" },
        "dest_port":          { "type": "integer" },
        "risk_score":         { "type": "short" },
        "mitre_techniques":   { "type": "keyword" },
        "event_source":       { "type": "keyword" },
        "@timestamp":         { "type": "date" },
        "received_at":        { "type": "date" },
        "tags":               { "type": "keyword" }
      }
    }
  }
}
```

**Key rules:**
- `"dynamic": "strict"` — reject any field not in the mapping
- Raw/unparsed data goes to a separate `sentinel-raw-*` index with minimal mapping
  (just `event_id`, `@timestamp`, `raw_bytes` as `binary` type)
- Never use `object` or `nested` types for variable-structure data
- Use `keyword` for all categorical fields (not `text`)
- `command_line` and `file_path` get both `text` (for full-text search) and
  `keyword` (for exact match and aggregations)

## 3.4 Raw vs Normalized Event Storage

```
┌────────────────────────────────────────────────────────────────┐
│                     Storage Separation                          │
├────────────────────────────────────────────────────────────────┤
│                                                                  │
│  PostgreSQL (relational queries, small volume):                  │
│  ├─ agents          — Agent registration, status, metadata       │
│  ├─ alerts          — Detection alerts with MITRE, risk score    │
│  ├─ users           — Authentication and RBAC                    │
│  ├─ agent_policies  — Policy assignments                         │
│  └─ investigations  — AI analysis results, analyst notes         │
│                                                                  │
│  Elasticsearch (time-series telemetry, high volume):             │
│  ├─ sentinel-telemetry-YYYY.MM.DD  — Normalized events           │
│  │   • Strict mapping, ~200 fields max                           │
│  │   • Hot tier: 30 days on NVMe SSD                             │
│  │   • Warm tier: 90 days on HDD (force-merged, read-only)       │
│  │   • Cold tier: 365 days on S3/MinIO (searchable snapshots)    │
│  │                                                               │
│  ├─ sentinel-raw-YYYY.MM.DD       — Raw protobuf bytes           │
│  │   • Minimal mapping (event_id, @timestamp, raw_bytes)         │
│  │   • For forensic integrity — never modified                   │
│  │   • Hot: 7 days, then Cold: 365 days                          │
│  │                                                               │
│  └─ sentinel-alerts-YYYY.MM       — Alert search index           │
│      • Denormalized: alert + triggering events + enrichment      │
│      • Hot: 90 days                                              │
│                                                                  │
│  S3 / MinIO (long-term archive):                                 │
│  └─ sentinel-archive/YYYY/MM/DD/  — Compressed raw events        │
│      • Parquet format for cost-effective storage                  │
│      • Queryable via Trino/Athena for historical investigation   │
│                                                                  │
└────────────────────────────────────────────────────────────────┘
```

## 3.5 Index Lifecycle Management

```yaml
# ILM Policy: sentinel-telemetry
hot:
  max_age: 30d
  max_primary_shard_size: 50gb
  actions:
    rollover: {}
    set_priority: { priority: 100 }

warm:
  min_age: 30d
  actions:
    allocate:
      require: { data: warm }
    forcemerge: { max_num_segments: 1 }
    shrink: { number_of_shards: 1 }
    set_priority: { priority: 50 }
    readonly: {}

cold:
  min_age: 120d
  actions:
    searchable_snapshot:
      snapshot_repository: sentinel-s3-repo
    set_priority: { priority: 0 }

delete:
  min_age: 400d
  actions:
    delete: {}
```

---

# Part 4 — Detection Engine Design

## 4.1 Architecture Decision: Isolated Rust Service

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| Embedded in FastAPI | Simple deployment | GIL limits parallelism; LLM calls block detection; single failure domain | **Rejected** |
| Isolated Rust service | Zero-copy protobuf, parallel rule eval, microsecond latency, no GIL | More complex deployment | **Selected** |
| Stream-consumer (NATS) | Decoupled from ingestion, horizontally scalable | Slightly more latency | **Selected** (combined with above) |

**Decision**: The detection engine is an **isolated Rust service** that consumes
from NATS JetStream as a **queue group member**. This means:

1. Ingestion pipeline is **never blocked** by detection
2. Detection scales horizontally by adding replicas
3. Rust provides microsecond-level rule evaluation
4. YARA integration is native (via `yara-rust` crate)
5. If detection crashes, events remain in NATS for replay

## 4.2 Hybrid Detection Architecture

```
                    ┌────────────────────────────────────────────────────┐
                    │            Detection Engine (Rust Service)          │
                    │                                                      │
                    │  ┌──────────────────────────────────────────────┐   │
                    │  │           FAST PATH  (< 1ms per event)       │   │
                    │  │                                                │   │
                    │  │  1. Sigma Rule Engine                          │   │
  NATS              │  │     • Pre-compiled Sigma → state machine       │   │
  TELEMETRY.        │  │     • 500+ rules evaluated in parallel         │   │
  normalized.*  ───▶│  │     • Output: (rule_id, severity, mitre_id)    │   │
                    │  │                                                │   │
                    │  │  2. IOC Matcher                                │   │
                    │  │     • Bloom filter for known-bad hashes         │   │
                    │  │     • Aho-Corasick for domain/IP blocklists     │   │
                    │  │     • Updated via NATS SYSTEM.ioc_update        │   │
                    │  │                                                │   │
                    │  │  3. YARA Scanner (file events only)            │   │
                    │  │     • Pre-compiled YARA rules                  │   │
                    │  │     • Scans file content if available           │   │
                    │  │     • Falls back to metadata-only matching      │   │
                    │  │                                                │   │
                    │  └──────────────┬───────────────────────────────┘   │
                    │                 │                                     │
                    │                 ▼                                     │
                    │  ┌──────────────────────────────────────────────┐   │
                    │  │       CORRELATION PATH  (window-based)       │   │
                    │  │                                                │   │
                    │  │  4. Temporal Correlation Engine                │   │
                    │  │     • Sliding windows (30s, 5m, 1h, 24h)      │   │
                    │  │     • State: per-agent event sequence buffers  │   │
                    │  │     • Detect multi-step attack chains:         │   │
                    │  │       - Recon → Credential Access → Lateral    │   │
                    │  │       - Download → Execute → Persist → C2     │   │
                    │  │     • Kill-chain scoring using MITRE phases    │   │
                    │  │                                                │   │
                    │  │  5. Cross-Agent Correlation                    │   │
                    │  │     • Same IOC seen on multiple agents         │   │
                    │  │     • Lateral movement detection               │   │
                    │  │     • Shared NATS state via KV bucket          │   │
                    │  │                                                │   │
                    │  │  6. Risk Score Aggregation                     │   │
                    │  │     • Per-agent cumulative risk score           │   │
                    │  │     • Fast path hits increase score             │   │
                    │  │     • Time decay (risk decreases over time)    │   │
                    │  │     • Threshold breach → alert                 │   │
                    │  │                                                │   │
                    │  └──────────────┬───────────────────────────────┘   │
                    │                 │                                     │
                    │                 ▼                                     │
                    │  ┌──────────────────────────────────────────────┐   │
                    │  │           OUTPUT                              │   │
                    │  │                                                │   │
                    │  │  Publish to NATS:                              │   │
                    │  │  • DETECTION.alerts.{severity}                │   │
                    │  │  • ENRICHMENT.requests.{event_id}            │   │
                    │  │                                                │   │
                    │  │  Alert contains:                               │   │
                    │  │  • Triggering event(s)                         │   │
                    │  │  • Matched rule(s) with confidence             │   │
                    │  │  • MITRE ATT&CK technique(s)                  │   │
                    │  │  • Risk score (0-100)                          │   │
                    │  │  • Kill-chain phase                            │   │
                    │  │  • Recommended response action                 │   │
                    │  └──────────────────────────────────────────────┘   │
                    └────────────────────────────────────────────────────┘
```

## 4.3 Sigma Rule Integration

The detection engine loads Sigma rules (YAML format) and compiles them into
efficient state machines at startup:

```
Rule Loading Pipeline:
  sigma/*.yml → Parse YAML → Validate fields exist in schema
              → Compile to filter expression tree
              → Optimize: merge common prefixes, short-circuit
              → Store as Vec<CompiledRule>

Runtime Evaluation:
  event → Extract relevant fields into HashMap
        → Iterate CompiledRule vec
        → Each rule: evaluate filter tree against field map
        → Collect matches → (rule_id, severity, mitre_ids)
        → Total time target: < 500μs for 500 rules
```

## 4.4 Correlation Window Design

```rust
/// A time-windowed event buffer for multi-step attack detection.
pub struct CorrelationWindow {
    /// Per-agent circular buffers, keyed by agent_id.
    agent_buffers: DashMap<Uuid, VecDeque<WindowEntry>>,
    /// Window duration (events older than this are evicted).
    window_duration: Duration,
    /// Correlation rules to evaluate.
    rules: Vec<CorrelationRule>,
}

/// A correlation rule defines a sequence of conditions
/// that must occur within a time window to trigger an alert.
pub struct CorrelationRule {
    pub id: String,
    pub name: String,
    pub mitre_tactic: String,
    /// Ordered sequence of conditions (must match in order).
    pub stages: Vec<CorrelationStage>,
    /// Maximum time for the full sequence.
    pub max_duration: Duration,
    /// Minimum number of stages that must match.
    pub min_stages: usize,
    pub severity: Severity,
}

pub struct CorrelationStage {
    pub event_type: EventType,
    pub conditions: Vec<FieldCondition>,
    /// Max time since previous stage.
    pub max_gap: Duration,
}
```

Example correlation rule — "Fileless Malware Execution Chain":
```
Stage 1: Process create, name=powershell.exe, command_line contains "-nop"
  ↓ within 30s
Stage 2: Network connect, dest_port in [80, 443], process_name=powershell.exe
  ↓ within 60s
Stage 3: Process create, parent_name=powershell.exe, name NOT in [known_good]
  ↓ within 120s
Stage 4: File create, path contains "\\AppData\\Local\\Temp\\"

→ MITRE: T1059.001 → T1105 → T1059 → T1074
→ Severity: CRITICAL
→ Risk Score: 95
```

---

# Part 5 — Security Hardening

## 5.1 mTLS with Per-Agent Certificates

### Certificate Hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│                  Certificate Authority (CA)                   │
│                                                               │
│  Root CA (offline, HSM-protected)                             │
│  └─ Intermediate CA (online, short-lived, auto-rotated)       │
│     ├─ Ingestion Gateway Server Cert                          │
│     │   CN=ingest.sentinel.internal                           │
│     │   SAN=ingest-0.sentinel.internal, ...                   │
│     │   Usage: serverAuth                                     │
│     │   Lifetime: 90 days, auto-renewed                       │
│     │                                                         │
│     ├─ Agent Cert (per-agent)                                 │
│     │   CN={agent_guid}                                       │
│     │   O={tenant_id}                                         │
│     │   OU=endpoint-agent                                     │
│     │   Usage: clientAuth                                     │
│     │   Lifetime: 30 days, auto-rotated                       │
│     │                                                         │
│     └─ Inter-service Certs (per microservice)                 │
│         CN={service_name}                                     │
│         Usage: clientAuth, serverAuth                         │
│         Lifetime: 24 hours (short-lived, SPIFFE-compatible)   │
└─────────────────────────────────────────────────────────────┘
```

### Certificate Rotation Model

```
Agent Certificate Lifecycle:

Day 0:  Agent enrolled → CSR generated on agent → signed by CA
        → agent receives cert + CA chain
        → cert stored encrypted on disk (DPAPI on Windows, keyring on Linux)

Day 20: Agent notices cert expires in 10 days
        → Generates new CSR
        → Sends renewal request (signed with current cert)
        → CA validates: current cert is valid, agent_id matches
        → Issues new cert
        → Agent performs atomic cert swap (write new, then delete old)

Day 30: Old cert expires (already rotated at Day 20)

Failure Mode:
  If agent cannot reach CA for renewal before expiry:
  → Agent continues operating with expired cert
  → Ingestion gateway accepts expired certs with grace period (48h)
  → Events are buffered locally
  → After grace period: agent re-enrolls via enrollment token
```

## 5.2 Secure Agent Enrollment

```
┌─────────────┐                     ┌──────────────┐                  ┌───────────┐
│  Admin UI   │                     │  Enrollment  │                  │   Agent   │
│  (Panel)    │                     │  Service     │                  │  (New)    │
└──────┬──────┘                     └──────┬───────┘                  └─────┬─────┘
       │                                    │                                │
       │ 1. Admin generates enrollment      │                                │
       │    token (JWT, 24h expiry,         │                                │
       │    scoped to tenant + tags)        │                                │
       │───────────────────────────────────▶│                                │
       │                                    │                                │
       │ 2. Admin deploys agent binary      │                                │
       │    + enrollment token to endpoint  │                                │
       │────────────────────────────────────┼───────────────────────────────▶│
       │                                    │                                │
       │                                    │  3. Agent generates ECDSA P-256│
       │                                    │     key pair (never leaves     │
       │                                    │     endpoint)                  │
       │                                    │                                │
       │                                    │  4. Agent sends CSR +          │
       │                                    │     enrollment token +         │
       │                                    │     host fingerprint           │
       │                                    │◀───────────────────────────────│
       │                                    │                                │
       │                                    │  5. Enrollment service:        │
       │                                    │     • Validates JWT signature   │
       │                                    │     • Checks token not revoked │
       │                                    │     • Validates CSR fields     │
       │                                    │     • Signs cert via CA        │
       │                                    │     • Creates agent record     │
       │                                    │     • Assigns policy           │
       │                                    │                                │
       │                                    │  6. Returns:                   │
       │                                    │     • Signed agent cert        │
       │                                    │     • CA chain                 │
       │                                    │     • Agent GUID               │
       │                                    │     • Initial policy           │
       │                                    │────────────────────────────────▶│
       │                                    │                                │
       │                                    │  7. Agent stores cert securely │
       │                                    │     and begins telemetry       │
       │                                    │     streaming                  │
```

## 5.3 Secure Update Mechanism

```
Binary Update Verification:

1. Backend publishes update notification:
   {
     version: "2.1.0",
     platform: "windows-x86_64",
     sha256: "abc123...",
     signature: "<ed25519 signature of sha256>",
     download_url: "https://updates.sentinel.io/agent/2.1.0/windows-x86_64.exe",
     min_version: "2.0.0",    // minimum version that can update
     rollback_version: "2.0.5" // version to rollback to on failure
   }

2. Agent validates:
   a. Signature verification using embedded public key (Ed25519)
      - Public key is compiled into the agent binary
      - Cannot be changed without rebuilding and re-signing
   b. Version is newer than current
   c. Current version meets min_version requirement

3. Agent downloads binary to temp location

4. Agent verifies:
   a. SHA256 of downloaded file matches manifest
   b. Code signing certificate (Windows: Authenticode, Linux: GPG)
   c. Binary is not suspiciously large or small

5. Agent performs update:
   Windows: Copy to staging dir → register pending rename → restart service
   Linux: Copy to staging dir → atomic rename → systemd restart via ExecReload

6. Post-update health check:
   - New binary must heartbeat within 60 seconds
   - If no heartbeat, watchdog rolls back to previous version
```

## 5.4 Multi-Tenant Isolation

```
┌──────────────────────────────────────────────────────────────┐
│                   Multi-Tenant Architecture                    │
├──────────────────────────────────────────────────────────────┤
│                                                                │
│  NATS JetStream:                                               │
│  • Separate NATS Accounts per tenant                           │
│  • Each account has isolated JetStream domain                  │
│  • Cross-tenant access is impossible at the NATS level         │
│  • Subjects: {tenant_id}.TELEMETRY.raw.{agent_id}             │
│                                                                │
│  Elasticsearch:                                                │
│  • Index per tenant: sentinel-{tenant_id}-telemetry-*          │
│  • Document-level security via tenant_id field                 │
│  • API service enforces tenant filter on all queries           │
│  • No cross-tenant index patterns                              │
│                                                                │
│  PostgreSQL:                                                   │
│  • Row-level security (RLS) policies on all tables             │
│  • tenant_id column on agents, alerts, events, users           │
│  • SET app.current_tenant = '{tenant_id}' per connection       │
│  • Superuser queries disabled in application                   │
│                                                                │
│  Agent Certificates:                                           │
│  • O= field in cert contains tenant_id                         │
│  • Ingestion gateway validates tenant_id from cert             │
│  • Agent cannot send events to wrong tenant's stream           │
│                                                                │
│  API Service:                                                  │
│  • JWT contains tenant_id claim                                │
│  • Every query is scoped to requesting user's tenant           │
│  • Admin users can only manage their own tenant                │
│  • Super-admin (SaaS operator) has cross-tenant access         │
│                                                                │
│  On-Prem vs Cloud:                                             │
│  ┌─────────────────────┐  ┌──────────────────────────┐        │
│  │  On-Prem Deployment  │  │  Cloud SaaS Deployment   │        │
│  │                       │  │                          │        │
│  │  • Single tenant      │  │  • Multi-tenant          │        │
│  │  • Customer's infra   │  │  • Shared infra          │        │
│  │  • Customer manages   │  │  • SentinelAI operates   │        │
│  │    CA (their HSM)     │  │    CA (our HSM)          │        │
│  │  • Air-gapped option  │  │  • Internet-connected    │        │
│  │  • Helm chart +       │  │  • Managed K8s           │        │
│  │    docker-compose     │  │  • Auto-scaling          │        │
│  │  • Local NATS cluster │  │  • Shared NATS cluster   │        │
│  │  • Local ES cluster   │  │    (account isolation)   │        │
│  │                       │  │  • Shared ES cluster     │        │
│  └─────────────────────┘  │    (index isolation)      │        │
│                            └──────────────────────────┘        │
└──────────────────────────────────────────────────────────────┘
```

## 5.5 Threat Model

### Threat Actor Profiles

| Actor | Capability | Goal |
|---|---|---|
| **Script kiddie** | User-level access, public tools | Disable agent, avoid detection |
| **Sophisticated attacker** | Admin/root, custom tools | Suppress telemetry silently |
| **Nation-state** | Kernel access, 0-days | Persistent access, data exfiltration |
| **Insider** | Valid credentials, API access | Data theft, sabotage |

### Threat Matrix

| Threat | Attack Vector | Likelihood | Impact | Mitigation | Residual Risk |
|---|---|---|---|---|---|
| **Kernel tampering** | Load malicious driver, patch ETW/BPF | Medium | Critical | PPL (Windows), BPF-LSM (Linux), UEFI Secure Boot | Nation-state with signed driver can bypass |
| **Telemetry suppression** | Kill ETW session, detach BPF, flood events | High | Critical | Guardian threads, canary events, flood detection | Kernel-level suppression undetectable from userspace |
| **Process injection** | DLL injection, ptrace, process hollowing | High | High | Process mitigation policies, PR_SET_DUMPABLE=0 | Kernel-level injection still possible |
| **Event flooding** | Generate millions of events/sec | Medium | High | Per-PID rate limiting (BPF/ETW), bloom filter dedup, priority queues | Sustained flood at kernel level may still cause drops |
| **API abuse** | Brute-force auth, credential stuffing | High | Medium | Rate limiting, account lockout, MFA, short-lived JWT | Compromised admin token grants full access |
| **Insider threat** | Legitimate access used for unauthorized actions | Medium | High | RBAC, audit logging, MFA, data access monitoring | Insider with admin can suppress own alerts |
| **Agent binary tampering** | Replace agent binary with trojanized version | Medium | Critical | Code signing verification, self-integrity check, ELAM | Attacker with kernel access can bypass |
| **Certificate theft** | Extract agent private key from disk | Medium | High | DPAPI/keyring encryption, TPM binding (future), short cert lifetime | Memory dump can extract key |
| **NATS compromise** | Access NATS cluster, inject/delete events | Low | Critical | NATS TLS + auth, network segmentation, audit logging | Compromised NATS = full data access |
| **Elasticsearch compromise** | Direct ES access, modify/delete events | Low | Critical | ES security features, network segmentation, immutable audit trail | Compromised ES = data integrity loss |

### Defense-in-Depth Layers

```
Layer 7 (Application):  RBAC, input validation, rate limiting, audit logging
Layer 6 (Session):      JWT with short expiry, refresh token rotation
Layer 5 (Transport):    mTLS everywhere, certificate pinning on agent
Layer 4 (Network):      Network segmentation, firewall rules, NATS auth
Layer 3 (OS):           PPL, BPF-LSM, mandatory access control (SELinux/AppArmor)
Layer 2 (Firmware):     UEFI Secure Boot, measured boot (future)
Layer 1 (Physical):     HSM for CA keys, encrypted storage
```

---

# Part 6 — Performance & Resilience

## 6.1 Capacity Planning

### 50,000 Agents at 100 events/agent/sec (burst)

```
Sustained:  50,000 agents × 20 events/sec average  = 1,000,000 events/sec
Burst:      50,000 agents × 100 events/sec peak     = 5,000,000 events/sec
Average:    50,000 agents × 5 events/sec normal      = 250,000 events/sec

Event size (protobuf): ~300 bytes average
Bandwidth:  250,000 × 300 = 75 MB/sec sustained
            1,000,000 × 300 = 300 MB/sec burst

NATS JetStream:
  3 nodes, each 32 GB RAM, NVMe SSD
  R3 replication → effective throughput: ~1M msg/sec
  72h retention → 75 MB/s × 72h × 3600 = ~19 TB (before replication)

Elasticsearch:
  Hot tier:   6 data nodes, each 64 GB RAM, 2 TB NVMe
  Warm tier:  3 data nodes, each 32 GB RAM, 8 TB HDD
  Cold tier:  S3 / MinIO (searchable snapshots)

PostgreSQL:
  Primary + 2 read replicas
  Only stores: agents, alerts, users, policies (~small volume)
  Not on the hot path for telemetry
```

## 6.2 Backpressure Handling

```
┌──────────────────────────────────────────────────────────────┐
│                  Backpressure Chain                            │
├──────────────────────────────────────────────────────────────┤
│                                                                │
│  Agent Level:                                                  │
│  ┌─────────────────────────────────────────────────┐          │
│  │ Kernel → Ring Buffer (16MB) → Pipeline → Batch → Transport │
│  │                                                   │          │
│  │ If transport returns BACKPRESSURE signal:          │          │
│  │ 1. Pipeline switches to lossy mode:               │          │
│  │    - Drop system_info events first                │          │
│  │    - Drop duplicate network events                │          │
│  │    - Keep: process exec, file create, auth fail   │          │
│  │ 2. Buffer to disk (WAL-style append log)          │          │
│  │    - Max disk buffer: 500 MB (configurable)       │          │
│  │    - Oldest events evicted when full               │          │
│  │ 3. If disk buffer full: drop lowest-risk events   │          │
│  │ 4. Always emit BACKPRESSURE_ACTIVE telemetry      │          │
│  └─────────────────────────────────────────────────┘          │
│                                                                │
│  Ingestion Gateway Level:                                      │
│  ┌─────────────────────────────────────────────────┐          │
│  │ gRPC stream → Validate → NATS Publish            │          │
│  │                                                   │          │
│  │ If NATS publish fails or is slow:                 │          │
│  │ 1. Return gRPC RESOURCE_EXHAUSTED to agent        │          │
│  │ 2. Agent interprets as BACKPRESSURE signal        │          │
│  │ 3. Per-agent rate limit: token bucket (1000/sec)  │          │
│  │ 4. If agent exceeds limit: 429 + Retry-After      │          │
│  └─────────────────────────────────────────────────┘          │
│                                                                │
│  NATS Level:                                                   │
│  ┌─────────────────────────────────────────────────┐          │
│  │ If consumers are slow (detection/storage):        │          │
│  │ 1. JetStream buffers messages (72h retention)     │          │
│  │ 2. Consumer can replay from any point             │          │
│  │ 3. Max bytes per stream: configurable per tenant  │          │
│  │ 4. If stream full: discard old policy             │          │
│  └─────────────────────────────────────────────────┘          │
│                                                                │
│  Elasticsearch Level:                                          │
│  ┌─────────────────────────────────────────────────┐          │
│  │ If bulk index is slow:                            │          │
│  │ 1. Storage service batches larger (up to 10MB)    │          │
│  │ 2. Exponential backoff on ES 429 responses        │          │
│  │ 3. Events remain in NATS (durability guaranteed)  │          │
│  │ 4. Alert: ES_WRITE_LATENCY_HIGH                   │          │
│  └─────────────────────────────────────────────────┘          │
└──────────────────────────────────────────────────────────────┘
```

## 6.3 Preventing Elasticsearch Bottlenecks

| Problem | Solution |
|---|---|
| Too many small writes | Bulk API with 5MB batches, flush every 5s or when full |
| Refresh interval too aggressive | Set `refresh_interval: 30s` on hot indices (default 1s is unnecessary) |
| Too many shards | 1 primary shard per 50GB. Daily index for <10k agents, weekly for >10k |
| Merge storms | Limit `index.merge.scheduler.max_thread_count: 1` on warm tier |
| Field data cache explosion | Disable `fielddata` on text fields; use `keyword` sub-fields for aggregations |
| Mapping explosion | Strict mappings, no dynamic fields, separate raw index |
| Query-time overhead | Pre-materialized alert index with denormalized data for dashboard queries |
| Disk I/O contention | Separate hot (NVMe) and warm (HDD) tiers on different physical nodes |

## 6.4 Hot / Warm / Cold Storage Model

```
Timeline:
  0────────30 days──────────120 days──────────400 days──────▶ delete

  ┌─────────────────┐
  │    HOT TIER     │  NVMe SSD, 6 nodes, 2 replicas
  │   (0-30 days)   │  Full search capability
  │                 │  Primary write target
  │  sentinel-telemetry-2026.02.27  ← current write index
  │  sentinel-telemetry-2026.02.26
  │  ...                                                
  └────────┬────────┘
           │ ILM rollover at 30d or 50GB
           ▼
  ┌─────────────────┐
  │   WARM TIER     │  HDD, 3 nodes, 1 replica
  │  (30-120 days)  │  Read-only, force-merged
  │                 │  Slower search, but functional
  │  Shrunk to 1 shard per index
  │  Segment-merged for compression                     
  └────────┬────────┘
           │ ILM at 120d
           ▼
  ┌─────────────────┐
  │   COLD TIER     │  S3/MinIO, searchable snapshots
  │ (120-400 days)  │  Searchable but slow (seconds)
  │                 │  Minimal infrastructure cost
  │  Mounted as searchable snapshot
  │  No local disk usage                                
  └────────┬────────┘
           │ ILM at 400d
           ▼
       [DELETED]
```

## 6.5 Failover Handling

| Component | Failure Mode | Recovery | RPO | RTO |
|---|---|---|---|---|
| **Agent** | Process crash | Systemd/SCM auto-restart; BPF pins survive; disk buffer preserves events | 0 (disk buffer) | < 5s |
| **Ingestion Gateway** | Pod crash | K8s restarts; agents reconnect to another replica via load balancer | 0 (agents buffer) | < 10s |
| **NATS node** | Node failure | R3 replication; remaining 2 nodes continue; auto-rebalance | 0 (replicated) | < 2s |
| **Detection Engine** | Pod crash | K8s restarts; NATS replays unacked messages; no data loss | 0 (NATS durable) | < 10s |
| **Elasticsearch node** | Node failure | 2 replicas; cluster remains green; auto-rebalance | 0 (replicated) | < 30s |
| **PostgreSQL** | Primary failure | Async replica promoted; ~1s of alert data may be lost | < 1s | < 30s |
| **Full datacenter** | Outage | Agents buffer to disk (500MB); resume when connectivity restored | 0 | Depends on DC recovery |

## 6.6 Retention Policy Design

| Data Type | Hot | Warm | Cold | Archive | Total |
|---|---|---|---|---|---|
| Normalized telemetry | 30d | 90d | 280d | — | 400d |
| Raw telemetry | 7d | — | 358d | — | 365d |
| Alerts | 90d | 275d | — | — | 365d |
| Agent metadata | Permanent (PG) | — | — | — | ∞ |
| Audit logs | 90d | 275d | — | — | 365d |
| AI analysis reports | Permanent (PG) | — | — | — | ∞ |

**Compliance note**: Retention periods should be configurable per tenant to meet
regulatory requirements (GDPR: right to deletion; HIPAA: 6-year retention;
SOC 2: 1-year minimum).

---

## Appendix A: Migration Path from Current Architecture

### Phase 1 (Weeks 1-4): Foundation
- Deploy NATS JetStream cluster alongside existing Redis
- Create protobuf v2 schema
- Build ingestion gateway (accepts both HTTP/JSON and gRPC/protobuf)
- Agent continues sending HTTP; gateway publishes to NATS

### Phase 2 (Weeks 5-8): Agent Upgrade
- Implement ETW collectors (Windows)
- Implement eBPF collectors (Linux)
- Switch agent transport to gRPC + mTLS
- Enable local detection engine (currently dead code)
- Add disk-based event buffering

### Phase 3 (Weeks 9-12): Backend Decomposition
- Extract detection engine as separate Rust service
- Extract storage service (ES writer)
- Extract enrichment service
- Refactor FastAPI to API-only service (reads from ES/PG)
- Move AI analysis to isolated service

### Phase 4 (Weeks 13-16): Hardening
- Deploy mTLS with per-agent certificates
- Implement secure enrollment flow
- Implement agent self-protection
- Add multi-tenant isolation
- Security audit and penetration test

### Phase 5 (Ongoing): Operational Excellence
- ILM policies and storage tiering
- Horizontal scaling validation (load test 50k agents)
- Runbook creation for operational scenarios
- Incident response playbook integration
