//! SentinelAI Agent v2 — Collector Module
//!
//! This module defines the `TelemetryProvider` trait and the collector
//! registry that manages platform-specific telemetry sources.
//!
//! Architecture:
//! ```text
//! Platform Providers (ETW / eBPF / Fallback)
//!        │
//!        ▼  push RawEvent
//!   EventSink (lock-free ring buffer)
//!        │
//!        ▼  consumed by
//!   EventPipeline (normalizer → enricher → filter → aggregator)
//! ```

use std::fmt;
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

// ─── Types ──────────────────────────────────────────────────────

/// Categories of events a provider can emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventCategory {
    Process,
    File,
    Network,
    Dns,
    Auth,
    Registry,
    ModuleLoad,
    System,
    Tamper,
}

/// Raw event produced by a telemetry provider before normalization.
#[derive(Debug, Clone)]
pub struct RawEvent {
    /// Which category this event belongs to.
    pub category: EventCategory,
    /// Platform-specific action string ("create", "terminate", "connect", etc.)
    pub action: String,
    /// Monotonic timestamp (nanoseconds since boot).
    pub monotonic_ns: u64,
    /// Wall-clock timestamp (nanoseconds since Unix epoch).
    pub wall_clock_ns: u64,
    /// Source provider name (e.g., "etw::process", "ebpf::execve").
    pub source: String,
    /// Platform-specific payload (will be normalized by EventPipeline).
    pub payload: RawPayload,
}

/// Platform-specific event payload before normalization.
#[derive(Debug, Clone)]
pub enum RawPayload {
    Process(RawProcessEvent),
    File(RawFileEvent),
    Network(RawNetworkEvent),
    Dns(RawDnsEvent),
    Auth(RawAuthEvent),
    Registry(RawRegistryEvent),
    ModuleLoad(RawModuleLoadEvent),
    System(RawSystemEvent),
    Tamper(RawTamperEvent),
}

#[derive(Debug, Clone)]
pub struct RawProcessEvent {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe_path: String,
    pub command_line: String,
    pub user_id: String,
    pub user_name: String,
    pub session_id: u32,
    pub memory_bytes: u64,
    pub cpu_percent: f32,
    pub thread_count: u32,
    pub creation_flags: u32,
    pub start_time_ns: u64,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct RawFileEvent {
    pub path: String,
    pub old_path: Option<String>,
    pub size: u64,
    pub attributes: u32,
    pub actor_pid: u32,
}

#[derive(Debug, Clone)]
pub struct RawNetworkEvent {
    pub source_ip: String,
    pub source_port: u32,
    pub dest_ip: String,
    pub dest_port: u32,
    pub protocol: u8, // IPPROTO_TCP=6, IPPROTO_UDP=17
    pub state: String,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub owner_pid: u32,
}

#[derive(Debug, Clone)]
pub struct RawDnsEvent {
    pub query_name: String,
    pub query_type: String,
    pub answers: Vec<String>,
    pub rcode: u32,
    pub ttl: u32,
    pub querying_pid: u32,
    pub response_time_us: u32,
}

#[derive(Debug, Clone)]
pub struct RawAuthEvent {
    pub auth_type: String,
    pub auth_method: String,
    pub success: bool,
    pub username: String,
    pub domain: String,
    pub user_sid: String,
    pub source_ip: String,
    pub source_port: u32,
    pub logon_type: u32,
    pub failure_reason: String,
}

#[derive(Debug, Clone)]
pub struct RawRegistryEvent {
    pub hive: String,
    pub key_path: String,
    pub value_name: String,
    pub value_data: String,
    pub value_type: u32,
    pub old_value_data: Option<String>,
    pub actor_pid: u32,
}

#[derive(Debug, Clone)]
pub struct RawModuleLoadEvent {
    pub module_path: String,
    pub loading_pid: u32,
    pub signer: String,
    pub is_signed: bool,
    pub base_address: u64,
    pub image_size: u64,
}

#[derive(Debug, Clone)]
pub struct RawSystemEvent {
    pub metric_type: String,
    pub metrics: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct RawTamperEvent {
    pub tamper_type: TamperType,
    pub description: String,
    pub suspect_pid: Option<u32>,
    pub context: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TamperType {
    EtwSessionStopped,
    EbpfProgramDetached,
    AgentProcessInjected,
    AgentBinaryModified,
    CanaryEventMissing,
    ServiceConfigChanged,
    CertificateTampered,
    EventFloodDetected,
}

/// Handle to push events into the pipeline.
/// Wraps a lock-free ring buffer producer.
pub struct EventSink {
    // In production: crossbeam ring buffer or custom SPSC
    tx: tokio::sync::mpsc::Sender<RawEvent>,
}

impl EventSink {
    pub fn new(tx: tokio::sync::mpsc::Sender<RawEvent>) -> Self {
        Self { tx }
    }

    /// Push an event into the sink. Returns false if the buffer is full
    /// (backpressure — caller should increment drop counter).
    pub fn try_push(&self, event: RawEvent) -> bool {
        self.tx.try_send(event).is_ok()
    }

    /// Push with async backpressure (blocks until space available).
    pub async fn push(&self, event: RawEvent) -> Result<(), CollectorError> {
        self.tx.send(event).await.map_err(|_| CollectorError::SinkClosed)
    }
}

/// Handle to consume events from providers.
pub struct EventSource {
    rx: tokio::sync::mpsc::Receiver<RawEvent>,
}

impl EventSource {
    pub fn new(rx: tokio::sync::mpsc::Receiver<RawEvent>) -> Self {
        Self { rx }
    }

    pub async fn recv(&mut self) -> Option<RawEvent> {
        self.rx.recv().await
    }
}

/// Create a linked (sink, source) pair with the given buffer capacity.
pub fn event_channel(capacity: usize) -> (EventSink, EventSource) {
    let (tx, rx) = tokio::sync::mpsc::channel(capacity);
    (EventSink::new(tx), EventSource::new(rx))
}

// ─── Metrics ────────────────────────────────────────────────────

/// Per-provider operational metrics.
#[derive(Debug, Clone, Default)]
pub struct ProviderMetrics {
    /// Total events emitted since provider start.
    pub events_emitted: u64,
    /// Events dropped due to ring buffer full.
    pub events_dropped: u64,
    /// Current events per second (exponential moving average).
    pub events_per_second: f64,
    /// Errors encountered.
    pub errors: u64,
    /// Whether the provider is currently healthy.
    pub healthy: bool,
}

/// Provider health status for self-protection monitoring.
#[derive(Debug, Clone)]
pub struct ProviderHealthStatus {
    pub name: String,
    pub healthy: bool,
    pub last_event_age_ms: u64,
    pub details: String,
}

// ─── Errors ─────────────────────────────────────────────────────

#[derive(Debug)]
pub enum CollectorError {
    /// The event sink (ring buffer) is closed.
    SinkClosed,
    /// Platform API error (ETW, eBPF, etc.).
    PlatformError(String),
    /// Permission denied (need admin/root/CAP_BPF).
    PermissionDenied(String),
    /// Provider was tampered with.
    Tampered(String),
    /// Generic I/O error.
    Io(std::io::Error),
}

impl fmt::Display for CollectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SinkClosed => write!(f, "event sink closed"),
            Self::PlatformError(e) => write!(f, "platform error: {e}"),
            Self::PermissionDenied(e) => write!(f, "permission denied: {e}"),
            Self::Tampered(e) => write!(f, "tamper detected: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for CollectorError {}

impl From<std::io::Error> for CollectorError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// ─── Trait ──────────────────────────────────────────────────────

/// A platform-specific telemetry source that produces raw events.
///
/// # Implementors
///
/// - `etw::ProcessProvider` — Windows ETW kernel process events
/// - `etw::FileProvider` — Windows ETW kernel file events
/// - `etw::NetworkProvider` — Windows ETW kernel network events
/// - `etw::RegistryProvider` — Windows ETW kernel registry events
/// - `etw::DnsProvider` — Windows DNS client events
/// - `ebpf::ProcessProbe` — Linux eBPF execve tracepoint
/// - `ebpf::FileProbe` — Linux eBPF openat tracepoint
/// - `ebpf::NetworkProbe` — Linux eBPF tcp_connect kprobe
/// - `android::AuditProvider` — Android SELinux audit log
/// - `android::ProcProvider` — Android /proc fallback
/// - `fallback::PollingProvider` — sysinfo-based polling (any platform)
///
/// # Contract
///
/// - `start()` must not block. It should spawn internal tasks and return.
/// - Events must be pushed into the provided `EventSink`.
/// - `is_healthy()` must detect provider tampering (ETW session killed,
///   eBPF program detached, etc.).
/// - `stop()` must flush pending events and release OS resources.
#[async_trait]
pub trait TelemetryProvider: Send + Sync + 'static {
    /// Human-readable name for logging and metrics.
    /// Examples: "etw::process", "ebpf::execve", "fallback::sysinfo"
    fn name(&self) -> &str;

    /// Event categories this provider can emit.
    fn capabilities(&self) -> &[EventCategory];

    /// Start the provider. Must not block — spawn internal tasks.
    /// Events are pushed into the provided sink.
    async fn start(
        &mut self,
        sink: EventSink,
        cancel: CancellationToken,
    ) -> Result<(), CollectorError>;

    /// Gracefully stop. Flush any pending events and release OS resources.
    async fn stop(&mut self) -> Result<(), CollectorError>;

    /// Health check — returns false if the provider has been tampered with.
    ///
    /// Examples of tamper detection:
    /// - ETW: QueryAllTraces() to verify session exists
    /// - eBPF: Check /sys/fs/bpf/sentinel/ pins still present
    /// - Fallback: Verify /proc is accessible
    async fn is_healthy(&self) -> bool;

    /// Return provider-specific operational metrics.
    fn metrics(&self) -> ProviderMetrics;
}

// ─── Submodules ─────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub mod etw;

#[cfg(target_os = "linux")]
pub mod ebpf;

#[cfg(target_os = "android")]
pub mod android;

pub mod fallback;
pub mod registry;
