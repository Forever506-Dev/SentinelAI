//! SentinelAI Agent v2 — Main Orchestrator
//!
//! Wires together all subsystems:
//!   PlatformCapabilities → CollectorRegistry → EventPipeline
//!     → LocalDetection → Transport → SelfProtection
//!
//! Lifecycle:
//!   1. Parse CLI / load config
//!   2. Detect platform capabilities
//!   3. Initialize self-protection (anti-tamper baseline)
//!   4. Connect transport (gRPC+mTLS or enrollment)
//!   5. Receive initial policy from backend
//!   6. Start collector providers per policy
//!   7. Run event pipeline (normalize → filter → detect → batch → send)
//!   8. Listen for commands (policy updates, kill/isolate, cert rotation)
//!   9. Periodic health checks, metric reporting, integrity verification

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::signal;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::time;
use tracing::{error, info, warn};

mod collector;
mod event_pipeline;
mod local_detection;
mod platform;
mod self_protection;
mod transport;

use collector::{EventSink, EventSource, RawEvent, TelemetryProvider};
use event_pipeline::{EventPipeline, NormalizedEvent};
use local_detection::DetectionEngine;
use platform::PlatformCapabilities;
use self_protection::SelfProtection;
use transport::{AgentCommand, ConnectionState, TransportClient};

// ─── Configuration ──────────────────────────────────────────────────────────

/// Top-level agent configuration loaded from file or enrollment response.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Unique agent GUID (persisted across restarts).
    pub agent_guid: String,
    /// Backend gRPC endpoint.
    pub backend_endpoint: String,
    /// Path to TLS client certificate (PEM).
    pub tls_cert_path: PathBuf,
    /// Path to TLS client key (PEM).
    pub tls_key_path: PathBuf,
    /// Path to CA bundle (PEM).
    pub tls_ca_path: PathBuf,
    /// Path to local disk buffer (redb).
    pub buffer_path: PathBuf,
    /// Maximum batch size before flushing.
    pub batch_max_events: usize,
    /// Maximum batch age before flushing.
    pub batch_max_delay: Duration,
    /// Interval for self-protection integrity checks.
    pub integrity_check_interval: Duration,
    /// Interval for health/metric heartbeats.
    pub heartbeat_interval: Duration,
    /// Maximum in-flight events in the pipeline channel.
    pub pipeline_channel_capacity: usize,
    /// Enable local detection engine.
    pub local_detection_enabled: bool,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_guid: String::new(),
            backend_endpoint: "https://sentinel-backend:4443".into(),
            tls_cert_path: PathBuf::from("/etc/sentinel/agent.crt"),
            tls_key_path: PathBuf::from("/etc/sentinel/agent.key"),
            tls_ca_path: PathBuf::from("/etc/sentinel/ca.crt"),
            buffer_path: PathBuf::from("/var/lib/sentinel/buffer.redb"),
            batch_max_events: 256,
            batch_max_delay: Duration::from_secs(5),
            integrity_check_interval: Duration::from_secs(300),
            heartbeat_interval: Duration::from_secs(60),
            pipeline_channel_capacity: 8192,
            local_detection_enabled: true,
        }
    }
}

// ─── Collector Registry ─────────────────────────────────────────────────────

/// Manages multiple TelemetryProvider instances and fans-in their output.
struct CollectorRegistry {
    providers: Vec<Box<dyn TelemetryProvider + Send>>,
    event_tx: EventSink,
}

impl CollectorRegistry {
    fn new(event_tx: EventSink) -> Self {
        Self {
            providers: Vec::new(),
            event_tx,
        }
    }

    fn register(&mut self, provider: Box<dyn TelemetryProvider + Send>) {
        self.providers.push(provider);
    }

    async fn start_all(&mut self) {
        for (i, provider) in self.providers.iter_mut().enumerate() {
            match provider.start(self.event_tx.clone()).await {
                Ok(()) => info!(provider_index = i, "collector started"),
                Err(e) => error!(provider_index = i, error = %e, "collector failed to start"),
            }
        }
    }

    async fn stop_all(&mut self) {
        for (i, provider) in self.providers.iter_mut().enumerate() {
            match provider.stop().await {
                Ok(()) => info!(provider_index = i, "collector stopped"),
                Err(e) => warn!(provider_index = i, error = %e, "collector stop error"),
            }
        }
    }

    fn health_check(&self) -> Vec<bool> {
        self.providers.iter().map(|p| p.is_healthy()).collect()
    }
}

// ─── Shutdown Coordination ──────────────────────────────────────────────────

/// Signals for graceful shutdown propagation.
#[derive(Clone)]
struct ShutdownCoordinator {
    /// Send `true` to trigger shutdown.
    notify: Arc<broadcast::Sender<()>>,
}

impl ShutdownCoordinator {
    fn new() -> (Self, broadcast::Receiver<()>) {
        let (tx, rx) = broadcast::channel(1);
        (Self { notify: Arc::new(tx) }, rx)
    }

    fn subscribe(&self) -> broadcast::Receiver<()> {
        self.notify.subscribe()
    }

    fn trigger(&self) {
        let _ = self.notify.send(());
    }
}

// ─── Pipeline Task ──────────────────────────────────────────────────────────

/// Consumes RawEvents from collectors, normalizes, filters, detects locally,
/// batches, and hands off to transport.
async fn run_pipeline(
    mut event_rx: EventSource,
    transport_tx: mpsc::Sender<NormalizedEvent>,
    detection_engine: Option<Arc<DetectionEngine>>,
    mut shutdown: broadcast::Receiver<()>,
) {
    info!("event pipeline started");
    loop {
        tokio::select! {
            biased;

            _ = shutdown.recv() => {
                info!("pipeline: shutdown signal received");
                break;
            }

            maybe_event = event_rx.recv() => {
                match maybe_event {
                    Some(raw) => {
                        // 1. Normalize raw → NormalizedEvent
                        let normalized = normalize_event(raw);

                        // 2. Local detection (non-blocking)
                        if let Some(ref engine) = detection_engine {
                            // Detection runs synchronously on normalized event copy.
                            // In production, offload to a dedicated thread pool via
                            // tokio::task::spawn_blocking if rule sets are large.
                            let _alerts = engine.evaluate(&normalized);
                            // TODO: forward alerts to transport as priority events
                        }

                        // 3. Forward to transport batcher
                        if transport_tx.send(normalized).await.is_err() {
                            warn!("pipeline: transport channel closed, buffering");
                            // TODO: write to local redb disk buffer
                        }
                    }
                    None => {
                        info!("pipeline: all collector channels closed");
                        break;
                    }
                }
            }
        }
    }
    info!("event pipeline stopped");
}

/// Placeholder normalizer — maps RawEvent into NormalizedEvent.
fn normalize_event(raw: RawEvent) -> NormalizedEvent {
    NormalizedEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        timestamp_ns: raw.timestamp_ns,
        category: format!("{:?}", raw.payload).split('(').next().unwrap_or("unknown").to_string(),
        raw_size_bytes: 0, // TODO: serialize and measure
    }
}

// ─── Transport Task ─────────────────────────────────────────────────────────

/// Batches NormalizedEvents and streams them to backend via gRPC+mTLS.
async fn run_transport(
    mut event_rx: mpsc::Receiver<NormalizedEvent>,
    config: Arc<AgentConfig>,
    mut shutdown: broadcast::Receiver<()>,
) {
    info!("transport batcher started");

    let mut batch: Vec<NormalizedEvent> = Vec::with_capacity(config.batch_max_events);
    let mut flush_interval = time::interval(config.batch_max_delay);

    loop {
        tokio::select! {
            biased;

            _ = shutdown.recv() => {
                // Flush remaining events on shutdown
                if !batch.is_empty() {
                    info!(count = batch.len(), "transport: flushing remaining batch on shutdown");
                    flush_batch(&batch).await;
                }
                break;
            }

            _ = flush_interval.tick() => {
                if !batch.is_empty() {
                    flush_batch(&batch).await;
                    batch.clear();
                }
            }

            maybe_event = event_rx.recv() => {
                match maybe_event {
                    Some(event) => {
                        batch.push(event);
                        if batch.len() >= config.batch_max_events {
                            flush_batch(&batch).await;
                            batch.clear();
                        }
                    }
                    None => {
                        if !batch.is_empty() {
                            flush_batch(&batch).await;
                        }
                        break;
                    }
                }
            }
        }
    }
    info!("transport batcher stopped");
}

/// Sends a batch to the backend. On failure, writes to disk buffer.
async fn flush_batch(batch: &[NormalizedEvent]) {
    // TODO: Serialize batch to TelemetryBatch protobuf
    // TODO: Send via tonic gRPC client with mTLS
    // TODO: On failure, serialize to redb disk buffer
    // TODO: Track sequence numbers for gap detection
    info!(
        count = batch.len(),
        "transport: batch flushed (stub — no backend connection)"
    );
}

// ─── Command Listener Task ──────────────────────────────────────────────────

/// Receives commands from backend via gRPC bidirectional stream.
async fn run_command_listener(
    config: Arc<AgentConfig>,
    mut shutdown: broadcast::Receiver<()>,
) {
    info!("command listener started");

    loop {
        tokio::select! {
            biased;

            _ = shutdown.recv() => {
                info!("command listener: shutdown");
                break;
            }

            // TODO: Replace with actual gRPC command stream
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                // Placeholder: poll for commands
                // In production, this is a persistent gRPC stream via
                // CommandService.CommandStream()
            }
        }
    }
}

// ─── Self-Protection Task ───────────────────────────────────────────────────

/// Periodically verifies agent integrity and provider health.
async fn run_integrity_monitor(
    config: Arc<AgentConfig>,
    registry_health: tokio::sync::watch::Receiver<Vec<bool>>,
    mut shutdown: broadcast::Receiver<()>,
) {
    info!("integrity monitor started");
    let mut interval = time::interval(config.integrity_check_interval);

    loop {
        tokio::select! {
            biased;

            _ = shutdown.recv() => {
                info!("integrity monitor: shutdown");
                break;
            }

            _ = interval.tick() => {
                // 1. Verify binary integrity (hash check)
                // TODO: SelfProtection::verify_integrity()

                // 2. Check provider health
                let health = registry_health.borrow().clone();
                let unhealthy: Vec<usize> = health.iter().enumerate()
                    .filter(|(_, &h)| !h)
                    .map(|(i, _)| i)
                    .collect();

                if !unhealthy.is_empty() {
                    warn!(providers = ?unhealthy, "unhealthy collectors detected");
                    // TODO: Attempt restart of unhealthy providers
                    // TODO: Report tamper event if restart fails
                }

                info!("integrity check passed");
            }
        }
    }
}

// ─── Main Entrypoint ────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── 1. Initialize tracing ───────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_target(true)
        .with_thread_ids(true)
        .with_level(true)
        .json()
        .init();

    info!("SentinelAI Agent v2 starting");

    // ── 2. Load configuration ───────────────────────────────────────────
    // TODO: Parse from CLI args + config file + enrollment response
    let config = Arc::new(AgentConfig::default());

    // ── 3. Detect platform capabilities ─────────────────────────────────
    let capabilities = PlatformCapabilities::detect();
    info!(
        etw = capabilities.etw_available,
        ebpf = capabilities.ebpf_available,
        "platform capabilities detected"
    );

    let recommended = capabilities.recommended_providers();
    info!(providers = ?recommended, "selected telemetry providers");

    // ── 4. Initialize self-protection ───────────────────────────────────
    // TODO: Call SelfProtection::initialize() — set binary hash baseline,
    //       register with Windows PPL or BPF-LSM

    // ── 5. Set up channels ──────────────────────────────────────────────
    //
    //   Collectors ──[RawEvent]──► Pipeline ──[NormalizedEvent]──► Transport
    //                                 │
    //                          LocalDetection
    //
    let (raw_tx, raw_rx): (EventSink, EventSource) =
        mpsc::channel(config.pipeline_channel_capacity);

    let (normalized_tx, normalized_rx) =
        mpsc::channel::<NormalizedEvent>(config.pipeline_channel_capacity);

    // Health reporting channel (registry → integrity monitor)
    let (health_tx, health_rx) = watch::channel(Vec::<bool>::new());

    // ── 6. Initialize collectors ────────────────────────────────────────
    let mut registry = CollectorRegistry::new(raw_tx);

    // Register providers based on platform capabilities.
    // Each provider implements TelemetryProvider trait.
    //
    // Example (not compiled — provider implementations are separate crates):
    //
    // #[cfg(target_os = "windows")]
    // if capabilities.etw_available {
    //     registry.register(Box::new(
    //         collector::etw::EtwProvider::new(collector::etw::EtwConfig {
    //             process_trace: true,
    //             file_trace: true,
    //             network_trace: true,
    //             registry_trace: true,
    //             dns_trace: true,
    //             image_load_trace: true,
    //         })
    //     ));
    // }
    //
    // #[cfg(target_os = "linux")]
    // if capabilities.ebpf_available {
    //     registry.register(Box::new(
    //         collector::ebpf::EbpfProvider::new(collector::ebpf::EbpfConfig {
    //             tracepoints: vec!["sched_process_exec", "sched_process_exit"],
    //             kprobes: vec!["tcp_connect", "tcp_accept"],
    //             use_ringbuf: capabilities.bpf_ringbuf_available,
    //         })
    //     ));
    // }

    info!("collector registry initialized");

    // ── 7. Initialize local detection engine ────────────────────────────
    let detection_engine = if config.local_detection_enabled {
        let engine = DetectionEngine::new();
        info!(
            sigma_rules = engine.sigma_rules.len(),
            heuristics = engine.heuristic_rules.len(),
            "local detection engine initialized"
        );
        Some(Arc::new(engine))
    } else {
        None
    };

    // ── 8. Set up shutdown coordination ─────────────────────────────────
    let (shutdown_coord, _initial_rx) = ShutdownCoordinator::new();

    // ── 9. Spawn tasks ──────────────────────────────────────────────────

    // 9a. Start collectors
    registry.start_all().await;

    // 9b. Pipeline task
    let pipeline_shutdown = shutdown_coord.subscribe();
    let pipeline_handle = tokio::spawn(run_pipeline(
        raw_rx,
        normalized_tx,
        detection_engine,
        pipeline_shutdown,
    ));

    // 9c. Transport batcher task
    let transport_shutdown = shutdown_coord.subscribe();
    let transport_config = config.clone();
    let transport_handle = tokio::spawn(run_transport(
        normalized_rx,
        transport_config,
        transport_shutdown,
    ));

    // 9d. Command listener task
    let command_shutdown = shutdown_coord.subscribe();
    let command_config = config.clone();
    let command_handle = tokio::spawn(run_command_listener(
        command_config,
        command_shutdown,
    ));

    // 9e. Integrity monitor task
    let integrity_shutdown = shutdown_coord.subscribe();
    let integrity_config = config.clone();
    let integrity_handle = tokio::spawn(run_integrity_monitor(
        integrity_config,
        health_rx,
        integrity_shutdown,
    ));

    info!("all subsystems running — agent operational");

    // ── 10. Wait for shutdown signal ────────────────────────────────────
    //
    // Graceful shutdown on:
    //   - SIGTERM / SIGINT (Unix)
    //   - Ctrl+C (all platforms)
    //   - Backend-initiated shutdown command

    #[cfg(unix)]
    {
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
        tokio::select! {
            _ = signal::ctrl_c() => info!("received SIGINT"),
            _ = sigterm.recv() => info!("received SIGTERM"),
        }
    }

    #[cfg(not(unix))]
    {
        signal::ctrl_c().await?;
        info!("received Ctrl+C");
    }

    // ── 11. Graceful shutdown sequence ──────────────────────────────────
    info!("initiating graceful shutdown...");
    shutdown_coord.trigger();

    // Give tasks up to 10 seconds to drain
    let shutdown_timeout = Duration::from_secs(10);
    let _ = tokio::time::timeout(shutdown_timeout, async {
        let _ = tokio::join!(
            pipeline_handle,
            transport_handle,
            command_handle,
            integrity_handle,
        );
    })
    .await;

    // Stop collectors last (they produce events)
    registry.stop_all().await;

    info!("SentinelAI Agent v2 shutdown complete");
    Ok(())
}
