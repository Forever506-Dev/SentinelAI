//! SentinelAI Agent v2 — Event Pipeline Module
//!
//! Normalizes raw platform-specific events into a canonical schema,
//! enriches them with process GUIDs and file hashes, applies filtering
//! and rate limiting, and batches them for transport.
//!
//! Architecture:
//! ```text
//! EventSource (raw events from collectors)
//!      │
//!      ▼
//! ┌─────────────┐     ┌──────────────┐     ┌──────────┐     ┌────────────┐
//! │ Normalizer   │────▶│  Enricher     │────▶│  Filter   │────▶│ Aggregator │
//! │              │     │              │     │          │     │            │
//! │ RawEvent →   │     │ Add process  │     │ Dedup,   │     │ Batch up   │
//! │ Normalized   │     │ GUID, hashes │     │ suppress │     │ to 100 or  │
//! │ Event        │     │ user resolve │     │ noise    │     │ 5s timer   │
//! └─────────────┘     └──────────────┘     └──────────┘     └────────────┘
//!                                                                  │
//!                                                                  ▼
//!                                           ┌──────────────────────────────┐
//!                                           │  EventBatch → Transport      │
//!                                           │  EventBatch → LocalDetection │
//!                                           └──────────────────────────────┘
//! ```

use std::fmt;
use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::collector::EventSource;

// ─── Types ──────────────────────────────────────────────────────

/// Normalized event in the canonical SentinelAI schema.
/// This maps 1:1 to the protobuf `TelemetryEvent` message.
#[derive(Debug, Clone)]
pub struct NormalizedEvent {
    /// UUIDv7 (time-ordered).
    pub event_id: String,
    pub category: crate::collector::EventCategory,
    pub action: String,
    pub source: String,
    pub host_guid: String,

    // Timestamps
    pub wall_clock_ns: u64,
    pub monotonic_ns: u64,
    pub processed_at_ns: u64,

    // Risk assessment (set by local detection, default 0)
    pub risk_score: u32,
    pub mitre_techniques: Vec<String>,
    pub tags: Vec<String>,

    // Type-specific payload (serialized protobuf bytes)
    pub payload_bytes: Vec<u8>,
}

/// A batch of normalized events ready for transport.
#[derive(Debug, Clone)]
pub struct EventBatch {
    pub batch_id: String,
    pub agent_id: String,
    pub sequence_number: u32,
    pub events: Vec<NormalizedEvent>,
    pub events_dropped_since_last: u64,
    pub sent_at_ns: u64,
}

/// Pipeline-level operational metrics.
#[derive(Debug, Clone, Default)]
pub struct PipelineMetrics {
    pub events_received: u64,
    pub events_normalized: u64,
    pub events_enriched: u64,
    pub events_filtered: u64,
    pub events_batched: u64,
    pub events_dropped: u64,
    pub batches_sent: u64,
    pub current_batch_size: usize,
    pub backpressure_active: bool,
    pub avg_latency_us: u64,
}

/// Policy for noise reduction and rate limiting.
#[derive(Debug, Clone)]
pub struct FilterPolicy {
    /// Process names to suppress entirely.
    pub suppress_process_names: Vec<String>,
    /// File path prefixes to suppress.
    pub suppress_file_paths: Vec<String>,
    /// Destination IPs to suppress.
    pub suppress_dest_ips: Vec<String>,
    /// Max events per second per category before rate limiting.
    pub max_events_per_sec_per_category: u32,
    /// Dedup window in milliseconds (suppress identical events within this window).
    pub dedup_window_ms: u64,
}

impl Default for FilterPolicy {
    fn default() -> Self {
        Self {
            suppress_process_names: Vec::new(),
            suppress_file_paths: Vec::new(),
            suppress_dest_ips: Vec::new(),
            max_events_per_sec_per_category: 1000,
            dedup_window_ms: 1000,
        }
    }
}

// ─── Errors ─────────────────────────────────────────────────────

#[derive(Debug)]
pub enum PipelineError {
    ChannelClosed,
    NormalizationFailed(String),
    EnrichmentFailed(String),
    Io(std::io::Error),
}

impl fmt::Display for PipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChannelClosed => write!(f, "pipeline channel closed"),
            Self::NormalizationFailed(e) => write!(f, "normalization failed: {e}"),
            Self::EnrichmentFailed(e) => write!(f, "enrichment failed: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for PipelineError {}

// ─── Trait ──────────────────────────────────────────────────────

/// Normalizes, enriches, filters, and batches raw telemetry events.
///
/// The pipeline consumes from an `EventSource` (connected to collectors)
/// and produces:
/// 1. `NormalizedEvent` stream → sent to local detection engine
/// 2. `EventBatch` stream → sent to transport layer
///
/// # Backpressure
///
/// If the transport channel is full (backend unreachable), the pipeline:
/// 1. Drops lowest-severity events first (system metrics, then network, etc.)
/// 2. Preserves high-severity events (process exec, auth failures)
/// 3. Increments `events_dropped` counter (included in next batch)
/// 4. Emits a BACKPRESSURE_ACTIVE tag on remaining events
#[async_trait]
pub trait EventPipeline: Send + Sync + 'static {
    /// Run the pipeline. Consumes raw events, produces normalized batches.
    ///
    /// - `source`: Raw events from telemetry providers
    /// - `detection_tx`: Channel to local detection engine (unbounded)
    /// - `transport_tx`: Channel to transport layer (bounded — backpressure)
    /// - `cancel`: Cancellation token for graceful shutdown
    async fn run(
        &mut self,
        source: EventSource,
        detection_tx: mpsc::UnboundedSender<NormalizedEvent>,
        transport_tx: mpsc::Sender<EventBatch>,
        cancel: CancellationToken,
    ) -> Result<(), PipelineError>;

    /// Current pipeline metrics.
    fn metrics(&self) -> PipelineMetrics;

    /// Update filtering rules at runtime (from backend policy push).
    fn update_filter_policy(&mut self, policy: FilterPolicy);
}

// ─── Submodules ─────────────────────────────────────────────────

pub mod normalizer;
pub mod enricher;
pub mod filter;
pub mod aggregator;
pub mod ring_buffer;
