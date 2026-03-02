//! SentinelAI Agent v2 — Transport Module
//!
//! Handles all communication between the agent and the SentinelAI backend.
//! Primary transport: gRPC with mutual TLS (mTLS).
//! Fallback: QUIC for hostile networks that block HTTP/2.
//! Resilience: persistent on-disk event buffer when backend is unreachable.
//!
//! Architecture:
//! ```text
//! EventBatch (from pipeline)
//!      │
//!      ▼
//! ┌──────────────────────────────────────────────────────┐
//! │                Transport Layer                         │
//! │                                                        │
//! │  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐  │
//! │  │ gRPC Client  │  │ QUIC Client  │  │ Disk Buffer  │  │
//! │  │ (primary)    │  │ (fallback)   │  │ (offline)    │  │
//! │  │ mTLS + H2    │  │ mTLS + QUIC  │  │ WAL append   │  │
//! │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
//! │         │                 │                 │          │
//! │         └────────┬────────┘                 │          │
//! │                  │                          │          │
//! │           ┌──────▼───────┐                  │          │
//! │           │   TLS Layer   │                  │          │
//! │           │ (cert mgmt)   │◄─────────────────┘          │
//! │           └───────────────┘  (flush when reconnected)  │
//! └──────────────────────────────────────────────────────┘
//! ```

use std::fmt;
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use crate::event_pipeline::{EventBatch, NormalizedEvent};

// ─── Types ──────────────────────────────────────────────────────

/// Current connection state of the transport layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state, not yet connected.
    Disconnected,
    /// Attempting to establish connection (mTLS handshake).
    Connecting,
    /// Connected and streaming events.
    Connected,
    /// Connection lost, attempting to reconnect.
    Reconnecting {
        /// Number of reconnection attempts so far.
        attempts: u32,
        /// Next retry in milliseconds.
        next_retry_ms: u64,
    },
    /// Backend is reachable but signaling backpressure.
    Backpressure {
        /// Recommended backoff in milliseconds.
        backoff_ms: u64,
    },
    /// Backend unreachable, buffering to disk.
    Buffering,
}

/// Signal from the backend about its capacity to accept events.
#[derive(Debug, Clone)]
pub enum BackpressureSignal {
    /// All good, keep sending.
    Ok,
    /// Slow down: wait this many milliseconds before next batch.
    SlowDown { backoff_ms: u64 },
    /// Stop: backend is overloaded. Buffer to disk.
    Stop,
}

/// Receiver for commands from the backend.
pub struct CommandReceiver {
    rx: tokio::sync::mpsc::Receiver<AgentCommand>,
}

/// Sender for command responses back to the backend.
pub struct ResponseSender {
    tx: tokio::sync::mpsc::Sender<CommandResult>,
}

/// A command received from the backend for execution.
#[derive(Debug, Clone)]
pub struct AgentCommand {
    pub command_id: String,
    pub command_type: CommandType,
    pub parameters: std::collections::HashMap<String, String>,
    pub issued_at_ns: u64,
    pub expires_at_ns: u64,
    pub urgency: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandType {
    UpdatePolicy,
    CollectArtifact,
    IsolateHost,
    UnisolateHost,
    KillProcess,
    ScanFile,
    UpdateRules,
    UpdateIocs,
    RestartAgent,
    UpdateAgent,
    CollectMemoryDump,
    ExecuteResponseScript,
    RotateCertificate,
}

/// Result of executing an agent command.
#[derive(Debug, Clone)]
pub struct CommandResult {
    pub command_id: String,
    pub success: bool,
    pub output: String,
    pub exit_code: Option<i32>,
    pub data: std::collections::HashMap<String, String>,
    pub completed_at_ns: u64,
}

/// Transport-level metrics.
#[derive(Debug, Clone, Default)]
pub struct TransportMetrics {
    pub batches_sent: u64,
    pub batches_failed: u64,
    pub bytes_sent: u64,
    pub reconnections: u64,
    pub disk_buffer_bytes: u64,
    pub disk_buffer_events: u64,
    pub current_state: String,
    pub avg_rtt_ms: f64,
}

// ─── Errors ─────────────────────────────────────────────────────

#[derive(Debug)]
pub enum TransportError {
    /// mTLS handshake failed.
    TlsHandshakeFailed(String),
    /// Certificate expired or invalid.
    CertificateError(String),
    /// Connection refused or timed out.
    ConnectionFailed(String),
    /// Backend returned an error.
    ServerError { status: u32, message: String },
    /// Serialization error (protobuf).
    SerializationError(String),
    /// Disk buffer I/O error.
    BufferError(String),
    /// Generic I/O error.
    Io(std::io::Error),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TlsHandshakeFailed(e) => write!(f, "TLS handshake failed: {e}"),
            Self::CertificateError(e) => write!(f, "certificate error: {e}"),
            Self::ConnectionFailed(e) => write!(f, "connection failed: {e}"),
            Self::ServerError { status, message } => {
                write!(f, "server error (status {status}): {message}")
            }
            Self::SerializationError(e) => write!(f, "serialization error: {e}"),
            Self::BufferError(e) => write!(f, "buffer error: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for TransportError {}

// ─── Trait ──────────────────────────────────────────────────────

/// Handles all communication with the SentinelAI backend.
///
/// # Connection Lifecycle
///
/// 1. `connect()` — Perform mTLS handshake, validate server certificate.
/// 2. `send_batch()` — Stream event batches. Returns backpressure signal.
/// 3. `command_stream()` — Open bidirectional command channel.
/// 4. `rotate_certificate()` — Handle cert renewal before expiry.
///
/// # Resilience
///
/// If the backend is unreachable:
/// 1. Events are buffered to disk (append-only WAL).
/// 2. Reconnection uses exponential backoff (1s, 2s, 4s, ..., 60s max).
/// 3. When reconnected, disk buffer is flushed (oldest first).
/// 4. If disk buffer exceeds `max_disk_buffer_mb`, oldest events are evicted.
///
/// # Certificate Management
///
/// - Agent cert is loaded from `certs/agent.crt` + `certs/agent.key`.
/// - CA chain is loaded from `certs/ca.crt`.
/// - If cert expires in < 10 days, `rotate_certificate()` is called.
/// - During rotation, the old cert is used for the renewal request.
/// - After rotation, the new cert is atomically swapped in.
#[async_trait]
pub trait TransportClient: Send + Sync + 'static {
    /// Establish connection to the backend (mTLS handshake).
    ///
    /// This should:
    /// 1. Load agent certificate and private key.
    /// 2. Load CA certificate chain.
    /// 3. Perform TLS handshake with server cert validation.
    /// 4. Verify server certificate CN matches expected backend identity.
    async fn connect(&mut self) -> Result<(), TransportError>;

    /// Stream a batch of events to the backend.
    ///
    /// Returns a backpressure signal:
    /// - `Ok` — keep sending at current rate
    /// - `SlowDown { backoff_ms }` — reduce rate
    /// - `Stop` — buffer to disk
    async fn send_batch(
        &self,
        batch: EventBatch,
    ) -> Result<BackpressureSignal, TransportError>;

    /// Open bidirectional command channel.
    ///
    /// The backend pushes commands (kill process, isolate host, etc.)
    /// through the returned receiver. The agent sends command results
    /// through the returned sender.
    async fn command_stream(
        &self,
    ) -> Result<(CommandReceiver, ResponseSender), TransportError>;

    /// Perform certificate rotation.
    ///
    /// 1. Generate new ECDSA P-256 key pair.
    /// 2. Create CSR with current agent_guid as CN.
    /// 3. Send renewal request (authenticated with current cert).
    /// 4. Receive new cert from CA.
    /// 5. Atomically swap cert files on disk.
    /// 6. Reconnect with new cert.
    async fn rotate_certificate(&mut self) -> Result<(), TransportError>;

    /// Current connection state.
    fn state(&self) -> ConnectionState;

    /// Transport-level metrics.
    fn metrics(&self) -> TransportMetrics;
}

// ─── Submodules ─────────────────────────────────────────────────

pub mod grpc_client;
pub mod quic_client;
pub mod buffer;
pub mod enrollment;
pub mod tls;
