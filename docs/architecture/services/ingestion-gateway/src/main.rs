//! SentinelAI Ingestion Gateway
//!
//! Rust gRPC server that terminates agent mTLS connections,
//! validates certificates, rate-limits per agent, and publishes
//! to NATS JetStream.
//!
//! Deployment: 2+ replicas behind L4 load balancer.
//! Exposed port: 4443 (gRPC + mTLS)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::sync::RwLock;
use tonic::{Request, Response, Status, Code};
use tracing::{error, info, warn};

// ─── Proto-generated types (from sentinel_v2.proto) ─────────────────────────

// In production, these come from `tonic-build` codegen:
//   pub mod sentinel_v2 {
//       tonic::include_proto!("sentinel.v2");
//   }
//
// Stubbed here for architecture demonstration.

pub struct TelemetryBatch {
    pub agent_guid: String,
    pub sequence_number: u64,
    pub events: Vec<TelemetryEvent>,
    pub compression: i32,
    pub batch_created_at_ns: u64,
    pub events_dropped: u64,
}

pub struct TelemetryEvent {
    pub event_id: String,
    pub category: i32,
    pub payload: Vec<u8>,
}

pub struct BatchAck {
    pub accepted: u64,
    pub rejected: u64,
    pub server_time_ns: u64,
    pub backpressure: bool,
    pub next_expected_sequence: u64,
}

// ─── Rate Limiter ───────────────────────────────────────────────────────────

/// Per-agent token-bucket rate limiter.
struct RateLimiter {
    /// Map of agent_guid → bucket state
    buckets: DashMap<String, TokenBucket>,
    /// Default events per second per agent
    default_rate: u64,
    /// Default burst capacity
    default_burst: u64,
}

struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl RateLimiter {
    fn new(default_rate: u64, default_burst: u64) -> Self {
        Self {
            buckets: DashMap::new(),
            default_rate,
            default_burst,
        }
    }

    /// Returns true if the request is allowed, false if rate-limited.
    fn check_and_consume(&self, agent_guid: &str, event_count: u64) -> bool {
        let mut bucket = self.buckets.entry(agent_guid.to_string()).or_insert_with(|| {
            TokenBucket {
                tokens: self.default_burst as f64,
                max_tokens: self.default_burst as f64,
                refill_rate: self.default_rate as f64,
                last_refill: Instant::now(),
            }
        });

        // Refill tokens based on elapsed time
        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * bucket.refill_rate).min(bucket.max_tokens);
        bucket.last_refill = now;

        // Try to consume
        let cost = event_count as f64;
        if bucket.tokens >= cost {
            bucket.tokens -= cost;
            true
        } else {
            false
        }
    }
}

// ─── Sequence Tracker ───────────────────────────────────────────────────────

/// Tracks per-agent sequence numbers to detect gaps (dropped events).
struct SequenceTracker {
    /// Map of agent_guid → last seen sequence number
    sequences: DashMap<String, u64>,
}

impl SequenceTracker {
    fn new() -> Self {
        Self {
            sequences: DashMap::new(),
        }
    }

    /// Returns the gap size (0 = no gap, >0 = events missing).
    fn check_and_update(&self, agent_guid: &str, seq: u64) -> u64 {
        let mut entry = self.sequences.entry(agent_guid.to_string()).or_insert(0);
        let expected = *entry + 1;
        let gap = if seq > expected { seq - expected } else { 0 };
        *entry = seq;
        gap
    }

    fn next_expected(&self, agent_guid: &str) -> u64 {
        self.sequences
            .get(agent_guid)
            .map(|v| *v + 1)
            .unwrap_or(1)
    }
}

// ─── Certificate Validator ──────────────────────────────────────────────────

/// Extracts and validates agent identity from mTLS client certificate.
struct CertValidator {
    /// Set of revoked certificate serial numbers (refreshed via NATS).
    revoked_serials: Arc<RwLock<std::collections::HashSet<String>>>,
}

impl CertValidator {
    fn new() -> Self {
        Self {
            revoked_serials: Arc::new(RwLock::new(std::collections::HashSet::new())),
        }
    }

    /// Extract agent_guid and tenant_id from the TLS peer certificate CN.
    /// CN format: "agent:<agent_guid>@tenant:<tenant_id>"
    async fn validate_peer(&self, request: &Request<TelemetryBatch>) -> Result<AgentIdentity, Status> {
        // In production, extract from tonic's TLS peer certificates:
        //   let certs = request.peer_certs().ok_or(Status::unauthenticated("no client cert"))?;
        //   let cert = x509_parser::parse_x509_certificate(&certs[0].as_ref())?;
        //   let cn = cert.subject().iter_common_name().next()...

        // Stub: parse from metadata header for development
        let cn = request
            .metadata()
            .get("x-agent-cn")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| Status::unauthenticated("missing agent identity"))?;

        let identity = parse_agent_cn(cn)?;

        // Check revocation
        let revoked = self.revoked_serials.read().await;
        if revoked.contains(&identity.cert_serial) {
            return Err(Status::permission_denied("certificate revoked"));
        }

        Ok(identity)
    }
}

struct AgentIdentity {
    agent_guid: String,
    tenant_id: String,
    cert_serial: String,
}

fn parse_agent_cn(cn: &str) -> Result<AgentIdentity, Status> {
    // Expected: "agent:<guid>@tenant:<tid>"
    // Simplified parsing
    let parts: Vec<&str> = cn.split('@').collect();
    if parts.len() != 2 {
        return Err(Status::unauthenticated("malformed CN"));
    }
    let agent_guid = parts[0]
        .strip_prefix("agent:")
        .ok_or_else(|| Status::unauthenticated("missing agent prefix"))?
        .to_string();
    let tenant_id = parts[1]
        .strip_prefix("tenant:")
        .ok_or_else(|| Status::unauthenticated("missing tenant prefix"))?
        .to_string();

    Ok(AgentIdentity {
        agent_guid,
        tenant_id,
        cert_serial: String::new(), // Extracted from cert in production
    })
}

// ─── NATS Publisher ─────────────────────────────────────────────────────────

/// Publishes validated batches to NATS JetStream subjects.
struct NatsPublisher {
    // In production: async_nats::jetstream::Context
    // Publishes to: telemetry.raw.<tenant_id>.<category>
}

impl NatsPublisher {
    async fn publish_batch(
        &self,
        tenant_id: &str,
        batch: &TelemetryBatch,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Subject format: telemetry.raw.<tenant_id>.<category>
        // In production:
        //   for event in &batch.events {
        //       let category = EventCategory::from_i32(event.category).unwrap_or_default();
        //       let subject = format!("telemetry.raw.{}.{}", tenant_id, category.as_str());
        //       self.js_context.publish(subject, event.payload.clone().into()).await?;
        //   }
        info!(
            tenant = tenant_id,
            events = batch.events.len(),
            "published batch to NATS JetStream (stub)"
        );
        Ok(())
    }
}

// ─── gRPC Service Implementation ────────────────────────────────────────────

/// Implements the IngestionService gRPC interface.
pub struct IngestionServiceImpl {
    rate_limiter: Arc<RateLimiter>,
    sequence_tracker: Arc<SequenceTracker>,
    cert_validator: Arc<CertValidator>,
    nats_publisher: Arc<NatsPublisher>,
}

impl IngestionServiceImpl {
    pub fn new() -> Self {
        Self {
            rate_limiter: Arc::new(RateLimiter::new(500, 1000)),
            sequence_tracker: Arc::new(SequenceTracker::new()),
            cert_validator: Arc::new(CertValidator::new()),
            nats_publisher: Arc::new(NatsPublisher {}),
        }
    }

    /// Handle a single batch submission (unary RPC).
    pub async fn submit_batch(
        &self,
        request: Request<TelemetryBatch>,
    ) -> Result<Response<BatchAck>, Status> {
        // 1. Validate agent identity from mTLS cert
        let identity = self.cert_validator.validate_peer(&request).await?;
        let batch = request.into_inner();

        // 2. Verify agent_guid in batch matches cert identity
        if batch.agent_guid != identity.agent_guid {
            return Err(Status::new(
                Code::PermissionDenied,
                "agent_guid mismatch with certificate",
            ));
        }

        // 3. Rate limit check
        let event_count = batch.events.len() as u64;
        if !self.rate_limiter.check_and_consume(&identity.agent_guid, event_count) {
            return Ok(Response::new(BatchAck {
                accepted: 0,
                rejected: event_count,
                server_time_ns: 0,
                backpressure: true,
                next_expected_sequence: self.sequence_tracker.next_expected(&identity.agent_guid),
            }));
        }

        // 4. Sequence gap detection
        let gap = self
            .sequence_tracker
            .check_and_update(&identity.agent_guid, batch.sequence_number);
        if gap > 0 {
            warn!(
                agent = %identity.agent_guid,
                gap = gap,
                "sequence gap detected — {} events potentially lost",
                gap
            );
            // TODO: Publish gap alert to NATS system.alerts subject
        }

        // 5. Publish to NATS JetStream
        match self
            .nats_publisher
            .publish_batch(&identity.tenant_id, &batch)
            .await
        {
            Ok(()) => Ok(Response::new(BatchAck {
                accepted: event_count,
                rejected: 0,
                server_time_ns: 0,
                backpressure: false,
                next_expected_sequence: self
                    .sequence_tracker
                    .next_expected(&identity.agent_guid),
            })),
            Err(e) => {
                error!(error = %e, "failed to publish to NATS");
                Err(Status::internal("event ingestion failed"))
            }
        }
    }
}

// ─── Metrics ────────────────────────────────────────────────────────────────

/// Prometheus-compatible metrics for the ingestion gateway.
/// In production, use the `metrics` crate with `metrics-exporter-prometheus`.
///
/// Counters:
///   - sentinel_ingestion_batches_total{tenant, status}
///   - sentinel_ingestion_events_total{tenant, category}
///   - sentinel_ingestion_rate_limited_total{tenant}
///   - sentinel_ingestion_sequence_gaps_total{tenant}
///
/// Histograms:
///   - sentinel_ingestion_batch_size
///   - sentinel_ingestion_latency_seconds
///
/// Gauges:
///   - sentinel_ingestion_active_connections

// ─── Main ───────────────────────────────────────────────────────────────────

// #[tokio::main]
// async fn main() -> Result<(), Box<dyn std::error::Error>> {
//     tracing_subscriber::fmt().json().init();
//
//     let addr: SocketAddr = "0.0.0.0:4443".parse()?;
//     let service = IngestionServiceImpl::new();
//
//     // Load TLS config
//     let cert = tokio::fs::read("certs/server.crt").await?;
//     let key = tokio::fs::read("certs/server.key").await?;
//     let ca = tokio::fs::read("certs/ca.crt").await?;
//
//     let tls = tonic::transport::ServerTlsConfig::new()
//         .identity(tonic::transport::Identity::from_pem(cert, key))
//         .client_ca_root(tonic::transport::Certificate::from_pem(ca));
//
//     info!(%addr, "ingestion gateway starting");
//
//     tonic::transport::Server::builder()
//         .tls_config(tls)?
//         .add_service(/* IngestionServiceServer::new(service) */)
//         .serve(addr)
//         .await?;
//
//     Ok(())
// }
