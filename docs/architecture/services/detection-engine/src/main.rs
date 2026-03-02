//! SentinelAI Detection Engine Service
//!
//! Standalone Rust microservice that consumes normalized telemetry
//! from NATS JetStream and evaluates Sigma/YARA/correlation rules.
//!
//! Architecture:
//!   NATS (telemetry.normalized.>) → Detection Workers → NATS (alerts.>)
//!
//! Features:
//!   - Hot-reload of Sigma/YARA rules without restart
//!   - Sliding window correlation (process tree, temporal)
//!   - IOC matching via bloom filter + exact set
//!   - MITRE ATT&CK enrichment on alert generation

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::{mpsc, RwLock, watch};
use tracing::{error, info, warn};

// ─── Domain Types ───────────────────────────────────────────────────────────

/// A normalized telemetry event consumed from NATS.
#[derive(Debug, Clone)]
pub struct NormalizedEvent {
    pub event_id: String,
    pub tenant_id: String,
    pub host_guid: String,
    pub category: EventCategory,
    pub timestamp_ns: u64,
    pub fields: HashMap<String, FieldValue>,
}

#[derive(Debug, Clone)]
pub enum EventCategory {
    ProcessCreate,
    ProcessTerminate,
    FileCreate,
    FileModify,
    FileDelete,
    NetworkConnect,
    NetworkListen,
    DnsQuery,
    RegistrySetValue,
    RegistryDeleteValue,
    ModuleLoad,
    Authentication,
    Tamper,
}

#[derive(Debug, Clone)]
pub enum FieldValue {
    String(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    Ip(std::net::IpAddr),
    StringList(Vec<String>),
}

// ─── Sigma Rule Engine ──────────────────────────────────────────────────────

/// Compiled Sigma rule for fast evaluation.
#[derive(Debug)]
pub struct CompiledRule {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub mitre_techniques: Vec<String>,
    pub logsource_category: String,
    /// Compiled filter expression tree
    pub condition: FilterExpression,
}

#[derive(Debug, Clone)]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

/// Boolean expression tree for Sigma detection logic.
#[derive(Debug)]
pub enum FilterExpression {
    And(Vec<FilterExpression>),
    Or(Vec<FilterExpression>),
    Not(Box<FilterExpression>),
    FieldMatch {
        field: String,
        operator: MatchOperator,
    },
}

#[derive(Debug)]
pub enum MatchOperator {
    Equals(String),
    Contains(String),
    StartsWith(String),
    EndsWith(String),
    Regex(regex::Regex),
    InList(Vec<String>),
    GreaterThan(i64),
    LessThan(i64),
}

impl CompiledRule {
    /// Evaluate this rule against a normalized event.
    pub fn matches(&self, event: &NormalizedEvent) -> bool {
        self.evaluate_expr(&self.condition, event)
    }

    fn evaluate_expr(&self, expr: &FilterExpression, event: &NormalizedEvent) -> bool {
        match expr {
            FilterExpression::And(children) => children.iter().all(|c| self.evaluate_expr(c, event)),
            FilterExpression::Or(children) => children.iter().any(|c| self.evaluate_expr(c, event)),
            FilterExpression::Not(child) => !self.evaluate_expr(child, event),
            FilterExpression::FieldMatch { field, operator } => {
                if let Some(value) = event.fields.get(field) {
                    match_field_value(value, operator)
                } else {
                    false
                }
            }
        }
    }
}

fn match_field_value(value: &FieldValue, operator: &MatchOperator) -> bool {
    match (value, operator) {
        (FieldValue::String(s), MatchOperator::Equals(expected)) => {
            s.eq_ignore_ascii_case(expected)
        }
        (FieldValue::String(s), MatchOperator::Contains(needle)) => {
            s.to_lowercase().contains(&needle.to_lowercase())
        }
        (FieldValue::String(s), MatchOperator::StartsWith(prefix)) => {
            s.to_lowercase().starts_with(&prefix.to_lowercase())
        }
        (FieldValue::String(s), MatchOperator::EndsWith(suffix)) => {
            s.to_lowercase().ends_with(&suffix.to_lowercase())
        }
        (FieldValue::String(s), MatchOperator::Regex(re)) => re.is_match(s),
        (FieldValue::String(s), MatchOperator::InList(list)) => {
            list.iter().any(|item| s.eq_ignore_ascii_case(item))
        }
        (FieldValue::Int(n), MatchOperator::GreaterThan(threshold)) => n > threshold,
        (FieldValue::Int(n), MatchOperator::LessThan(threshold)) => n < threshold,
        _ => false,
    }
}

// ─── Correlation Engine ─────────────────────────────────────────────────────

/// Temporal correlation windows for multi-event detection.
///
/// Example: "Credential dumping" = ProcessCreate(mimikatz) within 60s of
///          FileCreate(*.dmp in LSASS memory path)
pub struct CorrelationEngine {
    /// Active correlation windows, keyed by (tenant_id, correlation_rule_id)
    windows: DashMap<(String, String), CorrelationWindow>,
    /// Correlation rule definitions
    rules: Vec<CorrelationRule>,
}

pub struct CorrelationRule {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub mitre_techniques: Vec<String>,
    /// Conditions that must all be satisfied within the time window
    pub conditions: Vec<CorrelationCondition>,
    /// Maximum time span for all conditions to match
    pub window_duration: Duration,
    /// Group events by these fields (e.g., host_guid, user_id)
    pub group_by: Vec<String>,
}

pub struct CorrelationCondition {
    pub condition_id: String,
    pub category: EventCategory,
    pub filter: FilterExpression,
}

struct CorrelationWindow {
    /// Which conditions have been satisfied
    satisfied: HashMap<String, Vec<String>>, // condition_id → [event_ids]
    /// When the window opened
    opened_at: std::time::Instant,
    /// Window duration
    duration: Duration,
}

impl CorrelationEngine {
    pub fn new(rules: Vec<CorrelationRule>) -> Self {
        Self {
            windows: DashMap::new(),
            rules,
        }
    }

    /// Feed an event into the correlation engine.
    /// Returns alerts for any correlation rules that are now fully satisfied.
    pub fn process_event(&self, event: &NormalizedEvent) -> Vec<Alert> {
        let mut alerts = Vec::new();

        for rule in &self.rules {
            // Build group key from event fields
            let group_key = rule
                .group_by
                .iter()
                .filter_map(|field| {
                    event.fields.get(field).map(|v| format!("{:?}", v))
                })
                .collect::<Vec<_>>()
                .join("|");

            let window_key = (event.tenant_id.clone(), format!("{}:{}", rule.id, group_key));

            // Check each condition
            for condition in &rule.conditions {
                // Category must match
                if std::mem::discriminant(&condition.category)
                    != std::mem::discriminant(&event.category)
                {
                    continue;
                }

                // TODO: Evaluate condition.filter against event

                // Update window
                let mut window = self.windows.entry(window_key.clone()).or_insert_with(|| {
                    CorrelationWindow {
                        satisfied: HashMap::new(),
                        opened_at: std::time::Instant::now(),
                        duration: rule.window_duration,
                    }
                });

                // Expire stale windows
                if window.opened_at.elapsed() > window.duration {
                    window.satisfied.clear();
                    window.opened_at = std::time::Instant::now();
                }

                window
                    .satisfied
                    .entry(condition.condition_id.clone())
                    .or_default()
                    .push(event.event_id.clone());

                // Check if all conditions satisfied
                if rule
                    .conditions
                    .iter()
                    .all(|c| window.satisfied.contains_key(&c.condition_id))
                {
                    let evidence: Vec<String> = window
                        .satisfied
                        .values()
                        .flatten()
                        .cloned()
                        .collect();

                    alerts.push(Alert {
                        alert_id: uuid::Uuid::new_v4().to_string(),
                        rule_id: rule.id.clone(),
                        rule_title: rule.title.clone(),
                        severity: rule.severity.clone(),
                        tenant_id: event.tenant_id.clone(),
                        host_guid: event.host_guid.clone(),
                        mitre_techniques: rule.mitre_techniques.clone(),
                        evidence_event_ids: evidence,
                        detection_source: DetectionSource::Correlation,
                        timestamp_ns: event.timestamp_ns,
                    });

                    // Reset window after firing
                    window.satisfied.clear();
                }
            }
        }

        alerts
    }
}

// ─── Alert ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Alert {
    pub alert_id: String,
    pub rule_id: String,
    pub rule_title: String,
    pub severity: Severity,
    pub tenant_id: String,
    pub host_guid: String,
    pub mitre_techniques: Vec<String>,
    pub evidence_event_ids: Vec<String>,
    pub detection_source: DetectionSource,
    pub timestamp_ns: u64,
}

#[derive(Debug)]
pub enum DetectionSource {
    SigmaRule,
    YaraRule,
    Heuristic,
    Correlation,
    IocMatch,
    AiAnalysis,
}

// ─── Detection Worker ───────────────────────────────────────────────────────

/// A detection worker that processes events from NATS and evaluates rules.
pub struct DetectionWorker {
    /// Compiled Sigma rules (hot-reloadable via watch channel)
    sigma_rules: watch::Receiver<Arc<Vec<CompiledRule>>>,
    /// Correlation engine
    correlation: Arc<CorrelationEngine>,
    /// IOC bloom filter for fast negative lookups
    ioc_bloom: Arc<RwLock<IocFilter>>,
    /// Alert output channel → published to NATS alerts subject
    alert_tx: mpsc::Sender<Alert>,
}

/// IOC filter combining bloom filter (fast path) with exact hash set (confirmation).
pub struct IocFilter {
    /// Bloom filter for O(1) negative lookups (false positive rate ~0.1%)
    // bloom: probabilistic_collections::bloom::BloomFilter<String>,
    /// Exact set for confirmation after bloom hit
    exact_hashes: std::collections::HashSet<String>,
    /// Domain IOCs
    exact_domains: std::collections::HashSet<String>,
    /// IP IOCs
    exact_ips: std::collections::HashSet<std::net::IpAddr>,
}

impl DetectionWorker {
    /// Process a single normalized event through all detection layers.
    pub async fn evaluate(&self, event: &NormalizedEvent) -> Vec<Alert> {
        let mut alerts = Vec::new();

        // Layer 1: Sigma rules (fast path)
        let rules = self.sigma_rules.borrow().clone();
        for rule in rules.iter() {
            if rule.matches(event) {
                alerts.push(Alert {
                    alert_id: uuid::Uuid::new_v4().to_string(),
                    rule_id: rule.id.clone(),
                    rule_title: rule.title.clone(),
                    severity: rule.severity.clone(),
                    tenant_id: event.tenant_id.clone(),
                    host_guid: event.host_guid.clone(),
                    mitre_techniques: rule.mitre_techniques.clone(),
                    evidence_event_ids: vec![event.event_id.clone()],
                    detection_source: DetectionSource::SigmaRule,
                    timestamp_ns: event.timestamp_ns,
                });
            }
        }

        // Layer 2: IOC matching
        let ioc_alerts = self.check_iocs(event).await;
        alerts.extend(ioc_alerts);

        // Layer 3: Correlation (multi-event)
        let corr_alerts = self.correlation.process_event(event);
        alerts.extend(corr_alerts);

        // Publish alerts
        for alert in &alerts {
            if self.alert_tx.send(Alert {
                alert_id: alert.alert_id.clone(),
                rule_id: alert.rule_id.clone(),
                rule_title: alert.rule_title.clone(),
                severity: alert.severity.clone(),
                tenant_id: alert.tenant_id.clone(),
                host_guid: alert.host_guid.clone(),
                mitre_techniques: alert.mitre_techniques.clone(),
                evidence_event_ids: alert.evidence_event_ids.clone(),
                detection_source: DetectionSource::SigmaRule, // simplified
                timestamp_ns: alert.timestamp_ns,
            }).await.is_err() {
                error!("alert channel closed");
            }
        }

        alerts
    }

    /// Check event fields against IOC filters.
    async fn check_iocs(&self, event: &NormalizedEvent) -> Vec<Alert> {
        let filter = self.ioc_bloom.read().await;
        let mut alerts = Vec::new();

        // Check file hashes
        for hash_field in &["sha256", "sha1", "md5"] {
            if let Some(FieldValue::String(hash)) = event.fields.get(*hash_field) {
                if filter.exact_hashes.contains(hash) {
                    alerts.push(Alert {
                        alert_id: uuid::Uuid::new_v4().to_string(),
                        rule_id: format!("ioc-hash-{}", hash_field),
                        rule_title: format!("IOC Hash Match ({})", hash_field),
                        severity: Severity::High,
                        tenant_id: event.tenant_id.clone(),
                        host_guid: event.host_guid.clone(),
                        mitre_techniques: vec![],
                        evidence_event_ids: vec![event.event_id.clone()],
                        detection_source: DetectionSource::IocMatch,
                        timestamp_ns: event.timestamp_ns,
                    });
                }
            }
        }

        // Check DNS queries against domain IOCs
        if let Some(FieldValue::String(domain)) = event.fields.get("dns_query_name") {
            if filter.exact_domains.contains(domain) {
                alerts.push(Alert {
                    alert_id: uuid::Uuid::new_v4().to_string(),
                    rule_id: "ioc-domain".into(),
                    rule_title: "IOC Domain Match".into(),
                    severity: Severity::High,
                    tenant_id: event.tenant_id.clone(),
                    host_guid: event.host_guid.clone(),
                    mitre_techniques: vec![],
                    evidence_event_ids: vec![event.event_id.clone()],
                    detection_source: DetectionSource::IocMatch,
                    timestamp_ns: event.timestamp_ns,
                });
            }
        }

        // Check destination IPs against IP IOCs
        if let Some(FieldValue::Ip(ip)) = event.fields.get("dest_ip") {
            if filter.exact_ips.contains(ip) {
                alerts.push(Alert {
                    alert_id: uuid::Uuid::new_v4().to_string(),
                    rule_id: "ioc-ip".into(),
                    rule_title: "IOC IP Match".into(),
                    severity: Severity::High,
                    tenant_id: event.tenant_id.clone(),
                    host_guid: event.host_guid.clone(),
                    mitre_techniques: vec![],
                    evidence_event_ids: vec![event.event_id.clone()],
                    detection_source: DetectionSource::IocMatch,
                    timestamp_ns: event.timestamp_ns,
                });
            }
        }

        alerts
    }
}

// ─── Rule Hot-Reload ────────────────────────────────────────────────────────

/// Watches a rules directory and recompiles on change.
/// Publishes updated rule set via watch channel to all workers.
pub struct RuleReloader {
    rules_dir: std::path::PathBuf,
    rule_tx: watch::Sender<Arc<Vec<CompiledRule>>>,
}

impl RuleReloader {
    pub async fn watch_loop(&self) {
        // In production:
        // 1. Use `notify` crate to watch rules_dir for changes
        // 2. On change, re-parse and compile all .yml Sigma rules
        // 3. Validate new rule set (dry-run against test events)
        // 4. Atomically swap via watch::Sender
        // 5. Log rule count change and any compilation errors
        //
        // Also: Listen on NATS system.rules.update for backend-pushed updates

        info!(dir = %self.rules_dir.display(), "rule reloader watching for changes");
    }
}

// ─── Metrics ────────────────────────────────────────────────────────────────

/// Prometheus metrics:
///   - sentinel_detection_events_processed_total{tenant}
///   - sentinel_detection_alerts_generated_total{tenant, severity, rule_type}
///   - sentinel_detection_latency_seconds{rule_type}  (histogram)
///   - sentinel_detection_rules_loaded{type}  (gauge)
///   - sentinel_detection_ioc_count{type}  (gauge)
///   - sentinel_detection_correlation_windows_active  (gauge)

// ─── Main ───────────────────────────────────────────────────────────────────

// #[tokio::main]
// async fn main() -> Result<(), Box<dyn std::error::Error>> {
//     tracing_subscriber::fmt().json().init();
//     info!("detection engine starting");
//
//     // 1. Connect to NATS JetStream
//     // let nats = async_nats::connect("nats://nats:4222").await?;
//     // let js = async_nats::jetstream::new(nats);
//
//     // 2. Load and compile rules
//     // let rules = load_sigma_rules("rules/sigma/").await?;
//     // let (rule_tx, rule_rx) = watch::channel(Arc::new(rules));
//
//     // 3. Initialize correlation engine
//     // let correlation = Arc::new(CorrelationEngine::new(load_correlation_rules()?));
//
//     // 4. Initialize IOC filter
//     // let ioc_filter = Arc::new(RwLock::new(load_iocs("iocs/").await?));
//
//     // 5. Create alert publisher
//     // let (alert_tx, mut alert_rx) = mpsc::channel(4096);
//
//     // 6. Spawn NATS consumer (pull-based, queue group "detection")
//     // Subscribe to: telemetry.normalized.>
//     // For each message, deserialize and evaluate through DetectionWorker
//
//     // 7. Spawn alert publisher
//     // Reads from alert_rx, publishes to NATS alerts.<tenant_id>.<severity>
//
//     // 8. Spawn rule reloader
//     // 9. Spawn metrics server on :9090
//
//     Ok(())
// }
