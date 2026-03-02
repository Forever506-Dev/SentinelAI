//! Transport Layer
//!
//! The `BackendClient` manages all communication between the agent and
//! the SentinelAI backend: registration, heartbeats, telemetry,
//! command polling, and command result submission.

use chrono::Utc;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use sysinfo::System;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::collector::TelemetryEvent;
use crate::config::AgentConfig;
use crate::executor::CommandResult;

/// Monotonically increasing batch sequence number for gap detection.
static BATCH_SEQUENCE: AtomicU64 = AtomicU64::new(1);

// == Persisted state ==================================================

const STATE_FILE: &str = "agent_state.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedState {
    agent_id: String,
    auth_token: String,
    #[serde(default)]
    hmac_key: Option<String>,
}

fn state_path() -> std::path::PathBuf {
    dirs::config_dir()
        .map(|d| d.join("sentinelai").join(STATE_FILE))
        .unwrap_or_else(|| std::path::PathBuf::from(STATE_FILE))
}

fn load_persisted_state() -> Option<PersistedState> {
    let path = state_path();
    match std::fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str::<PersistedState>(&content) {
            Ok(state) => {
                info!(path = %path.display(), "Loaded persisted agent state");
                Some(state)
            }
            Err(e) => {
                warn!(error = %e, "Corrupt agent state file, will re-register");
                None
            }
        },
        Err(_) => None,
    }
}

fn save_persisted_state(state: &PersistedState) {
    let path = state_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match serde_json::to_string_pretty(state) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&path, &json) {
                error!(error = %e, path = %path.display(), "Failed to save agent state");
            } else {
                info!(path = %path.display(), "Agent state persisted to disk");
            }
        }
        Err(e) => error!(error = %e, "Failed to serialize agent state"),
    }
}

// == DTOs =============================================================

#[derive(Debug, Serialize)]
pub struct RegistrationPayload {
    pub hostname: String,
    pub os_type: String,
    pub os_version: String,
    pub architecture: String,
    pub agent_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal_ip: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegistrationResponse {
    pub agent_id: String,
    pub auth_token: String,
    #[serde(default)]
    pub heartbeat_interval: Option<u64>,
    #[serde(default)]
    pub policy: Option<serde_json::Value>,
    #[serde(default)]
    pub hmac_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HeartbeatPayload {
    pub cpu_usage: f32,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub uptime_seconds: u64,
    pub agent_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_ip: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct HeartbeatResponse {
    pub status: String,
    #[serde(default)]
    pub commands: Vec<PendingCommand>,
    #[serde(default)]
    pub policy_update: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AgentCommand {
    pub command: String,
    #[serde(default)]
    pub parameters: serde_json::Value,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PendingCommand {
    pub command_id: String,
    pub command: String,
    #[serde(default)]
    pub parameters: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct PendingCommandsResponse {
    pub commands: Vec<PendingCommand>,
}

#[derive(Debug, Serialize)]
struct TelemetryBatchPayload {
    events: Vec<serde_json::Value>,
    batch_id: String,
    sequence_number: u64,
    timestamp: String,
}

#[derive(Debug, Serialize)]
pub struct CommandResultPayload {
    pub command_id: String,
    pub status: String,
    pub output: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

// == BackendClient ====================================================

pub struct BackendClient {
    http: Client,
    base_url: String,
    agent_id: RwLock<Option<Uuid>>,
    auth_token: RwLock<Option<String>>,
    hmac_key: RwLock<Option<String>>,
}

impl BackendClient {
    pub fn new(config: &AgentConfig) -> Self {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .user_agent(format!("SentinelAI-Agent/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("Failed to build HTTP client");

        let (agent_id, auth_token, hmac_key) = match load_persisted_state() {
            Some(state) => {
                let parsed_id = state.agent_id.parse::<Uuid>().ok();
                (parsed_id, Some(state.auth_token), state.hmac_key)
            }
            None => (None, config.auth_token.clone(), config.hmac_key.clone()),
        };

        Self {
            http,
            base_url: config.backend_url.clone(),
            agent_id: RwLock::new(agent_id),
            auth_token: RwLock::new(auth_token),
            hmac_key: RwLock::new(hmac_key),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    async fn auth_header(&self) -> Option<String> {
        self.auth_token
            .read()
            .await
            .as_ref()
            .map(|t| format!("Bearer {}", t))
    }

    // -- Registration -------------------------------------------------

    pub async fn register(&self) -> Result<RegistrationResponse, Box<dyn std::error::Error + Send + Sync>> {
        if self.agent_id.read().await.is_some() {
            info!("Attempting to reuse persisted agent credentials");
            match self.send_heartbeat().await {
                Ok(_) => {
                    let id = self.agent_id.read().await.unwrap();
                    info!(agent_id = %id, "Persisted credentials valid");
                    return Ok(RegistrationResponse {
                        agent_id: id.to_string(),
                        auth_token: self.auth_token.read().await.clone().unwrap_or_default(),
                        heartbeat_interval: None,
                        policy: None,
                        hmac_key: self.hmac_key.read().await.clone(),
                    });
                }
                Err(e) => {
                    warn!(error = %e, "Persisted credentials rejected, re-registering");
                    *self.agent_id.write().await = None;
                    *self.auth_token.write().await = None;
                }
            }
        }

        let payload = RegistrationPayload {
            hostname: System::host_name().unwrap_or_else(|| "unknown".into()),
            os_type: std::env::consts::OS.to_string(),
            os_version: System::os_version().unwrap_or_else(|| "unknown".into()),
            architecture: std::env::consts::ARCH.to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            internal_ip: None, // Populated by backend from request IP if not provided
        };

        info!(hostname = %payload.hostname, os = %payload.os_type, "Registering with backend");

        let resp = self.http
            .post(self.url("/agents/register"))
            .json(&payload)
            .send()
            .await?;

        match resp.status() {
            StatusCode::OK | StatusCode::CREATED => {
                let body: RegistrationResponse = resp.json().await?;
                info!(agent_id = %body.agent_id, "Registration successful");
                let parsed_id: Uuid = body.agent_id.parse()?;
                *self.agent_id.write().await = Some(parsed_id);
                *self.auth_token.write().await = Some(body.auth_token.clone());
                if let Some(ref key) = body.hmac_key {
                    info!("HMAC key provisioned by backend");
                    *self.hmac_key.write().await = Some(key.clone());
                }
                save_persisted_state(&PersistedState {
                    agent_id: body.agent_id.clone(),
                    auth_token: body.auth_token.clone(),
                    hmac_key: body.hmac_key.clone(),
                });
                Ok(body)
            }
            status => {
                let text = resp.text().await.unwrap_or_default();
                error!(%status, body = %text, "Registration failed");
                Err(format!("Registration failed: {} - {}", status, text).into())
            }
        }
    }

    // -- Heartbeat ----------------------------------------------------

    pub async fn send_heartbeat(&self) -> Result<Vec<PendingCommand>, Box<dyn std::error::Error + Send + Sync>> {
        if self.agent_id.read().await.is_none() {
            return Err("Agent not registered".into());
        }

        let mut sys = System::new_all();
        sys.refresh_all();

        let total_mem = sys.total_memory() as f64;
        let used_mem = sys.used_memory() as f64;

        // Compute real disk usage from all mounted disks
        let disks = sysinfo::Disks::new_with_refreshed_list();
        let (total_disk, used_disk) = disks.list().iter().fold((0u64, 0u64), |(t, u), d| {
            (t + d.total_space(), u + (d.total_space() - d.available_space()))
        });
        let disk_pct = if total_disk > 0 { (used_disk as f64 / total_disk as f64) * 100.0 } else { 0.0 };

        // Get internal IP from first non-loopback network interface
        let networks = sysinfo::Networks::new_with_refreshed_list();
        let internal_ip = networks.iter()
            .find(|(name, _)| !name.contains("Loopback") && !name.starts_with("lo"))
            .map(|(_, _)| System::host_name().unwrap_or_else(|| "unknown".into()));

        let payload = HeartbeatPayload {
            cpu_usage: sys.global_cpu_info().cpu_usage(),
            memory_usage: if total_mem > 0.0 { (used_mem / total_mem) * 100.0 } else { 0.0 },
            disk_usage: disk_pct,
            uptime_seconds: System::uptime(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            internal_ip,
            external_ip: None,
        };

        let mut req = self.http.post(self.url("/agents/heartbeat")).json(&payload);
        if let Some(auth) = self.auth_header().await {
            req = req.header("Authorization", auth);
        }

        let resp = req.send().await?;
        match resp.status() {
            StatusCode::OK => {
                let body: HeartbeatResponse = resp.json().await?;
                debug!(commands = body.commands.len(), "Heartbeat acknowledged");
                Ok(body.commands)
            }
            status => {
                let text = resp.text().await.unwrap_or_default();
                warn!(%status, body = %text, "Heartbeat rejected by backend");
                Err(format!("Heartbeat rejected: {} - {}", status, text).into())
            }
        }
    }

    // -- Command Polling (fast loop) ----------------------------------

    pub async fn poll_commands(&self) -> Result<Vec<PendingCommand>, Box<dyn std::error::Error + Send + Sync>> {
        if self.agent_id.read().await.is_none() {
            return Ok(vec![]);
        }

        let mut req = self.http.get(self.url("/agents/commands/pending"));
        if let Some(auth) = self.auth_header().await {
            req = req.header("Authorization", auth);
        }

        let resp = req.send().await?;
        match resp.status() {
            StatusCode::OK => {
                let body: PendingCommandsResponse = resp.json().await?;
                if !body.commands.is_empty() {
                    info!(count = body.commands.len(), "Received pending commands");
                }
                Ok(body.commands)
            }
            status => {
                let text = resp.text().await.unwrap_or_default();
                debug!(%status, body = %text, "Command poll returned non-200");
                Ok(vec![])
            }
        }
    }

    // -- Submit Command Result ----------------------------------------

    pub async fn send_command_result(&self, result: &CommandResult) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let payload = CommandResultPayload {
            command_id: result.command_id.clone(),
            status: result.status.clone(),
            output: result.output.clone(),
            data: result.data.clone(),
            exit_code: result.exit_code,
        };

        let mut req = self.http.post(self.url("/agents/command-result")).json(&payload);
        if let Some(auth) = self.auth_header().await {
            req = req.header("Authorization", auth);
        }

        let resp = req.send().await?;
        match resp.status() {
            StatusCode::OK => {
                info!(command_id = %result.command_id, "Command result submitted");
                Ok(())
            }
            status => {
                let text = resp.text().await.unwrap_or_default();
                error!(%status, body = %text, "Failed to submit command result");
                Err(format!("Submit result failed: {}", status).into())
            }
        }
    }

    // -- Telemetry ----------------------------------------------------

    pub async fn send_telemetry(
        &self,
        events: Vec<TelemetryEvent>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.agent_id.read().await.is_none() {
            return Err("Agent not registered".into());
        }
        if events.is_empty() {
            return Ok(());
        }

        let batch_id = Uuid::new_v4();
        let seq = BATCH_SEQUENCE.fetch_add(1, Ordering::SeqCst);
        let batch = TelemetryBatchPayload {
            events: events.into_iter().map(|e| {
                let mut flat = serde_json::Map::new();
                flat.insert("event_type".into(), serde_json::to_value(&e.event_type).unwrap_or_default());
                flat.insert("event_action".into(), serde_json::Value::String(e.event_action));
                if let serde_json::Value::Object(data) = e.data {
                    for (k, v) in data { flat.insert(k, v); }
                }
                serde_json::Value::Object(flat)
            }).collect(),
            batch_id: batch_id.to_string(),
            sequence_number: seq,
            timestamp: Utc::now().to_rfc3339(),
        };

        let mut req = self.http.post(self.url("/agents/telemetry")).json(&batch);
        if let Some(auth) = self.auth_header().await {
            req = req.header("Authorization", auth);
        }

        let resp = req.send().await?;
        match resp.status() {
            StatusCode::OK | StatusCode::ACCEPTED => {
                debug!(%batch_id, "Telemetry batch accepted");
                Ok(())
            }
            status => {
                let text = resp.text().await.unwrap_or_default();
                warn!(%status, body = %text, "Telemetry submission failed");
                Err(format!("Telemetry failed: {}", status).into())
            }
        }
    }

    // -- Accessors ----------------------------------------------------

    pub async fn agent_id(&self) -> Option<Uuid> {
        *self.agent_id.read().await
    }

    pub async fn is_registered(&self) -> bool {
        self.agent_id.read().await.is_some() && self.auth_token.read().await.is_some()
    }

    /// Get the current HMAC key (for command signature verification).
    pub async fn hmac_key(&self) -> Option<String> {
        self.hmac_key.read().await.clone()
    }

    // -- Local Alert Submission ---------------------------------------

    /// Send locally detected alerts to the backend for persistence and correlation.
    pub async fn send_local_alerts(
        &self,
        alerts: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.agent_id.read().await.is_none() {
            return Err("Agent not registered".into());
        }

        let payload = serde_json::json!({
            "source": "agent_local_detection",
            "agent_id": self.agent_id.read().await.map(|id| id.to_string()),
            "alerts": alerts,
            "timestamp": Utc::now().to_rfc3339(),
        });

        let mut req = self.http
            .post(self.url("/agents/telemetry"))
            .json(&serde_json::json!({
                "events": [{
                    "event_type": "local_alert",
                    "event_action": "detection",
                    "local_alerts": payload,
                }],
                "batch_id": Uuid::new_v4().to_string(),
                "timestamp": Utc::now().to_rfc3339(),
            }));
        if let Some(auth) = self.auth_header().await {
            req = req.header("Authorization", auth);
        }

        let resp = req.send().await?;
        match resp.status() {
            StatusCode::OK | StatusCode::ACCEPTED => {
                info!("Local detection alerts sent to backend");
                Ok(())
            }
            status => {
                let text = resp.text().await.unwrap_or_default();
                warn!(%status, body = %text, "Failed to send local alerts");
                Err(format!("Local alert submission failed: {}", status).into())
            }
        }
    }
}
