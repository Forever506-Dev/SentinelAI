//! Telemetry Collectors
//!
//! Each collector gathers specific types of endpoint telemetry
//! and sends events through the shared event channel.

pub mod process;
pub mod filesystem;
pub mod network;
pub mod system_info;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::mpsc;
use tracing::{info, error};
use uuid::Uuid;

use crate::config::AgentConfig;

/// Telemetry event sent from collectors to the transport layer.
#[derive(Debug, Clone, Serialize)]
pub struct TelemetryEvent {
    pub id: Uuid,
    pub event_type: EventType,
    pub event_action: String,
    pub event_time: DateTime<Utc>,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    Process,
    File,
    Network,
    Auth,
    Registry,
    System,
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventType::Process => write!(f, "process"),
            EventType::File => write!(f, "file"),
            EventType::Network => write!(f, "network"),
            EventType::Auth => write!(f, "auth"),
            EventType::Registry => write!(f, "registry"),
            EventType::System => write!(f, "system"),
        }
    }
}

/// Manages all telemetry collectors.
pub struct CollectorManager {
    config: AgentConfig,
    event_tx: mpsc::Sender<TelemetryEvent>,
}

impl CollectorManager {
    pub fn new(config: AgentConfig, event_tx: mpsc::Sender<TelemetryEvent>) -> Self {
        Self { config, event_tx }
    }

    /// Start all enabled collectors as concurrent tasks.
    pub async fn start(self) -> Result<(), Box<dyn std::error::Error>> {
        let mut handles = Vec::new();

        // Process collector
        if self.config.collectors.process_enabled {
            let tx = self.event_tx.clone();
            let interval = self.config.collectors.process_interval_secs;
            handles.push(tokio::spawn(async move {
                info!("Process collector started");
                if let Err(e) = process::collect_processes(tx, interval).await {
                    error!(error = %e, "Process collector failed");
                }
            }));
        }

        // Filesystem collector
        if self.config.collectors.filesystem_enabled {
            let tx = self.event_tx.clone();
            let watch_paths = self.config.watch_paths.clone();
            let hash_extensions = self.config.hash_extensions.clone();
            handles.push(tokio::spawn(async move {
                info!("Filesystem collector started");
                if let Err(e) = filesystem::watch_filesystem(tx, watch_paths, hash_extensions).await {
                    error!(error = %e, "Filesystem collector failed");
                }
            }));
        }

        // Network collector
        if self.config.collectors.network_enabled {
            let tx = self.event_tx.clone();
            let interval = self.config.collectors.network_interval_secs;
            handles.push(tokio::spawn(async move {
                info!("Network collector started");
                if let Err(e) = network::collect_network(tx, interval).await {
                    error!(error = %e, "Network collector failed");
                }
            }));
        }

        // System info collector
        if self.config.collectors.system_info_enabled {
            let tx = self.event_tx.clone();
            let interval = self.config.collectors.system_info_interval_secs;
            handles.push(tokio::spawn(async move {
                info!("System info collector started");
                if let Err(e) = system_info::collect_system_info(tx, interval).await {
                    error!(error = %e, "System info collector failed");
                }
            }));
        }

        info!(collector_count = handles.len(), "All collectors started");

        // Wait for all collectors — if any crash, log it (they should run indefinitely)
        for (i, handle) in handles.into_iter().enumerate() {
            match handle.await {
                Ok(()) => info!(collector = i, "Collector task finished cleanly"),
                Err(e) => error!(collector = i, error = %e, "Collector task panicked"),
            }
        }

        Ok(())
    }
}
