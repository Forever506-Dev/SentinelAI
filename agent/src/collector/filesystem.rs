//! Filesystem Collector
//!
//! Watches specified directories for file creation, modification, and deletion.
//! Computes SHA-256 hashes for relevant file types.

use std::path::PathBuf;

use chrono::Utc;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde_json::json;
use sha2::{Sha256, Digest};
use tokio::sync::mpsc;
use tracing::{debug, warn, error};
use uuid::Uuid;

use super::{TelemetryEvent, EventType};

/// Watch filesystem paths for changes and emit telemetry events.
pub async fn watch_filesystem(
    tx: mpsc::Sender<TelemetryEvent>,
    watch_paths: Vec<PathBuf>,
    hash_extensions: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel(2000);

    // Create filesystem watcher
    let mut watcher = RecommendedWatcher::new(
        move |result: Result<Event, notify::Error>| {
            let tx = notify_tx.clone();
            match result {
                Ok(event) => {
                    // Use try_send to avoid blocking/panicking when channel is full
                    if tx.try_send(event).is_err() {
                        // Channel full — drop event rather than crash
                    }
                }
                Err(e) => {
                    error!(error = %e, "Filesystem watch error");
                }
            }
        },
        Config::default(),
    )?;

    // Add watch paths
    for path in &watch_paths {
        if path.exists() {
            match watcher.watch(path, RecursiveMode::Recursive) {
                Ok(_) => debug!(path = %path.display(), "Watching directory"),
                Err(e) => warn!(path = %path.display(), error = %e, "Failed to watch path"),
            }
        }
    }

    // Process filesystem events
    while let Some(event) = notify_rx.recv().await {
        let action = match event.kind {
            EventKind::Create(_) => "create",
            EventKind::Modify(_) => "modify",
            EventKind::Remove(_) => "delete",
            _ => continue,
        };

        for path in &event.paths {
            let file_hash = if action != "delete" && should_hash(path, &hash_extensions) {
                compute_sha256(path).ok()
            } else {
                None
            };

            let file_size = if action != "delete" {
                std::fs::metadata(path).ok().map(|m| m.len())
            } else {
                None
            };

            let telemetry_event = TelemetryEvent {
                id: Uuid::new_v4(),
                event_type: EventType::File,
                event_action: action.to_string(),
                event_time: Utc::now(),
                data: json!({
                    "file_path": path.to_string_lossy(),
                    "file_name": path.file_name().map(|n| n.to_string_lossy().to_string()),
                    "file_extension": path.extension().map(|e| e.to_string_lossy().to_string()),
                    "file_hash_sha256": file_hash,
                    "file_size": file_size,
                }),
            };

            debug!(
                path = %path.display(),
                action = action,
                "File event"
            );

            let _ = tx.send(telemetry_event).await;
        }
    }

    Ok(())
}

/// Check if a file should be hashed based on its extension.
fn should_hash(path: &PathBuf, hash_extensions: &[String]) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| hash_extensions.iter().any(|h| h.eq_ignore_ascii_case(ext)))
        .unwrap_or(false)
}

/// Compute SHA-256 hash of a file.
fn compute_sha256(path: &PathBuf) -> Result<String, std::io::Error> {
    let data = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(hex::encode(hasher.finalize()))
}
