//! Process Collector
//!
//! Monitors running processes, detects new process creation and termination,
//! captures command lines and parent-child relationships.

use chrono::Utc;
use serde_json::json;
use sha2::{Digest, Sha256};
use sysinfo::{System, Pid, ProcessRefreshKind, ProcessesToUpdate};
use tokio::sync::mpsc;
use tracing::debug;
use uuid::Uuid;

use super::{TelemetryEvent, EventType};

/// Generate a deterministic process GUID from agent_id, PID, and start time.
/// This makes processes globally unique and trackable across the fleet.
fn process_guid(agent_id: &str, pid: u32, start_time: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(agent_id.as_bytes());
    hasher.update(pid.to_le_bytes());
    hasher.update(start_time.to_le_bytes());
    let result = hasher.finalize();
    hex::encode(result)[..32].to_string()
}

/// Continuously monitor processes at the given interval.
pub async fn collect_processes(
    tx: mpsc::Sender<TelemetryEvent>,
    interval_secs: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut sys = System::new();
    let mut known_pids: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
    let hostname = System::host_name().unwrap_or_else(|| "unknown".into());

    loop {
        interval.tick().await;

        // Refresh process list
        sys.refresh_processes(ProcessesToUpdate::All, true);

        let current_pids: std::collections::HashSet<u32> = sys
            .processes()
            .keys()
            .map(|pid| pid.as_u32())
            .collect();

        // Detect new processes
        for pid in current_pids.difference(&known_pids) {
            if let Some(process) = sys.process(Pid::from_u32(*pid)) {
                let pguid = process_guid(&hostname, *pid, process.start_time());
                let parent_pid = process.parent().map(|p| p.as_u32()).unwrap_or(0);
                let parent_guid = process.parent()
                    .and_then(|ppid| sys.process(ppid))
                    .map(|p| process_guid(&hostname, parent_pid, p.start_time()))
                    .unwrap_or_default();

                let event = TelemetryEvent {
                    id: Uuid::new_v4(),
                    event_type: EventType::Process,
                    event_action: "create".to_string(),
                    event_time: Utc::now(),
                    data: {
                        // Resolve parent process name for process chain detection
                        let parent_name = process.parent()
                            .and_then(|ppid| sys.process(ppid))
                            .map(|p| p.name().to_string_lossy().into_owned())
                            .unwrap_or_default();

                        // cmd() can be empty on Windows; fall back to exe path
                        let cmd_line = {
                            let parts = process.cmd();
                            if parts.is_empty() {
                                process.exe()
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_default()
                            } else {
                                parts.iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>().join(" ")
                            }
                        };

                        json!({
                            "event_type": "process",
                            "event_action": "create",
                            "process_name": process.name().to_string_lossy().into_owned(),
                            "process_id": pid,
                            "process_guid": pguid,
                            "parent_process_id": process.parent().map(|p| p.as_u32()),
                            "parent_process_name": parent_name,
                            "parent_process_guid": parent_guid,
                            "command_line": cmd_line,
                            "exe_path": process.exe().map(|p| p.to_string_lossy().to_string()),
                            "username": process.user_id().map(|u| format!("{:?}", u)),
                            "memory_bytes": process.memory(),
                            "cpu_usage": process.cpu_usage(),
                            "start_time": process.start_time(),
                            "status": format!("{:?}", process.status()),
                        })
                    },
                };

                debug!(
                    pid = pid,
                    name = %process.name().to_string_lossy(),
                    "New process detected"
                );

                let _ = tx.send(event).await;
            }
        }

        // Detect terminated processes
        for pid in known_pids.difference(&current_pids) {
            let event = TelemetryEvent {
                id: Uuid::new_v4(),
                event_type: EventType::Process,
                event_action: "terminate".to_string(),
                event_time: Utc::now(),
                data: json!({
                    "process_id": pid,
                }),
            };
            let _ = tx.send(event).await;
        }

        known_pids = current_pids;
    }
}
