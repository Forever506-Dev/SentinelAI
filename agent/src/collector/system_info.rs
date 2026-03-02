//! System Info Collector
//!
//! Gathers system metrics — CPU usage, memory, disk, OS info — and
//! reports them as telemetry events for fleet health monitoring.

use chrono::Utc;
use serde_json::json;
use sysinfo::{System, Disks, CpuRefreshKind, MemoryRefreshKind, RefreshKind};
use tokio::sync::mpsc;
use tracing::debug;
use uuid::Uuid;

use super::{TelemetryEvent, EventType};

/// Periodically collects system resource metrics.
pub async fn collect_system_info(
    tx: mpsc::Sender<TelemetryEvent>,
    interval_secs: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut sys = System::new_with_specifics(
        RefreshKind::new()
            .with_cpu(CpuRefreshKind::everything())
            .with_memory(MemoryRefreshKind::everything()),
    );

    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));

    loop {
        interval.tick().await;
        sys.refresh_all();

        // ── CPU ─────────────────────────────────────────────────────
        let global_cpu_usage = sys.global_cpu_info().cpu_usage();
        let per_core: Vec<f32> = sys.cpus().iter().map(|c| c.cpu_usage()).collect();

        let cpu_event = TelemetryEvent {
            id: Uuid::new_v4(),
            event_type: EventType::System,
            event_action: "cpu_metrics".to_string(),
            event_time: Utc::now(),
            data: json!({
                "global_usage_pct": global_cpu_usage,
                "per_core_usage_pct": per_core,
                "physical_core_count": sys.physical_core_count(),
                "cpu_count": sys.cpus().len(),
                "cpu_brand": sys.cpus().first().map(|c| c.brand().to_string()),
            }),
        };
        let _ = tx.send(cpu_event).await;

        // ── Memory ──────────────────────────────────────────────────
        let total_mem = sys.total_memory();
        let used_mem = sys.used_memory();
        let total_swap = sys.total_swap();
        let used_swap = sys.used_swap();

        let mem_event = TelemetryEvent {
            id: Uuid::new_v4(),
            event_type: EventType::System,
            event_action: "memory_metrics".to_string(),
            event_time: Utc::now(),
            data: json!({
                "total_memory_bytes": total_mem,
                "used_memory_bytes": used_mem,
                "free_memory_bytes": sys.free_memory(),
                "memory_usage_pct": (used_mem as f64 / total_mem as f64) * 100.0,
                "total_swap_bytes": total_swap,
                "used_swap_bytes": used_swap,
                "swap_usage_pct": if total_swap > 0 {
                    (used_swap as f64 / total_swap as f64) * 100.0
                } else {
                    0.0
                },
            }),
        };
        let _ = tx.send(mem_event).await;

        // ── Disk ────────────────────────────────────────────────────
        let disks = Disks::new_with_refreshed_list();
        for disk in disks.list() {
            let total = disk.total_space();
            let available = disk.available_space();
            let used = total.saturating_sub(available);

            let disk_event = TelemetryEvent {
                id: Uuid::new_v4(),
                event_type: EventType::System,
                event_action: "disk_metrics".to_string(),
                event_time: Utc::now(),
                data: json!({
                    "mount_point": disk.mount_point().to_string_lossy(),
                    "name": disk.name().to_string_lossy(),
                    "file_system": String::from_utf8_lossy(disk.file_system().as_encoded_bytes()),
                    "total_bytes": total,
                    "available_bytes": available,
                    "used_bytes": used,
                    "usage_pct": if total > 0 {
                        (used as f64 / total as f64) * 100.0
                    } else {
                        0.0
                    },
                    "is_removable": disk.is_removable(),
                }),
            };
            let _ = tx.send(disk_event).await;
        }

        // ── OS / Host ───────────────────────────────────────────────
        let os_event = TelemetryEvent {
            id: Uuid::new_v4(),
            event_type: EventType::System,
            event_action: "os_info".to_string(),
            event_time: Utc::now(),
            data: json!({
                "os_name": System::name(),
                "os_version": System::os_version(),
                "kernel_version": System::kernel_version(),
                "hostname": System::host_name(),
                "uptime_secs": System::uptime(),
                "boot_time": System::boot_time(),
                "distribution_id": System::distribution_id(),
            }),
        };
        let _ = tx.send(os_event).await;

        // ── Load average (Unix only) ────────────────────────────────
        #[cfg(unix)]
        {
            let load = System::load_average();
            let load_event = TelemetryEvent {
                id: Uuid::new_v4(),
                event_type: EventType::System,
                event_action: "load_average".to_string(),
                event_time: Utc::now(),
                data: json!({
                    "one": load.one,
                    "five": load.five,
                    "fifteen": load.fifteen,
                }),
            };
            let _ = tx.send(load_event).await;
        }

        debug!(
            cpu = format!("{:.1}%", global_cpu_usage),
            mem = format!("{:.1}%", (used_mem as f64 / total_mem as f64) * 100.0),
            "System metrics collected"
        );
    }
}
