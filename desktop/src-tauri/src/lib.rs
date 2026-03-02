//! SentinelAI Desktop — Tauri 2.0 Application
//!
//! Wraps the Next.js panel as a native desktop application with
//! system-tray integration, native notifications, and local agent
//! management.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::{Manager, Emitter};
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════════
// Tauri Commands (invokable from the frontend)
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Serialize, Deserialize)]
struct AgentStatus {
    running: bool,
    pid: Option<u32>,
    version: String,
    uptime_secs: u64,
}

/// Check if the local agent is running on this machine.
#[tauri::command]
async fn get_local_agent_status() -> Result<AgentStatus, String> {
    // In a real implementation, check if the sentinel-agent process
    // is running and retrieve its status via local IPC or HTTP.
    Ok(AgentStatus {
        running: false,
        pid: None,
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs: 0,
    })
}

/// Start the local agent.
#[tauri::command]
async fn start_local_agent() -> Result<String, String> {
    // Placeholder — would spawn the sentinel-agent binary
    Ok("Agent start requested".to_string())
}

/// Stop the local agent.
#[tauri::command]
async fn stop_local_agent() -> Result<String, String> {
    // Placeholder — would send a graceful shutdown signal
    Ok("Agent stop requested".to_string())
}

/// Get the backend connection URL from the desktop config.
#[tauri::command]
fn get_backend_url() -> String {
    // Default; in production read from persisted settings
    "https://localhost:8000".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
struct DesktopSettings {
    backend_url: String,
    auto_start_agent: bool,
    minimize_to_tray: bool,
    notification_level: String,
}

#[tauri::command]
fn get_settings() -> DesktopSettings {
    DesktopSettings {
        backend_url: "https://localhost:8000".to_string(),
        auto_start_agent: true,
        minimize_to_tray: true,
        notification_level: "high".to_string(),
    }
}

#[tauri::command]
fn save_settings(settings: DesktopSettings) -> Result<(), String> {
    // Placeholder — would persist to a config file
    println!("Settings saved: {:?}", settings);
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
// Lib export for Tauri
// ═══════════════════════════════════════════════════════════════════

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            get_local_agent_status,
            start_local_agent,
            stop_local_agent,
            get_backend_url,
            get_settings,
            save_settings,
        ])
        .setup(|app| {
            let window = app.get_webview_window("main").unwrap();
            // Set dark title bar on Windows
            #[cfg(target_os = "windows")]
            {
                let _ = window.set_title("SentinelAI — EDR Management Console");
            }

            println!("SentinelAI Desktop v{} started", env!("CARGO_PKG_VERSION"));
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("Error running SentinelAI Desktop");
}
