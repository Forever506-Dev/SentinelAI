//! Network Collector
//!
//! Monitors active network connections — TCP/UDP sockets, listening ports,
//! and DNS queries.

use chrono::Utc;
use serde_json::json;
use sysinfo::Networks;
use tokio::sync::mpsc;
use tracing::debug;
use uuid::Uuid;

use super::{TelemetryEvent, EventType};

/// Periodically collect network connection information.
pub async fn collect_network(
    tx: mpsc::Sender<TelemetryEvent>,
    interval_secs: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
    let mut previous_connections: std::collections::HashSet<String> = std::collections::HashSet::new();

    loop {
        interval.tick().await;

        // Collect active TCP connections using platform-specific methods
        let connections = get_tcp_connections().await;

        let current_keys: std::collections::HashSet<String> = connections
            .iter()
            .map(|c| format!("{}:{}-{}:{}", c.local_ip, c.local_port, c.remote_ip, c.remote_port))
            .collect();

        // Report new connections
        for conn in &connections {
            let key = format!("{}:{}-{}:{}", conn.local_ip, conn.local_port, conn.remote_ip, conn.remote_port);
            if !previous_connections.contains(&key) && !conn.remote_ip.is_empty() && conn.remote_ip != "0.0.0.0" {
                let event = TelemetryEvent {
                    id: Uuid::new_v4(),
                    event_type: EventType::Network,
                    event_action: "connect".to_string(),
                    event_time: Utc::now(),
                    data: json!({
                        "event_type": "network",
                        "event_action": "connection",
                        "source_ip": conn.local_ip,
                        "source_port": conn.local_port,
                        "dest_ip": conn.remote_ip,
                        "dest_port": conn.remote_port,
                        "protocol": conn.protocol,
                        "state": conn.state,
                        "process_id": conn.pid,
                    }),
                };

                debug!(
                    dest = format!("{}:{}", conn.remote_ip, conn.remote_port),
                    "New connection detected"
                );

                let _ = tx.send(event).await;
            }
        }

        // Detect closed connections
        for key in previous_connections.difference(&current_keys) {
            let event = TelemetryEvent {
                id: Uuid::new_v4(),
                event_type: EventType::Network,
                event_action: "close".to_string(),
                event_time: Utc::now(),
                data: json!({
                    "connection_key": key,
                }),
            };
            let _ = tx.send(event).await;
        }

        // Collect network interface stats
        let networks = Networks::new_with_refreshed_list();
        for (name, data) in &networks {
            let event = TelemetryEvent {
                id: Uuid::new_v4(),
                event_type: EventType::Network,
                event_action: "stats".to_string(),
                event_time: Utc::now(),
                data: json!({
                    "event_type": "network",
                    "event_action": "stats",
                    "interface": name,
                    "bytes_received": data.total_received(),
                    "bytes_transmitted": data.total_transmitted(),
                    "packets_received": data.total_packets_received(),
                    "packets_transmitted": data.total_packets_transmitted(),
                    "errors_received": data.total_errors_on_received(),
                    "errors_transmitted": data.total_errors_on_transmitted(),
                }),
            };
            let _ = tx.send(event).await;
        }

        previous_connections = current_keys;
    }
}

/// Represents a network connection.
#[derive(Debug)]
struct ConnectionInfo {
    local_ip: String,
    local_port: u16,
    remote_ip: String,
    remote_port: u16,
    protocol: String,
    state: String,
    pid: Option<u32>,
}

/// Get TCP connections using platform-specific methods.
async fn get_tcp_connections() -> Vec<ConnectionInfo> {
    #[cfg(target_os = "linux")]
    {
        parse_proc_net_tcp().unwrap_or_default()
    }

    #[cfg(target_os = "windows")]
    {
        get_windows_tcp_connections()
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Vec::new()
    }
}

/// Get TCP connections on Windows using netstat parsing.
#[cfg(target_os = "windows")]
fn get_windows_tcp_connections() -> Vec<ConnectionInfo> {
    use std::process::Command;

    let output = match Command::new("netstat")
        .args(["-n", "-o", "-p", "TCP"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut connections = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if !line.starts_with("TCP") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        // Parse local address (ip:port)
        let (local_ip, local_port) = match parse_netstat_addr(parts[1]) {
            Some(v) => v,
            None => continue,
        };

        // Parse remote address (ip:port)
        let (remote_ip, remote_port) = match parse_netstat_addr(parts[2]) {
            Some(v) => v,
            None => continue,
        };

        // Skip loopback and unconnected
        if remote_ip == "0.0.0.0" || remote_ip == "*" {
            continue;
        }

        let state = parts[3].to_string();
        let pid = parts.get(4).and_then(|p| p.parse::<u32>().ok());

        connections.push(ConnectionInfo {
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            protocol: "tcp".to_string(),
            state,
            pid,
        });
    }

    connections
}

/// Parse a netstat address like "192.168.1.1:443" or "[::1]:443"
#[cfg(target_os = "windows")]
fn parse_netstat_addr(addr: &str) -> Option<(String, u16)> {
    if let Some(colon_pos) = addr.rfind(':') {
        let ip = addr[..colon_pos].to_string();
        let port: u16 = addr[colon_pos + 1..].parse().ok()?;
        Some((ip, port))
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn parse_proc_net_tcp() -> Result<Vec<ConnectionInfo>, std::io::Error> {
    let content = std::fs::read_to_string("/proc/net/tcp")?;
    let mut connections = Vec::new();

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        if let (Some(local), Some(remote)) = (
            parse_hex_address(fields[1]),
            parse_hex_address(fields[2]),
        ) {
            connections.push(ConnectionInfo {
                local_ip: local.0,
                local_port: local.1,
                remote_ip: remote.0,
                remote_port: remote.1,
                protocol: "tcp".to_string(),
                state: parse_tcp_state(fields[3]),
                pid: None,
            });
        }
    }

    Ok(connections)
}

#[cfg(target_os = "linux")]
fn parse_hex_address(hex: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 {
        return None;
    }

    let ip_hex = u32::from_str_radix(parts[0], 16).ok()?;
    let port = u16::from_str_radix(parts[1], 16).ok()?;

    let ip = format!(
        "{}.{}.{}.{}",
        ip_hex & 0xFF,
        (ip_hex >> 8) & 0xFF,
        (ip_hex >> 16) & 0xFF,
        (ip_hex >> 24) & 0xFF,
    );

    Some((ip, port))
}

#[cfg(target_os = "linux")]
fn parse_tcp_state(hex: &str) -> String {
    match hex {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }.to_string()
}
