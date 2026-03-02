import sys

path = r'F:\SentinelAI\agent\src\collector\network.rs'
with open(path, 'r') as f:
    content = f.read()

# 1. Fix the connect event data to include event_type/event_action
old_connect = '''                    data: json!({
                        "source_ip": conn.local_ip,
                        "source_port": conn.local_port,
                        "dest_ip": conn.remote_ip,
                        "dest_port": conn.remote_port,
                        "protocol": conn.protocol,
                        "state": conn.state,
                        "process_id": conn.pid,
                    }),'''

new_connect = '''                    data: json!({
                        "event_type": "network",
                        "event_action": "connection",
                        "source_ip": conn.local_ip,
                        "source_port": conn.local_port,
                        "dest_ip": conn.remote_ip,
                        "dest_port": conn.remote_port,
                        "protocol": conn.protocol,
                        "state": conn.state,
                        "process_id": conn.pid,
                    }),'''

if old_connect in content:
    content = content.replace(old_connect, new_connect)
    print("Fixed connect event data")
else:
    print("WARNING: Could not find connect event data block")

# 2. Fix stats event data
old_stats = '''                data: json!({
                    "interface": name,
                    "bytes_received": data.total_received(),
                    "bytes_transmitted": data.total_transmitted(),
                    "packets_received": data.total_packets_received(),
                    "packets_transmitted": data.total_packets_transmitted(),
                    "errors_received": data.total_errors_on_received(),
                    "errors_transmitted": data.total_errors_on_transmitted(),
                }),'''

new_stats = '''                data: json!({
                    "event_type": "network",
                    "event_action": "stats",
                    "interface": name,
                    "bytes_received": data.total_received(),
                    "bytes_transmitted": data.total_transmitted(),
                    "packets_received": data.total_packets_received(),
                    "packets_transmitted": data.total_packets_transmitted(),
                    "errors_received": data.total_errors_on_received(),
                    "errors_transmitted": data.total_errors_on_transmitted(),
                }),'''

if old_stats in content:
    content = content.replace(old_stats, new_stats)
    print("Fixed stats event data")
else:
    print("WARNING: Could not find stats event data block")

# 3. Replace the Windows fallback for TCP connections
old_fallback = '''    #[cfg(not(target_os = "linux"))]
    {
        // Fallback: empty list (platform-specific implementation needed)
        Vec::new()
    }'''

new_fallback = '''    #[cfg(target_os = "windows")]
    {
        get_windows_tcp_connections()
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Vec::new()
    }'''

if old_fallback in content:
    content = content.replace(old_fallback, new_fallback)
    print("Fixed Windows TCP fallback")
else:
    print("WARNING: Could not find Windows fallback block")

# 4. Add Windows TCP implementation before the Linux parse_proc_net_tcp
windows_impl = '''
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

'''

# Insert before the Linux implementation
insert_marker = '#[cfg(target_os = "linux")]'
first_linux = content.find(insert_marker)
if first_linux >= 0:
    content = content[:first_linux] + windows_impl + content[first_linux:]
    print("Added Windows TCP connection implementation")
else:
    print("WARNING: Could not find Linux cfg marker for insertion")

with open(path, 'w') as f:
    f.write(content)

print("Done - network.rs updated")
