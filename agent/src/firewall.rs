//! Firewall Management Module
//!
//! Cross-platform firewall rule enumeration and manipulation.
//! Windows: `netsh advfirewall` / `New-NetFirewallRule`
//! Linux:   `iptables` (fallback `nftables`)

use std::process::Command;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, warn};

use crate::executor::CommandResult;

/// Parsed firewall rule (common representation for both OSes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub name: String,
    pub direction: String,      // inbound | outbound
    pub action: String,         // allow | block
    pub protocol: String,       // tcp | udp | any | icmp
    pub local_port: String,     // port number(s) or "any"
    pub remote_port: String,
    pub local_address: String,
    pub remote_address: String,
    pub enabled: bool,
    pub profile: String,        // domain | private | public | any
}

// =====================================================================
// List Firewall Rules
// =====================================================================

pub fn list_rules(command_id: &str) -> CommandResult {
    info!("Listing firewall rules");

    if cfg!(windows) {
        list_rules_windows(command_id)
    } else {
        list_rules_linux(command_id)
    }
}

fn list_rules_windows(command_id: &str) -> CommandResult {
    // Use `netsh` for speed — runs in <0.5s vs 25s+ for per-rule PowerShell cmdlets.
    // We fetch inbound + outbound in two fast calls and parse the text blocks.
    let mut all_rules: Vec<serde_json::Value> = Vec::new();

    for dir in ["in", "out"] {
        let result = Command::new("netsh")
            .args(["advfirewall", "firewall", "show", "rule", "name=all", &format!("dir={}", dir), "status=enabled", "verbose"])
            .output();

        match result {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let direction_label = if dir == "in" { "Inbound" } else { "Outbound" };
                parse_netsh_rules(&stdout, direction_label, &mut all_rules);
            }
            Err(e) => {
                info!("netsh {} failed: {}", dir, e);
            }
        }
    }

    let count = all_rules.len();
    let rules_array = json!(all_rules);

    // Human-readable summary
    let mut lines = vec![format!("Active firewall rules: {}", count)];
    lines.push(format!("{:<50} {:>8} {:>7} {:>6} {:>12} {:>15}",
        "NAME", "DIR", "ACTION", "PROTO", "LOCAL PORT", "REMOTE ADDR"));
    lines.push("─".repeat(110));

    for r in all_rules.iter().take(200) {
        lines.push(format!("{:<50} {:>8} {:>7} {:>6} {:>12} {:>15}",
            truncate_str(r["Name"].as_str().unwrap_or("?"), 49),
            r["Direction"].as_str().unwrap_or("?"),
            r["Action"].as_str().unwrap_or("?"),
            r["Protocol"].as_str().unwrap_or("?"),
            r["LocalPort"].as_str().unwrap_or("Any"),
            truncate_str(r["RemoteAddress"].as_str().unwrap_or("Any"), 14),
        ));
    }
    if count > 200 {
        lines.push(format!("... and {} more rules", count - 200));
    }

    CommandResult {
        command_id: command_id.to_string(),
        status: "completed".into(),
        output: lines.join("\n"),
        data: Some(json!({ "rules": rules_array, "total": count, "os": "windows" })),
        exit_code: Some(0),
    }
}

/// Parse `netsh advfirewall firewall show rule ... verbose` text output.
/// Each rule is separated by a blank line, fields are "Key:  Value" lines.
fn parse_netsh_rules(text: &str, default_direction: &str, out: &mut Vec<serde_json::Value>) {
    let mut current: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    for line in text.lines() {
        let trimmed = line.trim();

        // Skip separator lines and header noise
        if trimmed.is_empty() || trimmed.starts_with("---") || trimmed.starts_with("No rules") {
            if !current.is_empty() {
                out.push(netsh_map_to_rule(&current, default_direction));
                current.clear();
            }
            continue;
        }

        // Lines look like: "Rule Name:                       Windows Update"
        if let Some(pos) = trimmed.find(':') {
            let key = trimmed[..pos].trim().to_string();
            let val = trimmed[pos + 1..].trim().to_string();
            current.insert(key, val);
        }
    }
    // Don't forget last rule
    if !current.is_empty() {
        out.push(netsh_map_to_rule(&current, default_direction));
    }
}

fn netsh_map_to_rule(m: &std::collections::HashMap<String, String>, default_dir: &str) -> serde_json::Value {
    let dir = m.get("Direction").map(|s| s.as_str()).unwrap_or(default_dir);
    let action_raw = m.get("Action").map(|s| s.as_str()).unwrap_or("Allow");
    json!({
        "Name":          m.get("Rule Name").cloned().unwrap_or_default(),
        "Direction":     dir,
        "Action":        action_raw,
        "Protocol":      m.get("Protocol").cloned().unwrap_or_else(|| "Any".into()),
        "LocalPort":     m.get("LocalPort").cloned().unwrap_or_else(|| "Any".into()),
        "RemotePort":    m.get("RemotePort").cloned().unwrap_or_else(|| "Any".into()),
        "LocalAddress":  m.get("LocalIP").cloned().unwrap_or_else(|| "Any".into()),
        "RemoteAddress": m.get("RemoteIP").cloned().unwrap_or_else(|| "Any".into()),
        "Enabled":       m.get("Enabled").cloned().unwrap_or_else(|| "Yes".into()),
        "Profile":       m.get("Profiles").cloned().unwrap_or_else(|| "Any".into()),
    })
}

fn list_rules_linux(command_id: &str) -> CommandResult {
    // Try iptables first, fall back to nftables
    let result = Command::new("sh")
        .args(["-c", r#"
if command -v iptables >/dev/null 2>&1; then
  echo "=== IPTABLES ==="
  echo "--- INPUT ---"
  iptables -L INPUT -n -v --line-numbers 2>/dev/null
  echo ""
  echo "--- OUTPUT ---"
  iptables -L OUTPUT -n -v --line-numbers 2>/dev/null
  echo ""
  echo "--- FORWARD ---"
  iptables -L FORWARD -n -v --line-numbers 2>/dev/null
  echo ""
  echo "=== IPTABLES-JSON ==="
  iptables-save 2>/dev/null
elif command -v nft >/dev/null 2>&1; then
  echo "=== NFTABLES ==="
  nft list ruleset 2>/dev/null
else
  echo "ERROR: No firewall management tool found (iptables/nft)"
  exit 1
fi

echo ""
echo "=== UFW STATUS ==="
ufw status verbose 2>/dev/null || echo "ufw not available"
"#])
        .output();

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();

            // Parse iptables-save output into structured rules
            let rules = parse_iptables_save(&stdout);
            let count = rules.len();

            CommandResult {
                command_id: command_id.to_string(),
                status: "completed".into(),
                output: stdout,
                data: Some(json!({ "rules": rules, "total": count, "os": "linux" })),
                exit_code: output.status.code(),
            }
        }
        Err(e) => error_result(command_id, &format!("Failed to list Linux firewall rules: {}", e)),
    }
}

/// Parse iptables-save output into structured rule objects.
fn parse_iptables_save(raw: &str) -> Vec<serde_json::Value> {
    let mut rules = Vec::new();
    let mut current_chain = String::new();

    for line in raw.lines() {
        let line = line.trim();
        if line.starts_with(':') {
            // Chain declaration like :INPUT ACCEPT [0:0]
            let parts: Vec<&str> = line[1..].splitn(2, ' ').collect();
            if !parts.is_empty() {
                current_chain = parts[0].to_string();
            }
        } else if line.starts_with("-A ") {
            // Rule like -A INPUT -p tcp --dport 22 -j ACCEPT
            let mut rule = json!({
                "chain": current_chain,
                "raw": line,
                "protocol": "any",
                "local_port": "any",
                "remote_address": "any",
                "action": "unknown",
            });

            let parts: Vec<&str> = line.split_whitespace().collect();
            let mut i = 0;
            while i < parts.len() {
                match parts[i] {
                    "-p" if i + 1 < parts.len() => {
                        rule["protocol"] = json!(parts[i + 1]);
                        i += 1;
                    }
                    "--dport" if i + 1 < parts.len() => {
                        rule["local_port"] = json!(parts[i + 1]);
                        i += 1;
                    }
                    "--sport" if i + 1 < parts.len() => {
                        rule["remote_port"] = json!(parts[i + 1]);
                        i += 1;
                    }
                    "-s" if i + 1 < parts.len() => {
                        rule["remote_address"] = json!(parts[i + 1]);
                        i += 1;
                    }
                    "-d" if i + 1 < parts.len() => {
                        rule["local_address"] = json!(parts[i + 1]);
                        i += 1;
                    }
                    "-j" if i + 1 < parts.len() => {
                        rule["action"] = json!(parts[i + 1].to_lowercase());
                        i += 1;
                    }
                    _ => {}
                }
                i += 1;
            }
            rules.push(rule);
        }
    }
    rules
}

// =====================================================================
// Add Firewall Rule
// =====================================================================

pub fn add_rule(command_id: &str, params: &serde_json::Value) -> CommandResult {
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("SentinelAI-Rule");
    let direction = params.get("direction").and_then(|v| v.as_str()).unwrap_or("inbound");
    let action = params.get("action").and_then(|v| v.as_str()).unwrap_or("block");
    let protocol = params.get("protocol").and_then(|v| v.as_str()).unwrap_or("tcp");
    let port = params.get("port").and_then(|v| v.as_str()).unwrap_or("");
    let remote_addr = params.get("remote_address").and_then(|v| v.as_str()).unwrap_or("");

    // Input validation
    if !["inbound", "outbound"].contains(&direction) {
        return error_result(command_id, "Invalid direction: must be 'inbound' or 'outbound'");
    }
    if !["allow", "block"].contains(&action) {
        return error_result(command_id, "Invalid action: must be 'allow' or 'block'");
    }
    if !["tcp", "udp", "any", "icmp"].contains(&protocol) {
        return error_result(command_id, "Invalid protocol: must be 'tcp', 'udp', 'icmp', or 'any'");
    }

    // Validate port if provided
    if !port.is_empty() {
        if let Err(_) = validate_port(port) {
            return error_result(command_id, &format!("Invalid port: {}", port));
        }
    }

    info!(name = %name, direction = %direction, action = %action, protocol = %protocol,
          port = %port, remote_addr = %remote_addr, "Adding firewall rule");

    if cfg!(windows) {
        add_rule_windows(command_id, name, direction, action, protocol, port, remote_addr)
    } else {
        add_rule_linux(command_id, direction, action, protocol, port, remote_addr)
    }
}

fn add_rule_windows(command_id: &str, name: &str, direction: &str, action: &str,
                     protocol: &str, port: &str, remote_addr: &str) -> CommandResult {
    let dir = if direction == "inbound" { "in" } else { "out" };
    let act = if action == "block" { "block" } else { "allow" };

    let mut cmd_str = format!(
        "netsh advfirewall firewall add rule name=\"SentinelAI-{}\" dir={} action={} protocol={}",
        name, dir, act, protocol
    );

    if !port.is_empty() {
        cmd_str.push_str(&format!(" localport={}", port));
    }
    if !remote_addr.is_empty() {
        cmd_str.push_str(&format!(" remoteip={}", remote_addr));
    }
    cmd_str.push_str(" enable=yes");

    let result = Command::new("cmd").args(["/C", &cmd_str]).output();

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let combined = if stderr.is_empty() { stdout.clone() } else { format!("{}\n{}", stdout, stderr) };

            CommandResult {
                command_id: command_id.to_string(),
                status: if output.status.success() { "completed" } else { "error" }.into(),
                output: format!("Rule added: {}\n{}", cmd_str, combined),
                data: Some(json!({
                    "rule_name": format!("SentinelAI-{}", name),
                    "direction": direction,
                    "action": action,
                    "protocol": protocol,
                    "port": port,
                    "remote_address": remote_addr,
                })),
                exit_code: output.status.code(),
            }
        }
        Err(e) => error_result(command_id, &format!("Failed to add rule: {}", e)),
    }
}

fn add_rule_linux(command_id: &str, direction: &str, action: &str,
                   protocol: &str, port: &str, remote_addr: &str) -> CommandResult {
    let chain = if direction == "inbound" { "INPUT" } else { "OUTPUT" };
    let target = if action == "block" { "DROP" } else { "ACCEPT" };

    let mut cmd_str = format!("iptables -A {}", chain);

    if protocol != "any" {
        cmd_str.push_str(&format!(" -p {}", protocol));
    }
    if !port.is_empty() {
        cmd_str.push_str(&format!(" --dport {}", port));
    }
    if !remote_addr.is_empty() {
        cmd_str.push_str(&format!(" -s {}", remote_addr));
    }
    cmd_str.push_str(&format!(" -j {} -m comment --comment \"SentinelAI-managed\"", target));

    let result = Command::new("sh").args(["-c", &cmd_str]).output();

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let combined = if stderr.is_empty() { stdout.clone() } else { format!("{}\n{}", stdout, stderr) };

            CommandResult {
                command_id: command_id.to_string(),
                status: if output.status.success() { "completed" } else { "error" }.into(),
                output: format!("Rule added: {}\n{}", cmd_str, combined),
                data: Some(json!({
                    "chain": chain,
                    "direction": direction,
                    "action": action,
                    "protocol": protocol,
                    "port": port,
                    "remote_address": remote_addr,
                })),
                exit_code: output.status.code(),
            }
        }
        Err(e) => error_result(command_id, &format!("Failed to add iptables rule: {}", e)),
    }
}

// =====================================================================
// Delete Firewall Rule
// =====================================================================

pub fn delete_rule(command_id: &str, params: &serde_json::Value) -> CommandResult {
    info!("Deleting firewall rule");

    if cfg!(windows) {
        delete_rule_windows(command_id, params)
    } else {
        delete_rule_linux(command_id, params)
    }
}

fn delete_rule_windows(command_id: &str, params: &serde_json::Value) -> CommandResult {
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");

    if name.is_empty() {
        return error_result(command_id, "Rule name is required for deletion on Windows");
    }

    // Try the exact name first (handles both pre-existing and SentinelAI-prefixed rules)
    let cmd_str = format!("netsh advfirewall firewall delete rule name=\"{}\"", name);
    let result = Command::new("cmd").args(["/C", &cmd_str]).output();

    match result {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            CommandResult {
                command_id: command_id.to_string(),
                status: "completed".into(),
                output: format!("Delete: {}\n{}", cmd_str, stdout),
                data: Some(json!({ "deleted_rule": name })),
                exit_code: output.status.code(),
            }
        }
        _ => {
            // Fallback: try with SentinelAI- prefix (rules created by add_rule have this)
            let prefixed = format!("SentinelAI-{}", name);
            let cmd_str2 = format!("netsh advfirewall firewall delete rule name=\"{}\"", prefixed);
            let result2 = Command::new("cmd").args(["/C", &cmd_str2]).output();

            match result2 {
                Ok(output2) => {
                    let stdout = String::from_utf8_lossy(&output2.stdout).to_string();
                    CommandResult {
                        command_id: command_id.to_string(),
                        status: if output2.status.success() { "completed" } else { "error" }.into(),
                        output: format!("Delete (prefixed): {}\n{}", cmd_str2, stdout),
                        data: Some(json!({ "deleted_rule": prefixed })),
                        exit_code: output2.status.code(),
                    }
                }
                Err(e) => error_result(command_id, &format!("Failed to delete rule '{}' (also tried '{}'): {}", name, prefixed, e)),
            }
        }
    }
}

fn delete_rule_linux(command_id: &str, params: &serde_json::Value) -> CommandResult {
    // Accept either rule_number+chain or raw specification
    let chain = params.get("chain").and_then(|v| v.as_str()).unwrap_or("INPUT");
    let rule_number = params.get("rule_number").and_then(|v| v.as_u64());

    let cmd_str = if let Some(num) = rule_number {
        format!("iptables -D {} {}", chain, num)
    } else {
        // Try to delete by specification
        let protocol = params.get("protocol").and_then(|v| v.as_str()).unwrap_or("");
        let port = params.get("port").and_then(|v| v.as_str()).unwrap_or("");
        let remote = params.get("remote_address").and_then(|v| v.as_str()).unwrap_or("");
        let action = params.get("action").and_then(|v| v.as_str()).unwrap_or("DROP");
        let target = if action == "block" || action == "DROP" { "DROP" } else { "ACCEPT" };

        let mut s = format!("iptables -D {}", chain);
        if !protocol.is_empty() { s.push_str(&format!(" -p {}", protocol)); }
        if !port.is_empty() { s.push_str(&format!(" --dport {}", port)); }
        if !remote.is_empty() { s.push_str(&format!(" -s {}", remote)); }
        s.push_str(&format!(" -j {}", target));
        s
    };

    let result = Command::new("sh").args(["-c", &cmd_str]).output();

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let combined = if stderr.is_empty() { stdout } else { format!("{}\n{}", stdout, stderr) };

            CommandResult {
                command_id: command_id.to_string(),
                status: if output.status.success() { "completed" } else { "error" }.into(),
                output: format!("Delete: {}\n{}", cmd_str, combined),
                data: Some(json!({ "command": cmd_str })),
                exit_code: output.status.code(),
            }
        }
        Err(e) => error_result(command_id, &format!("Failed to delete rule: {}", e)),
    }
}

// =====================================================================
// Edit Firewall Rule (delete + re-add with new params)
// =====================================================================

pub fn edit_rule(command_id: &str, params: &serde_json::Value) -> CommandResult {
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if name.is_empty() {
        return error_result(command_id, "Rule name is required for edit");
    }

    info!(name = %name, "Editing firewall rule");

    if cfg!(windows) {
        edit_rule_windows(command_id, name, params)
    } else {
        // On Linux, we need rule_number to delete, then re-add
        let chain = params.get("chain").and_then(|v| v.as_str()).unwrap_or("INPUT");
        if let Some(num) = params.get("rule_number").and_then(|v| v.as_u64()) {
            let del_cmd = format!("iptables -D {} {}", chain, num);
            let _ = Command::new("sh").args(["-c", &del_cmd]).output();
        }
        add_rule(command_id, params)
    }
}

/// Edit rule in-place on Windows using `netsh advfirewall firewall set rule`.
/// This modifies the existing rule without changing its name.
/// Note: direction cannot be changed in-place on Windows — it's a selector, not modifiable.
/// If direction changes, we must delete + re-add.
fn edit_rule_windows(command_id: &str, name: &str, params: &serde_json::Value) -> CommandResult {
    let new_direction = params.get("direction").and_then(|v| v.as_str());
    let new_action    = params.get("action").and_then(|v| v.as_str());
    let new_protocol  = params.get("protocol").and_then(|v| v.as_str());
    let new_port      = params.get("port").and_then(|v| v.as_str());
    let new_remote    = params.get("remote_address").and_then(|v| v.as_str());

    // Resolve which actual name exists in Windows Firewall
    let actual_name = resolve_rule_name_windows(name);
    if actual_name.is_none() {
        return error_result(command_id, &format!(
            "Rule '{}' not found in Windows Firewall (also tried 'SentinelAI-{}')", name, name
        ));
    }
    let actual_name = actual_name.unwrap();

    // Build the "new" clause for netsh set rule.
    // Syntax: netsh advfirewall firewall set rule name="X" [dir=in|out] new <field>=<value> ...
    // dir= is a SELECTOR (identifies which rules), not a modifiable field.
    let mut new_parts: Vec<String> = Vec::new();

    if let Some(act) = new_action {
        let a = if act == "block" { "block" } else { "allow" };
        new_parts.push(format!("action={}", a));
    }
    // Determine effective protocol: either the one being set, or the existing one on the rule
    let effective_protocol = new_protocol
        .map(|s| s.to_lowercase())
        .or_else(|| detect_rule_protocol(&actual_name).map(|s| s.to_lowercase()));
    let proto_is_any = effective_protocol.as_deref() == Some("any") || effective_protocol.is_none();

    if let Some(proto) = new_protocol {
        // Only include protocol= if it's not "any" ("any" is the default)
        if !proto.eq_ignore_ascii_case("any") {
            new_parts.push(format!("protocol={}", proto));
        }
    }
    // netsh rejects localport= when protocol is Any — only include for TCP/UDP
    if let Some(p) = new_port {
        if !proto_is_any {
            if !p.is_empty() && !p.eq_ignore_ascii_case("any") {
                new_parts.push(format!("localport={}", p));
            }
        }
    }
    // Only include remoteip= if it's not the default "any"
    if let Some(ra) = new_remote {
        if !ra.is_empty() && !ra.eq_ignore_ascii_case("any") {
            new_parts.push(format!("remoteip={}", ra));
        }
    }

    // If direction changes, we must delete and re-add since dir is a selector, not settable
    if let Some(dir) = new_direction {
        let old_dir = detect_rule_direction(&actual_name);
        let normalized_new = if dir == "inbound" { "in" } else { "out" };
        if old_dir.as_deref() != Some(normalized_new) {
            info!(name = %actual_name, old_dir = ?old_dir, new_dir = %dir, "Direction change requires delete+re-add");
            // Delete existing rule
            let del_cmd = format!("netsh advfirewall firewall delete rule name=\"{}\"", actual_name);
            let del_result = Command::new("cmd").args(["/C", &del_cmd]).output();
            match del_result {
                Ok(output) if !output.status.success() => {
                    let stderr = String::from_utf8_lossy(&output.stdout);
                    return error_result(command_id, &format!("Failed to delete rule for direction change: {}", stderr));
                }
                Err(e) => return error_result(command_id, &format!("Failed to run delete: {}", e)),
                _ => {}
            }

            // Re-add with new direction and all specified fields, preserving original name
            let dir_flag = if dir == "inbound" { "in" } else { "out" };
            let act = new_action.unwrap_or("allow");
            let act_flag = if act == "block" { "block" } else { "allow" };
            let proto = new_protocol.unwrap_or("any");

            let mut cmd_str = format!(
                "netsh advfirewall firewall add rule name=\"{}\" dir={} action={} protocol={}",
                actual_name, dir_flag, act_flag, proto
            );
            // Only add port if protocol supports it (TCP/UDP)
            let proto_lower = proto.to_lowercase();
            if proto_lower != "any" {
                if let Some(p) = new_port {
                    if !p.is_empty() && !p.eq_ignore_ascii_case("any") {
                        cmd_str.push_str(&format!(" localport={}", p));
                    }
                }
            }
            if let Some(ra) = new_remote {
                if !ra.is_empty() && !ra.eq_ignore_ascii_case("any") {
                    cmd_str.push_str(&format!(" remoteip={}", ra));
                }
            }
            cmd_str.push_str(" enable=yes");

            let result = Command::new("cmd").args(["/C", &cmd_str]).output();
            return match result {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    CommandResult {
                        command_id: command_id.to_string(),
                        status: if output.status.success() { "completed" } else { "error" }.into(),
                        output: format!("Direction changed (delete+re-add): {}\n{}", cmd_str, stdout),
                        data: Some(json!({ "rule_name": actual_name, "direction_changed": true })),
                        exit_code: output.status.code(),
                    }
                }
                Err(e) => error_result(command_id, &format!("Failed to re-add rule: {}", e)),
            };
        }
    }

    if new_parts.is_empty() {
        return error_result(command_id, "No fields to modify");
    }

    // Use `set rule` for in-place modification (direction unchanged)
    // Add dir= as selector to be more precise
    let dir_selector = if let Some(d) = detect_rule_direction(&actual_name) {
        format!(" dir={}", d)
    } else {
        String::new()
    };

    let cmd_str = format!(
        "netsh advfirewall firewall set rule name=\"{}\"{} new {}",
        actual_name, dir_selector, new_parts.join(" ")
    );

    info!(cmd = %cmd_str, "Attempting rule edit");
    let result = Command::new("cmd").args(["/C", &cmd_str]).output();

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let combined = if stderr.is_empty() { stdout } else { format!("{}\n{}", stdout, stderr) };
            CommandResult {
                command_id: command_id.to_string(),
                status: if output.status.success() { "completed" } else { "error" }.into(),
                output: format!("Rule modified: {}\n{}", cmd_str, combined),
                data: Some(json!({ "rule_name": actual_name, "changes": new_parts })),
                exit_code: output.status.code(),
            }
        }
        Err(e) => error_result(command_id, &format!("Failed to modify rule: {}", e)),
    }
}

/// Check if a rule name exists in Windows Firewall, trying exact name then SentinelAI- prefix.
fn resolve_rule_name_windows(name: &str) -> Option<String> {
    // Try exact name first
    let cmd = format!("netsh advfirewall firewall show rule name=\"{}\"", name);
    if let Ok(output) = Command::new("cmd").args(["/C", &cmd]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.contains("No rules match") && output.status.success() {
            return Some(name.to_string());
        }
    }

    // Try SentinelAI- prefix
    if !name.starts_with("SentinelAI-") {
        let prefixed = format!("SentinelAI-{}", name);
        let cmd = format!("netsh advfirewall firewall show rule name=\"{}\"", prefixed);
        if let Ok(output) = Command::new("cmd").args(["/C", &cmd]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if !stdout.contains("No rules match") && output.status.success() {
                return Some(prefixed);
            }
        }
    }

    None
}

/// Detect the direction of an existing rule (returns "in" or "out").
fn detect_rule_direction(name: &str) -> Option<String> {
    let cmd = format!("netsh advfirewall firewall show rule name=\"{}\" verbose", name);
    if let Ok(output) = Command::new("cmd").args(["/C", &cmd]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if let Some(pos) = trimmed.find(':') {
                let key = trimmed[..pos].trim();
                let val = trimmed[pos + 1..].trim();
                if key == "Direction" {
                    return match val {
                        "In" => Some("in".to_string()),
                        "Out" => Some("out".to_string()),
                        _ => None,
                    };
                }
            }
        }
    }
    None
}

/// Detect the protocol of an existing rule (returns e.g. "TCP", "UDP", "Any").
fn detect_rule_protocol(name: &str) -> Option<String> {
    let cmd = format!("netsh advfirewall firewall show rule name=\"{}\" verbose", name);
    if let Ok(output) = Command::new("cmd").args(["/C", &cmd]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if let Some(pos) = trimmed.find(':') {
                let key = trimmed[..pos].trim();
                let val = trimmed[pos + 1..].trim();
                if key == "Protocol" {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

// =====================================================================
// Toggle Firewall Rule (enable/disable)
// =====================================================================

pub fn toggle_rule(command_id: &str, params: &serde_json::Value) -> CommandResult {
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let enabled = params.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);

    if name.is_empty() {
        return error_result(command_id, "Rule name is required for toggle");
    }

    info!(name = %name, enabled = %enabled, "Toggling firewall rule");

    if cfg!(windows) {
        let enable_str = if enabled { "yes" } else { "no" };
        let cmd_str = format!(
            "netsh advfirewall firewall set rule name=\"{}\" new enable={}",
            name, enable_str
        );
        let result = Command::new("cmd").args(["/C", &cmd_str]).output();

        match result {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                CommandResult {
                    command_id: command_id.to_string(),
                    status: if output.status.success() { "completed" } else { "error" }.into(),
                    output: format!("Toggle: {}\n{}", cmd_str, stdout),
                    data: Some(json!({ "rule_name": name, "enabled": enabled })),
                    exit_code: output.status.code(),
                }
            }
            Err(e) => error_result(command_id, &format!("Failed to toggle rule: {}", e)),
        }
    } else {
        // Linux iptables doesn't have enable/disable — we delete or re-add
        error_result(command_id, "Toggle not supported on Linux iptables — use delete/add instead")
    }
}

// =====================================================================
// Snapshot Rules (full capture for drift detection)
// =====================================================================

pub fn snapshot_rules(command_id: &str) -> CommandResult {
    info!("Taking full firewall rule snapshot for drift detection");

    // Re-use list_rules but tag it as a snapshot
    let mut result = list_rules(command_id);
    if let Some(ref mut data) = result.data {
        if let Some(obj) = data.as_object_mut() {
            obj.insert("snapshot".into(), json!(true));
            obj.insert("captured_at".into(), json!(chrono::Utc::now().to_rfc3339()));
        }
    }
    result
}

// =====================================================================
// Quarantine (network isolation levels)
// =====================================================================

pub fn set_quarantine(command_id: &str, params: &serde_json::Value) -> CommandResult {
    let level = params.get("level").and_then(|v| v.as_str()).unwrap_or("none");

    info!(level = %level, "Setting quarantine level");

    match level {
        "none" => remove_quarantine(command_id),
        "partial" => apply_partial_quarantine(command_id, params),
        "full" => apply_full_quarantine(command_id, params),
        _ => error_result(command_id, &format!("Unknown quarantine level: {}", level)),
    }
}

fn remove_quarantine(command_id: &str) -> CommandResult {
    info!("Removing quarantine — restoring normal connectivity");

    if cfg!(windows) {
        // Delete all SentinelAI-Quarantine rules
        let cmd = "netsh advfirewall firewall delete rule name=all dir=in | findstr /i \"SentinelAI-Quarantine\" & netsh advfirewall firewall delete rule name=\"SentinelAI-Quarantine-BlockAll-In\" & netsh advfirewall firewall delete rule name=\"SentinelAI-Quarantine-BlockAll-Out\" & netsh advfirewall firewall delete rule name=\"SentinelAI-Quarantine-AllowBackend-In\" & netsh advfirewall firewall delete rule name=\"SentinelAI-Quarantine-AllowBackend-Out\"";
        let _ = Command::new("cmd").args(["/C", cmd]).output();

        CommandResult {
            command_id: command_id.to_string(),
            status: "completed".into(),
            output: "Quarantine removed — normal connectivity restored".into(),
            data: Some(json!({ "quarantine_level": "none" })),
            exit_code: Some(0),
        }
    } else {
        // Remove iptables quarantine rules (marked with comment)
        let cmd = "iptables -S | grep 'SentinelAI-Quarantine' | sed 's/-A/-D/' | while read rule; do iptables $rule; done";
        let _ = Command::new("sh").args(["-c", cmd]).output();

        CommandResult {
            command_id: command_id.to_string(),
            status: "completed".into(),
            output: "Quarantine removed".into(),
            data: Some(json!({ "quarantine_level": "none" })),
            exit_code: Some(0),
        }
    }
}

fn apply_partial_quarantine(command_id: &str, params: &serde_json::Value) -> CommandResult {
    let backend_ip = params.get("backend_ip").and_then(|v| v.as_str()).unwrap_or("");

    info!(backend_ip = %backend_ip, "Applying partial quarantine — backend comms only");

    if cfg!(windows) {
        // Step 1: Allow backend communication
        if !backend_ip.is_empty() {
            let allow_in = format!(
                "netsh advfirewall firewall add rule name=\"SentinelAI-Quarantine-AllowBackend-In\" dir=in action=allow remoteip={} enable=yes",
                backend_ip
            );
            let allow_out = format!(
                "netsh advfirewall firewall add rule name=\"SentinelAI-Quarantine-AllowBackend-Out\" dir=out action=allow remoteip={} enable=yes",
                backend_ip
            );
            let _ = Command::new("cmd").args(["/C", &allow_in]).output();
            let _ = Command::new("cmd").args(["/C", &allow_out]).output();
        }

        // Step 2: Block everything else
        let block_in = "netsh advfirewall firewall add rule name=\"SentinelAI-Quarantine-BlockAll-In\" dir=in action=block enable=yes";
        let block_out = "netsh advfirewall firewall add rule name=\"SentinelAI-Quarantine-BlockAll-Out\" dir=out action=block enable=yes";
        let _ = Command::new("cmd").args(["/C", block_in]).output();
        let _ = Command::new("cmd").args(["/C", block_out]).output();

        CommandResult {
            command_id: command_id.to_string(),
            status: "completed".into(),
            output: format!("Partial quarantine applied — only backend ({}) allowed", backend_ip),
            data: Some(json!({ "quarantine_level": "partial", "backend_ip": backend_ip })),
            exit_code: Some(0),
        }
    } else {
        // Linux: allow backend, block rest
        let mut cmds = Vec::new();
        if !backend_ip.is_empty() {
            cmds.push(format!("iptables -I INPUT -s {} -j ACCEPT -m comment --comment \"SentinelAI-Quarantine\"", backend_ip));
            cmds.push(format!("iptables -I OUTPUT -d {} -j ACCEPT -m comment --comment \"SentinelAI-Quarantine\"", backend_ip));
        }
        cmds.push("iptables -A INPUT -j DROP -m comment --comment \"SentinelAI-Quarantine\"".into());
        cmds.push("iptables -A OUTPUT -j DROP -m comment --comment \"SentinelAI-Quarantine\"".into());

        for cmd in &cmds {
            let _ = Command::new("sh").args(["-c", cmd]).output();
        }

        CommandResult {
            command_id: command_id.to_string(),
            status: "completed".into(),
            output: format!("Partial quarantine applied"),
            data: Some(json!({ "quarantine_level": "partial", "backend_ip": backend_ip })),
            exit_code: Some(0),
        }
    }
}

fn apply_full_quarantine(command_id: &str, params: &serde_json::Value) -> CommandResult {
    let backend_ip = params.get("backend_ip").and_then(|v| v.as_str()).unwrap_or("");

    info!("Applying FULL quarantine — heartbeat only");

    if cfg!(windows) {
        // Allow only heartbeat port to backend
        if !backend_ip.is_empty() {
            let allow_hb = format!(
                "netsh advfirewall firewall add rule name=\"SentinelAI-Quarantine-AllowBackend-Out\" dir=out action=allow protocol=tcp remoteip={} remoteport=8000 enable=yes",
                backend_ip
            );
            let _ = Command::new("cmd").args(["/C", &allow_hb]).output();
        }

        // Block all
        let block_in = "netsh advfirewall firewall add rule name=\"SentinelAI-Quarantine-BlockAll-In\" dir=in action=block enable=yes";
        let block_out = "netsh advfirewall firewall add rule name=\"SentinelAI-Quarantine-BlockAll-Out\" dir=out action=block enable=yes";
        let _ = Command::new("cmd").args(["/C", block_in]).output();
        let _ = Command::new("cmd").args(["/C", block_out]).output();

        CommandResult {
            command_id: command_id.to_string(),
            status: "completed".into(),
            output: "FULL quarantine — only heartbeat allowed".into(),
            data: Some(json!({ "quarantine_level": "full", "backend_ip": backend_ip })),
            exit_code: Some(0),
        }
    } else {
        let mut cmds = Vec::new();
        if !backend_ip.is_empty() {
            cmds.push(format!("iptables -I OUTPUT -d {} -p tcp --dport 8000 -j ACCEPT -m comment --comment \"SentinelAI-Quarantine\"", backend_ip));
        }
        cmds.push("iptables -A INPUT -j DROP -m comment --comment \"SentinelAI-Quarantine\"".into());
        cmds.push("iptables -A OUTPUT -j DROP -m comment --comment \"SentinelAI-Quarantine\"".into());

        for cmd in &cmds {
            let _ = Command::new("sh").args(["-c", cmd]).output();
        }

        CommandResult {
            command_id: command_id.to_string(),
            status: "completed".into(),
            output: "FULL quarantine applied".into(),
            data: Some(json!({ "quarantine_level": "full" })),
            exit_code: Some(0),
        }
    }
}

// =====================================================================
// Quick Actions: Block IP / Block Port
// =====================================================================

pub fn block_ip(command_id: &str, params: &serde_json::Value) -> CommandResult {
    let ip = params.get("ip").and_then(|v| v.as_str()).unwrap_or("");
    let direction = params.get("direction").and_then(|v| v.as_str()).unwrap_or("inbound");

    if ip.is_empty() {
        return error_result(command_id, "IP address is required");
    }

    info!(ip = %ip, direction = %direction, "Blocking IP address");

    let rule_params = json!({
        "name": format!("Block-{}", ip.replace('.', "-").replace(':', "-")),
        "direction": direction,
        "action": "block",
        "protocol": "any",
        "port": "",
        "remote_address": ip,
    });

    add_rule(command_id, &rule_params)
}

pub fn block_port(command_id: &str, params: &serde_json::Value) -> CommandResult {
    let port = params.get("port").and_then(|v| v.as_str()).unwrap_or("");
    let protocol = params.get("protocol").and_then(|v| v.as_str()).unwrap_or("tcp");
    let direction = params.get("direction").and_then(|v| v.as_str()).unwrap_or("inbound");

    if port.is_empty() {
        return error_result(command_id, "Port number is required");
    }

    info!(port = %port, protocol = %protocol, direction = %direction, "Blocking port");

    let rule_params = json!({
        "name": format!("Block-Port-{}-{}", protocol, port),
        "direction": direction,
        "action": "block",
        "protocol": protocol,
        "port": port,
        "remote_address": "",
    });

    add_rule(command_id, &rule_params)
}

// =====================================================================
// Helpers
// =====================================================================

fn validate_port(port: &str) -> Result<(), String> {
    // Accept single port or comma-separated or range
    for part in port.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let range: Vec<&str> = part.splitn(2, '-').collect();
            if range.len() != 2 {
                return Err(format!("Invalid range: {}", part));
            }
            range[0].parse::<u16>().map_err(|_| format!("Invalid port: {}", range[0]))?;
            range[1].parse::<u16>().map_err(|_| format!("Invalid port: {}", range[1]))?;
        } else {
            part.parse::<u16>().map_err(|_| format!("Invalid port: {}", part))?;
        }
    }
    Ok(())
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}

fn error_result(command_id: &str, msg: &str) -> CommandResult {
    CommandResult {
        command_id: command_id.to_string(),
        status: "error".into(),
        output: msg.to_string(),
        data: None,
        exit_code: None,
    }
}
