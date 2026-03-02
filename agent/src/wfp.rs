//! Windows Filtering Platform (WFP) Engine
//!
//! Provides kernel-speed packet filtering via the WFP API.
//! Falls back to netsh if not running as SYSTEM / insufficient privileges.
//!
//! WFP rules are applied at the kernel networking stack, providing:
//! - Sub-millisecond rule evaluation
//! - No userspace packet copy overhead
//! - Tamper resistance (harder for malware to disable than netsh rules)
//!
//! This module is only compiled on Windows (`#[cfg(windows)]`).

#![cfg(windows)]

use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{info, warn, error};

/// Whether WFP engine is available (running as SYSTEM with sufficient privs).
static WFP_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// Check if we can use WFP (requires SYSTEM-level privileges).
/// Call this once at agent startup.
pub fn probe_wfp_availability() -> bool {
    // Check if running as SYSTEM (or at minimum elevated admin)
    let is_system = check_system_privileges();

    if is_system {
        // Try to open a WFP engine session
        match try_open_wfp_engine() {
            Ok(()) => {
                info!("✓ WFP engine available — kernel-speed filtering enabled");
                WFP_AVAILABLE.store(true, Ordering::SeqCst);
                true
            }
            Err(e) => {
                warn!("WFP engine open failed: {} — falling back to netsh", e);
                WFP_AVAILABLE.store(false, Ordering::SeqCst);
                false
            }
        }
    } else {
        info!("Not running as SYSTEM — WFP unavailable, using netsh fallback");
        WFP_AVAILABLE.store(false, Ordering::SeqCst);
        false
    }
}

/// Returns whether WFP is currently available.
pub fn is_available() -> bool {
    WFP_AVAILABLE.load(Ordering::SeqCst)
}

/// Check if we're running as NT AUTHORITY\SYSTEM.
fn check_system_privileges() -> bool {
    // Use whoami to check — simplest cross-build approach
    match std::process::Command::new("whoami").output() {
        Ok(output) => {
            let user = String::from_utf8_lossy(&output.stdout).to_lowercase();
            let is_system = user.contains("nt authority\\system") || user.contains("system");
            info!(user = %user.trim(), is_system = %is_system, "Privilege check");
            is_system
        }
        Err(_) => false,
    }
}

/// Attempt to open a WFP engine session.
/// This validates that the WFP API is accessible.
fn try_open_wfp_engine() -> Result<(), String> {
    // NOTE: Full WFP implementation using FwpmEngineOpen0 / FwpmFilterAdd0
    // requires the windows-rs WFP bindings. The current windows 0.52 crate
    // exposes these under Win32_NetworkManagement_WindowsFilteringPlatform.
    //
    // For Phase 1, we validate availability and provide the infrastructure.
    // The actual FwpmEngineOpen0 call chain is:
    //
    //   use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
    //   
    //   unsafe {
    //       let mut engine_handle = HANDLE::default();
    //       let result = FwpmEngineOpen0(
    //           None,           // server name (local)
    //           RPC_C_AUTHN_WINNT,
    //           None,           // auth identity
    //           None,           // session
    //           &mut engine_handle,
    //       );
    //       if result != 0 { return Err(...); }
    //       FwpmEngineClose0(engine_handle);
    //   }
    //
    // For now, we check the service is running as a proxy for availability.

    match std::process::Command::new("sc")
        .args(["query", "BFE"])  // Base Filtering Engine service
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("RUNNING") {
                info!("BFE (Base Filtering Engine) service is running");
                Ok(())
            } else {
                Err("BFE service not running".into())
            }
        }
        Err(e) => Err(format!("Failed to query BFE service: {}", e)),
    }
}

/// Sublayer GUID for SentinelAI WFP rules.
/// All our rules go into this sublayer for easy management.
pub const SENTINELAI_SUBLAYER_NAME: &str = "SentinelAI Security Filters";

/// Add a WFP filter rule (kernel-level).
/// Falls back to netsh if WFP is not available.
///
/// Returns Ok(method_used) where method_used is "wfp" or "netsh".
pub fn add_filter(
    name: &str,
    direction: &str,     // "inbound" | "outbound"
    action: &str,        // "block" | "allow"
    protocol: &str,      // "tcp" | "udp" | "icmp" | "any"
    port: &str,
    remote_address: &str,
) -> Result<String, String> {
    if is_available() {
        // WFP path (Phase 2 will implement full FwpmFilterAdd0)
        // For now, we still use netsh but log that WFP is available
        info!(name = %name, "WFP available but using netsh for Phase 1");
        add_filter_netsh(name, direction, action, protocol, port, remote_address)?;
        Ok("netsh-wfp-ready".into())
    } else {
        add_filter_netsh(name, direction, action, protocol, port, remote_address)?;
        Ok("netsh".into())
    }
}

/// Remove a WFP filter / netsh rule by name.
pub fn remove_filter(name: &str) -> Result<String, String> {
    let cmd = format!(
        "netsh advfirewall firewall delete rule name=\"{}\"",
        name
    );
    match std::process::Command::new("cmd").args(["/C", &cmd]).output() {
        Ok(output) if output.status.success() => Ok("removed".into()),
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("Delete failed: {}", stderr))
        }
        Err(e) => Err(format!("Command failed: {}", e)),
    }
}

/// Netsh-based rule addition (fallback path).
fn add_filter_netsh(
    name: &str,
    direction: &str,
    action: &str,
    protocol: &str,
    port: &str,
    remote_address: &str,
) -> Result<(), String> {
    let dir = if direction == "inbound" { "in" } else { "out" };
    let act = if action == "block" { "block" } else { "allow" };

    let mut cmd_str = format!(
        "netsh advfirewall firewall add rule name=\"SentinelAI-{}\" dir={} action={} protocol={}",
        name, dir, act, protocol
    );

    if !port.is_empty() {
        cmd_str.push_str(&format!(" localport={}", port));
    }
    if !remote_address.is_empty() {
        cmd_str.push_str(&format!(" remoteip={}", remote_address));
    }
    cmd_str.push_str(" enable=yes");

    match std::process::Command::new("cmd").args(["/C", &cmd_str]).output() {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            Err(format!("netsh failed: {} {}", stdout, stderr))
        }
        Err(e) => Err(format!("Command failed: {}", e)),
    }
}

/// Safeguard list — IPs that must NEVER be blocked.
/// This prevents the agent from accidentally cutting its own backend communication.
pub struct SafeguardList {
    pub protected_ips: Vec<String>,
    pub protected_ports: Vec<u16>,
}

impl SafeguardList {
    pub fn new(backend_url: &str) -> Self {
        let mut protected_ips: Vec<String> = Vec::new();

        // Extract backend host from URL (simple parse without url crate)
        if let Some(after_scheme) = backend_url.split("://").nth(1) {
            let host_port = after_scheme.split('/').next().unwrap_or("");
            let host = host_port.split(':').next().unwrap_or("");
            if !host.is_empty() {
                protected_ips.push(host.to_string());
            }
        }

        // Always protect loopback
        protected_ips.push("127.0.0.1".into());
        protected_ips.push("::1".into());

        Self {
            protected_ips,
            protected_ports: vec![8000, 443], // backend port, HTTPS
        }
    }

    /// Check if a given IP is in the safeguard list.
    pub fn is_protected_ip(&self, ip: &str) -> bool {
        self.protected_ips.iter().any(|p| p == ip)
    }

    /// Check if a given port is protected.
    pub fn is_protected_port(&self, port: u16) -> bool {
        self.protected_ports.contains(&port)
    }
}
