//! SentinelAI Agent v2 — Self-Protection Module
//!
//! Platform-specific anti-tamper mechanisms that increase the cost
//! of disabling or evading the agent.
//!
//! # Threat Model
//!
//! These mechanisms defend against:
//! - User-level attackers (script kiddies, commodity malware)
//! - Admin-level attackers (lateral movement, credential theft)
//!
//! They CANNOT defend against:
//! - Kernel-level attackers (rootkits, bootkits)
//! - Physical access attackers (disk encryption bypass)
//!
//! The goal is defense-in-depth: maximize the cost and noise
//! of disabling the agent, not achieve impossibility.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │                   SelfProtection                          │
//! │                                                            │
//! │  ┌────────────────────────────────────────────────────┐   │
//! │  │  Common Layer                                       │   │
//! │  │  • Heartbeat watchdog (detect own suspension)       │   │
//! │  │  • Canary events (detect telemetry suppression)     │   │
//! │  │  • Binary self-hash (detect replacement)            │   │
//! │  └────────────────────────────────────────────────────┘   │
//! │                                                            │
//! │  ┌──────────────────┐  ┌──────────────────────────────┐   │
//! │  │  Windows          │  │  Linux                        │   │
//! │  │  • PPL / ELAM     │  │  • BPF pin monitoring         │   │
//! │  │  • ETW guardian   │  │  • cgroup OOM protection      │   │
//! │  │  • Service guard  │  │  • prctl anti-ptrace          │   │
//! │  │  • DACL hardening │  │  • systemd watchdog           │   │
//! │  └──────────────────┘  └──────────────────────────────┘   │
//! └──────────────────────────────────────────────────────────┘
//! ```

use std::fmt;
use async_trait::async_trait;

use crate::collector::TamperType;

// ─── Types ──────────────────────────────────────────────────────

/// Result of an integrity verification check.
#[derive(Debug, Clone)]
pub struct IntegrityReport {
    /// Overall integrity status.
    pub status: IntegrityStatus,
    /// Per-check results.
    pub checks: Vec<IntegrityCheck>,
    /// Timestamp of the check.
    pub checked_at_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityStatus {
    /// All checks passed.
    Intact,
    /// Some checks failed but agent is operational.
    Degraded,
    /// Critical tamper detected.
    Compromised,
}

#[derive(Debug, Clone)]
pub struct IntegrityCheck {
    pub name: String,
    pub passed: bool,
    pub details: String,
}

/// How to respond to a detected tamper event.
#[derive(Debug, Clone)]
pub enum TamperResponse {
    /// Log the tamper event and continue operating.
    LogAndContinue,
    /// Attempt to recover (restart provider, re-pin BPF, etc.).
    AttemptRecovery { action: String },
    /// Escalate: send high-priority alert to backend.
    Escalate { alert_message: String },
    /// Recovery is impossible. Enter degraded mode.
    EnterDegradedMode { reason: String },
}

// ─── Errors ─────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ProtectionError {
    /// Failed to initialize protection mechanism.
    InitializationFailed(String),
    /// OS API error.
    PlatformError(String),
    /// Insufficient privileges (need SYSTEM/root).
    InsufficientPrivileges(String),
    /// Generic I/O error.
    Io(std::io::Error),
}

impl fmt::Display for ProtectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InitializationFailed(e) => write!(f, "protection init failed: {e}"),
            Self::PlatformError(e) => write!(f, "platform error: {e}"),
            Self::InsufficientPrivileges(e) => write!(f, "insufficient privileges: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for ProtectionError {}

// ─── Trait ──────────────────────────────────────────────────────

/// Platform-specific anti-tamper mechanisms.
///
/// # Initialization Order
///
/// Self-protection must be initialized **before** telemetry providers
/// to ensure that the protection mechanisms are active before any
/// events are generated. This means:
///
/// 1. `SelfProtection::initialize()` — Set up PPL, BPF-LSM, etc.
/// 2. `TelemetryProvider::start()` — Start ETW/eBPF providers
/// 3. `EventPipeline::run()` — Begin event processing
/// 4. `TransportClient::connect()` — Connect to backend
///
/// # Integrity Checks
///
/// `verify_integrity()` performs these checks:
///
/// ## Windows
/// - Binary hash matches expected (agent hasn't been replaced)
/// - Service configuration unchanged (no startup type tampering)
/// - ETW trace sessions are all running
/// - No suspicious DLLs loaded into agent process
/// - Process token integrity level is SYSTEM
///
/// ## Linux
/// - Binary hash matches expected
/// - /sys/fs/bpf/sentinel/ pins all present
/// - Agent process not being ptraced
/// - systemd service file unchanged
/// - cgroup limits intact
#[async_trait]
pub trait SelfProtection: Send + Sync + 'static {
    /// Initialize protection mechanisms.
    ///
    /// Must be called early in startup, before telemetry providers.
    ///
    /// ## Windows
    /// - Register as Protected Process Light (if ELAM cert available)
    /// - Set process mitigation policies (no unsigned DLL loading)
    /// - Harden process DACL (deny PROCESS_TERMINATE to Everyone)
    /// - Set service failure recovery (restart on failure)
    ///
    /// ## Linux
    /// - Set prctl(PR_SET_DUMPABLE, 0) to prevent ptrace
    /// - Configure OOM score adjustment (-900)
    /// - Create cgroup with memory reservation
    /// - Pin BPF programs to /sys/fs/bpf/sentinel/
    async fn initialize(&mut self) -> Result<(), ProtectionError>;

    /// Periodic integrity verification.
    ///
    /// Should be called every 30-60 seconds. Returns a report
    /// detailing which checks passed and which failed.
    async fn verify_integrity(&self) -> IntegrityReport;

    /// Check if telemetry providers are still attached and healthy.
    ///
    /// This is a targeted check for provider-specific tamper:
    /// - ETW sessions still running
    /// - eBPF programs still pinned and attached
    /// - Audit subsystem still accessible
    async fn verify_providers(
        &self,
    ) -> Vec<crate::collector::ProviderHealthStatus>;

    /// Called when tamper is detected.
    ///
    /// The response depends on the type and severity:
    /// - ETW session killed → restart session + alert
    /// - eBPF program detached → re-load + alert
    /// - Agent binary modified → alert + continue (can't self-replace)
    /// - Canary missing → alert (telemetry suppression detected)
    async fn on_tamper_detected(
        &self,
        tamper_type: TamperType,
    ) -> TamperResponse;
}

// ─── Submodules ─────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

pub mod common;
