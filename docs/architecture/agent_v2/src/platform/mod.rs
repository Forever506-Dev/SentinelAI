//! SentinelAI Agent v2 — Platform Abstraction Module
//!
//! Provides OS detection, feature gating, and platform-specific
//! utility functions.

/// Detected platform capabilities.
#[derive(Debug, Clone)]
pub struct PlatformCapabilities {
    pub os: OsType,
    pub kernel_version: String,
    /// ETW available (Windows only).
    pub etw_available: bool,
    /// eBPF available (Linux only, requires kernel ≥ 4.18).
    pub ebpf_available: bool,
    /// BPF ring buffer available (Linux only, requires kernel ≥ 5.8).
    pub bpf_ringbuf_available: bool,
    /// BPF LSM hooks available (Linux only, requires kernel ≥ 5.7).
    pub bpf_lsm_available: bool,
    /// Protected Process Light available (Windows only, requires ELAM cert).
    pub ppl_available: bool,
    /// Running as admin/root.
    pub is_elevated: bool,
    /// TPM 2.0 available (for future certificate binding).
    pub tpm_available: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsType {
    Windows,
    Linux,
    MacOs,
    Android,
    Unknown,
}

impl PlatformCapabilities {
    /// Detect platform capabilities at runtime.
    pub fn detect() -> Self {
        #[cfg(target_os = "windows")]
        {
            Self::detect_windows()
        }
        #[cfg(target_os = "linux")]
        {
            Self::detect_linux()
        }
        #[cfg(target_os = "macos")]
        {
            Self {
                os: OsType::MacOs,
                kernel_version: String::new(),
                etw_available: false,
                ebpf_available: false,
                bpf_ringbuf_available: false,
                bpf_lsm_available: false,
                ppl_available: false,
                is_elevated: false,
                tpm_available: false,
            }
        }
        #[cfg(target_os = "android")]
        {
            Self {
                os: OsType::Android,
                kernel_version: String::new(),
                etw_available: false,
                ebpf_available: false, // Will be detected from kernel version
                bpf_ringbuf_available: false,
                bpf_lsm_available: false,
                ppl_available: false,
                is_elevated: false,
                tpm_available: false,
            }
        }
        #[cfg(not(any(
            target_os = "windows",
            target_os = "linux",
            target_os = "macos",
            target_os = "android"
        )))]
        {
            Self {
                os: OsType::Unknown,
                kernel_version: String::new(),
                etw_available: false,
                ebpf_available: false,
                bpf_ringbuf_available: false,
                bpf_lsm_available: false,
                ppl_available: false,
                is_elevated: false,
                tpm_available: false,
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn detect_windows() -> Self {
        // In production:
        // - Check Windows version for ETW support (Vista+)
        // - Check if running as SYSTEM or admin
        // - Check for ELAM certificate in cert store
        // - Check for TPM via TBS API
        Self {
            os: OsType::Windows,
            kernel_version: String::new(), // TODO: RtlGetVersion
            etw_available: true,           // Always true on Vista+
            ebpf_available: false,
            bpf_ringbuf_available: false,
            bpf_lsm_available: false,
            ppl_available: false, // TODO: Check ELAM cert
            is_elevated: false,   // TODO: CheckTokenMembership(BUILTIN_ADMINISTRATORS)
            tpm_available: false, // TODO: Tbsi_GetDeviceInfo
        }
    }

    #[cfg(target_os = "linux")]
    fn detect_linux() -> Self {
        // In production:
        // - Parse /proc/version for kernel version
        // - Check CAP_BPF or CAP_SYS_ADMIN capability
        // - Check if /sys/fs/bpf is mounted
        // - Probe BPF_MAP_TYPE_RINGBUF support
        // - Check if BPF_PROG_TYPE_LSM is available
        Self {
            os: OsType::Linux,
            kernel_version: String::new(), // TODO: uname()
            etw_available: false,
            ebpf_available: false,         // TODO: probe bpf() syscall
            bpf_ringbuf_available: false,  // TODO: probe BPF_MAP_TYPE_RINGBUF
            bpf_lsm_available: false,      // TODO: probe BPF_PROG_TYPE_LSM
            ppl_available: false,
            is_elevated: false,            // TODO: getuid() == 0
            tpm_available: false,          // TODO: check /dev/tpm0
        }
    }

    /// Select the best available telemetry providers for this platform.
    pub fn recommended_providers(&self) -> Vec<RecommendedProvider> {
        let mut providers = Vec::new();

        match self.os {
            OsType::Windows => {
                if self.etw_available && self.is_elevated {
                    providers.push(RecommendedProvider::EtwKernelProcess);
                    providers.push(RecommendedProvider::EtwKernelFile);
                    providers.push(RecommendedProvider::EtwKernelNetwork);
                    providers.push(RecommendedProvider::EtwKernelRegistry);
                    providers.push(RecommendedProvider::EtwDnsClient);
                } else {
                    providers.push(RecommendedProvider::FallbackPolling);
                }
            }
            OsType::Linux => {
                if self.ebpf_available && self.is_elevated {
                    providers.push(RecommendedProvider::EbpfProcessProbe);
                    providers.push(RecommendedProvider::EbpfFileProbe);
                    providers.push(RecommendedProvider::EbpfNetworkProbe);
                } else {
                    providers.push(RecommendedProvider::FallbackPolling);
                }
            }
            OsType::Android => {
                if self.ebpf_available {
                    providers.push(RecommendedProvider::EbpfProcessProbe);
                    providers.push(RecommendedProvider::EbpfNetworkProbe);
                } else {
                    providers.push(RecommendedProvider::AndroidAudit);
                    providers.push(RecommendedProvider::AndroidProc);
                }
            }
            _ => {
                providers.push(RecommendedProvider::FallbackPolling);
            }
        }

        providers
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecommendedProvider {
    EtwKernelProcess,
    EtwKernelFile,
    EtwKernelNetwork,
    EtwKernelRegistry,
    EtwDnsClient,
    EbpfProcessProbe,
    EbpfFileProbe,
    EbpfNetworkProbe,
    AndroidAudit,
    AndroidProc,
    FallbackPolling,
}

// ─── Platform-specific submodules ───────────────────────────────

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "android")]
pub mod android;
