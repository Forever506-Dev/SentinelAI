//! Agent Configuration
//!
//! Loads configuration from TOML file or environment variables.

use serde::Deserialize;
use std::path::PathBuf;

/// Agent configuration
#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    /// Backend API URL
    #[serde(default = "default_backend_url")]
    pub backend_url: String,

    /// Agent authentication token (received during registration)
    #[serde(default)]
    pub auth_token: Option<String>,

    /// Heartbeat interval in seconds
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,

    /// Number of events to batch before sending
    #[serde(default = "default_batch_size")]
    pub telemetry_batch_size: usize,

    /// Collectors configuration
    #[serde(default)]
    pub collectors: CollectorConfig,

    /// Paths to monitor for file system changes
    #[serde(default = "default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,

    /// File extensions to hash when created/modified
    #[serde(default = "default_hash_extensions")]
    pub hash_extensions: Vec<String>,

    /// HMAC-SHA256 key for verifying signed commands from backend
    /// Auto-provisioned during registration
    #[serde(default)]
    pub hmac_key: Option<String>,

    /// Whether to require HMAC signatures on destructive commands
    #[serde(default = "default_true")]
    pub require_command_signing: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CollectorConfig {
    /// Enable process monitoring
    #[serde(default = "default_true")]
    pub process_enabled: bool,

    /// Enable filesystem monitoring
    #[serde(default = "default_true")]
    pub filesystem_enabled: bool,

    /// Enable network monitoring
    #[serde(default = "default_true")]
    pub network_enabled: bool,

    /// Enable system info collection
    #[serde(default = "default_true")]
    pub system_info_enabled: bool,

    /// Process scan interval in seconds
    #[serde(default = "default_process_interval")]
    pub process_interval_secs: u64,

    /// Network scan interval in seconds
    #[serde(default = "default_network_interval")]
    pub network_interval_secs: u64,

    /// System info collection interval in seconds
    #[serde(default = "default_sysinfo_interval")]
    pub system_info_interval_secs: u64,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            process_enabled: true,
            filesystem_enabled: true,
            network_enabled: true,
            system_info_enabled: true,
            process_interval_secs: 5,
            network_interval_secs: 10,
            system_info_interval_secs: 30,
        }
    }
}

impl AgentConfig {
    /// Load configuration from file and environment variables.
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        // Try loading from config file.
        // Priority: exe directory > CWD > system paths > user config.
        // Exe directory first so the installed config always wins
        // (critical for Windows Services where CWD is System32,
        //  and to avoid picking up a template file from a random CWD).
        let mut config_paths: Vec<PathBuf> = Vec::new();

        // 1. Next to the running binary (highest priority)
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                config_paths.push(exe_dir.join("agent.toml"));
            }
        }

        // 2. Current working directory
        config_paths.push(PathBuf::from("agent.toml"));

        // 3. System-wide config locations
        config_paths.extend([
            PathBuf::from("/etc/sentinelai/agent.toml"),
            dirs::config_dir()
                .map(|p| p.join("sentinelai").join("agent.toml"))
                .unwrap_or_default(),
        ]);

        for path in &config_paths {
            if path.exists() {
                eprintln!("[config] Loading: {}", path.display());
                let content = std::fs::read_to_string(path)?;
                let config: AgentConfig = toml::from_str(&content)?;
                return Ok(config);
            }
        }

        // Fall back to defaults
        Ok(Self::default())
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            backend_url: default_backend_url(),
            auth_token: None,
            heartbeat_interval_secs: default_heartbeat_interval(),
            telemetry_batch_size: default_batch_size(),
            collectors: CollectorConfig::default(),
            watch_paths: default_watch_paths(),
            hash_extensions: default_hash_extensions(),
            hmac_key: None,
            require_command_signing: true,
        }
    }
}

// --- Default value functions ---

fn default_backend_url() -> String {
    std::env::var("SENTINEL_BACKEND_URL")
        .unwrap_or_else(|_| "http://localhost:8000/api/v1".to_string())
}

fn default_heartbeat_interval() -> u64 { 30 }
fn default_batch_size() -> usize { 100 }
fn default_true() -> bool { true }
fn default_process_interval() -> u64 { 5 }
fn default_network_interval() -> u64 { 10 }
fn default_sysinfo_interval() -> u64 { 30 }

fn default_watch_paths() -> Vec<PathBuf> {
    if cfg!(windows) {
        vec![
            PathBuf::from("C:\\Users"),
            PathBuf::from("C:\\Windows\\System32"),
            PathBuf::from("C:\\Windows\\Temp"),
        ]
    } else if cfg!(target_os = "macos") {
        vec![
            PathBuf::from("/Users"),
            PathBuf::from("/tmp"),
            PathBuf::from("/Applications"),
        ]
    } else {
        vec![
            PathBuf::from("/home"),
            PathBuf::from("/tmp"),
            PathBuf::from("/etc"),
            PathBuf::from("/var/log"),
        ]
    }
}

fn default_hash_extensions() -> Vec<String> {
    vec![
        "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js",
        "sh", "py", "rb", "elf", "so", "dylib", "app",
    ].into_iter().map(String::from).collect()
}
