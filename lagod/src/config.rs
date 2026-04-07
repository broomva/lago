use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Top-level daemon configuration, typically loaded from `lago.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Directory for persistent data (journal, blobs, snapshots).
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    /// Path to the policy configuration file.
    #[serde(default = "default_policy_path")]
    pub policy_path: PathBuf,

    /// Port for the gRPC ingest server.
    #[serde(default = "default_grpc_port")]
    pub grpc_port: u16,

    /// Port for the HTTP/REST API server.
    #[serde(default = "default_http_port")]
    pub http_port: u16,

    /// How often (in milliseconds) the WAL flushes buffered events to disk.
    #[serde(default = "default_wal_flush_interval_ms")]
    pub wal_flush_interval_ms: u64,

    /// Number of buffered events that triggers an immediate WAL flush.
    #[serde(default = "default_wal_flush_threshold")]
    pub wal_flush_threshold: usize,

    /// Number of events between automatic snapshots.
    #[serde(default = "default_snapshot_interval")]
    pub snapshot_interval: u64,

    /// Auth configuration for JWT-protected routes.
    #[serde(default)]
    pub auth: AuthConfig,
}

/// Auth configuration — when `jwt_secret` is set, `/v1/memory/*` routes
/// require a valid JWT bearer token.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Shared JWT secret (same as broomva.tech `AUTH_SECRET`).
    /// When `None`, auth middleware is disabled (backward-compatible).
    pub jwt_secret: Option<String>,
}

impl DaemonConfig {
    /// Load configuration from a TOML file.
    ///
    /// If the file does not exist, returns a default config.
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        if !path.exists() {
            tracing::info!(path = %path.display(), "config file not found, using defaults");
            return Ok(Self::default());
        }

        let contents = std::fs::read_to_string(path)?;

        // The TOML file may have a [daemon] section — try to parse the top
        // level first, then fall back to extracting the [daemon] table.
        let config: DaemonConfig = match toml::from_str(&contents) {
            Ok(cfg) => cfg,
            Err(_) => {
                // Try extracting from a [daemon] table
                let table: toml::Value = toml::from_str(&contents)?;
                if let Some(daemon) = table.get("daemon") {
                    toml::from_str(&daemon.to_string())?
                } else {
                    toml::from_str(&contents)?
                }
            }
        };

        tracing::info!(path = %path.display(), "config loaded");
        Ok(config)
    }

    /// Merge CLI overrides into the config. Non-default CLI values take
    /// precedence over values from the config file.
    pub fn merge_cli(
        &mut self,
        grpc_port: Option<u16>,
        http_port: Option<u16>,
        data_dir: Option<PathBuf>,
    ) {
        if let Some(port) = grpc_port {
            self.grpc_port = port;
        }
        if let Some(port) = http_port {
            self.http_port = port;
        }
        if let Some(dir) = data_dir {
            self.data_dir = dir;
        }
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            policy_path: default_policy_path(),
            grpc_port: default_grpc_port(),
            http_port: default_http_port(),
            wal_flush_interval_ms: default_wal_flush_interval_ms(),
            wal_flush_threshold: default_wal_flush_threshold(),
            snapshot_interval: default_snapshot_interval(),
            auth: AuthConfig::default(),
        }
    }
}

// --- Default value functions (used by serde and Default impl)

fn default_data_dir() -> PathBuf {
    if let Some(root) = life_paths::find_project_root() {
        root.join(".life").join("lago")
    } else {
        PathBuf::from(".lago")
    }
}

fn default_policy_path() -> PathBuf {
    PathBuf::from("policy.toml")
}

fn default_grpc_port() -> u16 {
    50051
}

fn default_http_port() -> u16 {
    8080
}

fn default_wal_flush_interval_ms() -> u64 {
    100
}

fn default_wal_flush_threshold() -> usize {
    1000
}

fn default_snapshot_interval() -> u64 {
    10_000
}
