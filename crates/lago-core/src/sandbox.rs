use crate::error::LagoResult;
use serde::{Deserialize, Serialize};
use std::pin::Pin;

/// Boxed future type alias for dyn-compatible async trait methods.
type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Sandbox isolation tiers, ordered from least to most isolated.
///
/// Derives `PartialOrd`/`Ord` so comparisons like `tier >= SandboxTier::Process`
/// work naturally for policy enforcement.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum SandboxTier {
    /// No isolation — direct host access.
    #[default]
    None,
    /// Basic restrictions (e.g. seccomp, pledge).
    Basic,
    /// Process-level isolation (e.g. bubblewrap, firejail).
    Process,
    /// Full container isolation (e.g. Apple Containers, Docker).
    Container,
}

/// Configuration for a sandbox instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub tier: SandboxTier,
    #[serde(default)]
    pub allowed_paths: Vec<String>,
    #[serde(default)]
    pub allowed_commands: Vec<String>,
    #[serde(default = "default_true")]
    pub network_access: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_memory_mb: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cpu_seconds: Option<u64>,
}

fn default_true() -> bool {
    true
}

/// Request to execute a command inside a sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxExecRequest {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// Result of a sandboxed command execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

/// The primary trait for sandbox environments.
///
/// Uses boxed futures for dyn-compatibility (`Arc<dyn Sandbox>`),
/// matching the `Journal` trait pattern.
///
/// lago-core defines this trait; runtime implementations (e.g. Arcan)
/// provide platform-specific backends.
pub trait Sandbox: Send + Sync {
    /// The isolation tier of this sandbox.
    fn tier(&self) -> SandboxTier;

    /// The configuration this sandbox was created with.
    fn config(&self) -> &SandboxConfig;

    /// Execute a command inside the sandbox.
    fn execute(&self, request: SandboxExecRequest) -> BoxFuture<'_, LagoResult<SandboxExecResult>>;

    /// Read a file from inside the sandbox.
    fn read_file(&self, path: &str) -> BoxFuture<'_, LagoResult<Vec<u8>>>;

    /// Write a file inside the sandbox.
    fn write_file(&self, path: &str, data: &[u8]) -> BoxFuture<'_, LagoResult<()>>;

    /// Destroy the sandbox and clean up resources.
    fn destroy(&self) -> BoxFuture<'_, LagoResult<()>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_tier_ordering() {
        assert!(SandboxTier::None < SandboxTier::Basic);
        assert!(SandboxTier::Basic < SandboxTier::Process);
        assert!(SandboxTier::Process < SandboxTier::Container);
    }

    #[test]
    fn sandbox_tier_serde_roundtrip() {
        for tier in [
            SandboxTier::None,
            SandboxTier::Basic,
            SandboxTier::Process,
            SandboxTier::Container,
        ] {
            let json = serde_json::to_string(&tier).unwrap();
            let back: SandboxTier = serde_json::from_str(&json).unwrap();
            assert_eq!(back, tier);
        }
        assert_eq!(
            serde_json::to_string(&SandboxTier::None).unwrap(),
            "\"none\""
        );
        assert_eq!(
            serde_json::to_string(&SandboxTier::Container).unwrap(),
            "\"container\""
        );
    }

    #[test]
    fn sandbox_tier_default() {
        assert_eq!(SandboxTier::default(), SandboxTier::None);
    }

    #[test]
    fn sandbox_config_serde_roundtrip() {
        let config = SandboxConfig {
            tier: SandboxTier::Process,
            allowed_paths: vec!["/tmp".to_string(), "/workspace".to_string()],
            allowed_commands: vec!["cargo".to_string(), "rustc".to_string()],
            network_access: false,
            max_memory_mb: Some(512),
            max_cpu_seconds: Some(60),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: SandboxConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tier, SandboxTier::Process);
        assert_eq!(back.allowed_paths.len(), 2);
        assert!(!back.network_access);
        assert_eq!(back.max_memory_mb, Some(512));
    }

    #[test]
    fn sandbox_config_defaults() {
        let json = r#"{"tier": "basic"}"#;
        let config: SandboxConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.tier, SandboxTier::Basic);
        assert!(config.allowed_paths.is_empty());
        assert!(config.allowed_commands.is_empty());
        assert!(config.network_access); // defaults to true
        assert!(config.max_memory_mb.is_none());
    }

    #[test]
    fn sandbox_exec_request_serde_roundtrip() {
        let req = SandboxExecRequest {
            command: "cargo".to_string(),
            args: vec!["test".to_string()],
            env: vec![("RUST_LOG".to_string(), "debug".to_string())],
            working_dir: Some("/workspace".to_string()),
            stdin: None,
            timeout_ms: Some(30000),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: SandboxExecRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.command, "cargo");
        assert_eq!(back.args, vec!["test"]);
        assert_eq!(back.timeout_ms, Some(30000));
    }

    #[test]
    fn sandbox_exec_result_serde_roundtrip() {
        let result = SandboxExecResult {
            exit_code: 0,
            stdout: "ok".to_string(),
            stderr: String::new(),
            duration_ms: 1234,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: SandboxExecResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.exit_code, 0);
        assert_eq!(back.duration_ms, 1234);
    }

    #[test]
    fn sandbox_tier_ge_comparison() {
        // For policy enforcement: "sandbox tier must be at least Process"
        let required = SandboxTier::Process;
        assert!(SandboxTier::Process >= required);
        assert!(SandboxTier::Container >= required);
        assert!(SandboxTier::Basic < required);
        assert!(SandboxTier::None < required);
    }
}
