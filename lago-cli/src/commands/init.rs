use std::fs;
use std::path::PathBuf;

/// Default contents of `lago.toml`.
const DEFAULT_CONFIG: &str = r#"# Lago configuration
# See https://lago.dev/docs/config for all options.

[daemon]
grpc_port = 50051
http_port = 8080
data_dir = ".lago"

[wal]
flush_interval_ms = 100
flush_threshold = 1000

[snapshot]
interval = 10000
"#;

/// Default policy file, embedded at compile time from `default-policy.toml`.
const DEFAULT_POLICY: &str = include_str!("../../../../default-policy.toml");

/// Execute the `lago init` command.
///
/// Creates a `.lago` directory and a `lago.toml` configuration file at the
/// specified path (or the current directory if none is given).
pub fn run(path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let root = path.unwrap_or_else(|| PathBuf::from("."));
    let root = root.canonicalize().unwrap_or(root);

    let lago_dir = root.join(".lago");
    let config_path = root.join("lago.toml");

    // Create the .lago data directory
    if lago_dir.exists() {
        println!("Directory already exists: {}", lago_dir.display());
    } else {
        fs::create_dir_all(&lago_dir)?;
        println!("Created directory: {}", lago_dir.display());
    }

    // Create subdirectories for blobs and journal
    let blobs_dir = lago_dir.join("blobs");
    if !blobs_dir.exists() {
        fs::create_dir_all(&blobs_dir)?;
    }

    // Write default config
    if config_path.exists() {
        println!("Config already exists: {}", config_path.display());
    } else {
        fs::write(&config_path, DEFAULT_CONFIG)?;
        println!("Created config: {}", config_path.display());
    }

    // Write default policy
    let policy_path = root.join("policy.toml");
    if policy_path.exists() {
        println!("Policy already exists: {}", policy_path.display());
    } else {
        fs::write(&policy_path, DEFAULT_POLICY)?;
        println!("Created policy: {}", policy_path.display());
    }

    println!("\nLago initialized successfully.");
    Ok(())
}
