use lagod::config::DaemonConfig;
use std::path::PathBuf;
use tracing::info;

/// Options for the `lago serve` command.
#[derive(Debug, Clone)]
pub struct ServeOptions {
    pub grpc_port: u16,
    pub http_port: u16,
    pub data_dir: PathBuf,
}

/// Execute the `lago serve` command.
///
/// Runs the Lago daemon directly.
pub async fn run(opts: ServeOptions) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        grpc_port = opts.grpc_port,
        http_port = opts.http_port,
        data_dir = %opts.data_dir.display(),
        "starting lago daemon"
    );

    // Try to load config from default location, or use defaults
    let mut config = DaemonConfig::load(std::path::Path::new("lago.toml"))?;

    // Override with CLI options
    config.merge_cli(
        Some(opts.grpc_port),
        Some(opts.http_port),
        Some(opts.data_dir),
    );

    lagod::run(config).await
}
