use std::path::PathBuf;

use clap::Parser;
use lagod::config::DaemonConfig;

// --- CLI definition

#[derive(Parser)]
#[command(
    name = "lagod",
    about = "Lago daemon — event-sourced agent runtime",
    version
)]
struct Args {
    /// Path to the configuration file (default: lago.toml)
    #[arg(long, default_value = "lago.toml")]
    config: PathBuf,

    /// gRPC server port (overrides config file)
    #[arg(long)]
    grpc_port: Option<u16>,

    /// HTTP server port (overrides config file)
    #[arg(long)]
    http_port: Option<u16>,

    /// Data directory (overrides config file)
    #[arg(long)]
    data_dir: Option<PathBuf>,
}

// --- Entry point

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    if let Err(e) = run(args).await {
        tracing::error!("fatal: {e}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    // --- Load configuration
    let mut config = DaemonConfig::load(&args.config)?;
    config.merge_cli(args.grpc_port, args.http_port, args.data_dir);

    // --- Run the daemon
    lagod::run(config).await
}
