mod client;
mod commands;
mod db;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

// --- CLI definition

#[derive(Parser)]
#[command(name = "lago", about = "Lago — event-sourced agent runtime", version)]
struct Cli {
    /// Path to the data directory (default: .lago)
    #[arg(long, global = true, default_value = ".lago")]
    data_dir: PathBuf,

    /// API port for client connections (default: 8080)
    #[arg(long, global = true, default_value_t = 8080)]
    api_port: u16,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new Lago project
    Init {
        /// Directory to initialize (default: current directory)
        path: Option<PathBuf>,
    },

    /// Start the Lago daemon
    Serve {
        /// gRPC server port
        #[arg(long, default_value_t = 50051)]
        grpc_port: u16,

        /// HTTP server port
        #[arg(long, default_value_t = 8080)]
        http_port: u16,

        /// Data directory
        #[arg(long, default_value = ".lago")]
        data_dir: PathBuf,
    },

    /// Manage sessions
    Session {
        #[command(subcommand)]
        action: SessionAction,
    },

    /// Manage branches
    Branch {
        #[command(subcommand)]
        action: BranchAction,
    },

    /// View the event log
    Log {
        /// Session ID (required)
        #[arg(long)]
        session: String,

        /// Branch name
        #[arg(long, default_value = "main")]
        branch: String,

        /// Maximum number of events to display
        #[arg(long, default_value_t = 50)]
        limit: usize,

        /// Show events after this sequence number
        #[arg(long)]
        after: Option<u64>,
    },

    /// Print file contents from the virtual filesystem
    Cat {
        /// File path within the manifest
        path: String,

        /// Session ID (required)
        #[arg(long)]
        session: String,

        /// Branch name
        #[arg(long, default_value = "main")]
        branch: String,
    },
}

#[derive(Subcommand)]
enum SessionAction {
    /// Create a new session
    Create {
        /// Session name
        #[arg(long)]
        name: String,
    },
    /// List all sessions
    List,
    /// Show session details
    Show {
        /// Session ID
        id: String,
    },
}

#[derive(Subcommand)]
enum BranchAction {
    /// Create a new branch
    Create {
        /// Session ID
        #[arg(long)]
        session: String,

        /// Branch name
        #[arg(long)]
        name: String,

        /// Fork at this sequence number (default: head of main)
        #[arg(long)]
        fork_at: Option<u64>,
    },
    /// List branches for a session
    List {
        /// Session ID
        #[arg(long)]
        session: String,
    },
}

// --- Entry point

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();

    let result = run(cli).await;

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = &cli.data_dir;
    let api_port = cli.api_port;

    match cli.command {
        Commands::Init { path } => {
            commands::init::run(path)?;
        }

        Commands::Serve {
            grpc_port,
            http_port,
            data_dir: serve_data_dir,
        } => {
            commands::serve::run(commands::serve::ServeOptions {
                grpc_port,
                http_port,
                data_dir: serve_data_dir,
            })
            .await?;
        }

        Commands::Session { action } => match action {
            SessionAction::Create { name } => {
                commands::session::create(data_dir, api_port, &name).await?;
            }
            SessionAction::List => {
                commands::session::list(data_dir, api_port).await?;
            }
            SessionAction::Show { id } => {
                commands::session::show(data_dir, api_port, &id).await?;
            }
        },

        Commands::Branch { action } => match action {
            BranchAction::Create {
                session,
                name,
                fork_at,
            } => {
                commands::branch::create(data_dir, &session, &name, fork_at).await?;
            }
            BranchAction::List { session } => {
                commands::branch::list(data_dir, &session).await?;
            }
        },

        Commands::Log {
            session,
            branch,
            limit,
            after,
        } => {
            commands::log::run(
                data_dir,
                commands::log::LogOptions {
                    session_id: session,
                    branch,
                    limit,
                    after_seq: after,
                },
            )
            .await?;
        }

        Commands::Cat {
            path,
            session,
            branch,
        } => {
            commands::cat::run(
                data_dir,
                commands::cat::CatOptions {
                    path,
                    session_id: session,
                    branch,
                },
            )
            .await?;
        }
    }

    Ok(())
}
