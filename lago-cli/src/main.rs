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

    /// Compact events and quarantine unreferenced blobs (garbage collection)
    Compact {
        /// Session ID (required)
        #[arg(long)]
        session: String,

        /// Branch name
        #[arg(long, default_value = "main")]
        branch: String,

        /// Custom quarantine directory (default: {data_dir}/quarantine/{timestamp}/)
        #[arg(long)]
        quarantine_dir: Option<PathBuf>,

        /// Show what would be quarantined without actually moving files
        #[arg(long)]
        dry_run: bool,
    },

    /// Memory vault operations (auth-protected)
    Memory {
        #[command(subcommand)]
        action: MemoryAction,
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

#[derive(Subcommand)]
enum MemoryAction {
    /// Show vault status (file count, total size)
    Status,

    /// List all .md files in the vault
    Ls {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Search vault notes
    Search {
        /// Search query
        query: String,

        /// Maximum results to return
        #[arg(long, default_value_t = 10)]
        max_results: usize,

        /// Follow wikilinks from top results
        #[arg(long)]
        follow_links: bool,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Read a specific note by name or path
    Read {
        /// Note name or relative path
        name: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Store a local .md file in the vault
    Store {
        /// Path to the local .md file
        file: PathBuf,

        /// Remote path override (default: filename)
        #[arg(long)]
        r#as: Option<String>,
    },

    /// Bulk ingest all .md files from a directory
    Ingest {
        /// Directory to ingest from
        directory: PathBuf,

        /// Preview without writing
        #[arg(long)]
        dry_run: bool,

        /// Glob pattern for files to ingest
        #[arg(long, default_value = "**/*.md")]
        pattern: String,
    },

    /// Delete a note from the vault
    Delete {
        /// File path in the vault
        path: String,
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

/// Resolve auth token from: --token flag → BROOMVA_API_TOKEN env → ~/.broomva/config.json
fn resolve_token() -> Option<String> {
    // 1. BROOMVA_API_TOKEN env var
    if let Ok(t) = std::env::var("BROOMVA_API_TOKEN")
        && !t.is_empty()
    {
        return Some(t);
    }

    // 2. ~/.broomva/config.json
    if let Some(home) = dirs_path() {
        let config_path = home.join(".broomva").join("config.json");
        if let Ok(content) = std::fs::read_to_string(config_path)
            && let Ok(config) = serde_json::from_str::<serde_json::Value>(&content)
            && let Some(token) = config.get("token").and_then(|t| t.as_str())
            && !token.is_empty()
        {
            return Some(token.to_string());
        }
    }

    None
}

fn dirs_path() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
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

        Commands::Compact {
            session,
            branch,
            quarantine_dir,
            dry_run,
        } => {
            commands::compact::run(
                data_dir,
                commands::compact::CompactOptions {
                    session_id: session,
                    branch,
                    quarantine_dir,
                    dry_run,
                },
            )
            .await?;
        }

        Commands::Memory { action } => {
            let base_url = format!("http://127.0.0.1:{api_port}");
            let token = resolve_token();
            let http = reqwest::Client::new();

            match action {
                MemoryAction::Status => {
                    let res = memory_request(
                        &http,
                        &base_url,
                        &token,
                        "GET",
                        "/v1/memory/manifest",
                        None,
                    )
                    .await?;
                    let manifest: serde_json::Value = res.json().await?;
                    let entries = manifest["entries"].as_array().map(|a| a.len()).unwrap_or(0);
                    let total_bytes: u64 = manifest["entries"]
                        .as_array()
                        .map(|a| a.iter().filter_map(|e| e["size_bytes"].as_u64()).sum())
                        .unwrap_or(0);
                    println!("Vault status:");
                    println!("  Files: {entries}");
                    println!("  Total size: {} bytes", total_bytes);
                }

                MemoryAction::Ls { json } => {
                    let res = memory_request(
                        &http,
                        &base_url,
                        &token,
                        "GET",
                        "/v1/memory/manifest",
                        None,
                    )
                    .await?;
                    let manifest: serde_json::Value = res.json().await?;

                    if json {
                        println!("{}", serde_json::to_string_pretty(&manifest)?);
                    } else if let Some(entries) = manifest["entries"].as_array() {
                        for entry in entries {
                            let path = entry["path"].as_str().unwrap_or("?");
                            let size = entry["size_bytes"].as_u64().unwrap_or(0);
                            println!("{path}  ({size} bytes)");
                        }
                    }
                }

                MemoryAction::Search {
                    query,
                    max_results,
                    follow_links,
                    json,
                } => {
                    let body = serde_json::json!({
                        "query": query,
                        "max_results": max_results,
                        "follow_links": follow_links,
                    });
                    let res = memory_request(
                        &http,
                        &base_url,
                        &token,
                        "POST",
                        "/v1/memory/search",
                        Some(body),
                    )
                    .await?;
                    let data: serde_json::Value = res.json().await?;

                    if json {
                        println!("{}", serde_json::to_string_pretty(&data)?);
                    } else if let Some(results) = data["results"].as_array() {
                        if results.is_empty() {
                            println!("No results found.");
                        } else {
                            for (i, r) in results.iter().enumerate() {
                                let name = r["name"].as_str().unwrap_or("?");
                                let path = r["path"].as_str().unwrap_or("?");
                                let score = r["score"].as_f64().unwrap_or(0.0);
                                println!("{}. {} ({}) [score: {:.1}]", i + 1, name, path, score);
                                if let Some(excerpts) = r["excerpts"].as_array() {
                                    for excerpt in excerpts.iter().take(2) {
                                        if let Some(s) = excerpt.as_str() {
                                            println!("   > {s}");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                MemoryAction::Read { name, json } => {
                    let encoded = urlencoding::encode(&name);
                    let res = memory_request(
                        &http,
                        &base_url,
                        &token,
                        "GET",
                        &format!("/v1/memory/note/{encoded}"),
                        None,
                    )
                    .await?;
                    let data: serde_json::Value = res.json().await?;

                    if json {
                        println!("{}", serde_json::to_string_pretty(&data)?);
                    } else {
                        let note_name = data["name"].as_str().unwrap_or("?");
                        let body = data["body"].as_str().unwrap_or("");
                        println!("# {note_name}\n");
                        println!("{body}");
                    }
                }

                MemoryAction::Store { file, r#as } => {
                    let content = std::fs::read(&file)?;
                    let remote_path = r#as.unwrap_or_else(|| {
                        format!(
                            "/{}",
                            file.file_name().unwrap_or_default().to_string_lossy()
                        )
                    });
                    let encoded = urlencoding::encode(&remote_path);
                    let res = http
                        .put(format!("{base_url}/v1/memory/files/{encoded}"))
                        .headers(auth_headers(&token))
                        .body(content)
                        .send()
                        .await?;

                    if res.status().is_success() {
                        let data: serde_json::Value = res.json().await?;
                        println!(
                            "Stored: {} ({} bytes)",
                            data["path"].as_str().unwrap_or("?"),
                            data["size_bytes"].as_u64().unwrap_or(0)
                        );
                    } else {
                        let status = res.status();
                        let body = res.text().await?;
                        eprintln!("Error {status}: {body}");
                    }
                }

                MemoryAction::Ingest {
                    directory,
                    dry_run,
                    pattern: _,
                } => {
                    let files = collect_md_files(&directory);
                    println!("Found {} .md files in {}", files.len(), directory.display());

                    for file in &files {
                        let rel = file.strip_prefix(&directory).unwrap_or(file);
                        let remote_path = format!("/{}", rel.to_string_lossy());

                        if dry_run {
                            println!("  [dry-run] {remote_path}");
                        } else {
                            let content = std::fs::read(file)?;
                            let encoded = urlencoding::encode(&remote_path);
                            let res = http
                                .put(format!("{base_url}/v1/memory/files/{encoded}"))
                                .headers(auth_headers(&token))
                                .body(content)
                                .send()
                                .await?;

                            if res.status().is_success() {
                                println!("  + {remote_path}");
                            } else {
                                eprintln!("  ! {remote_path} ({})", res.status());
                            }
                        }
                    }

                    if !dry_run {
                        println!("Ingested {} files.", files.len());
                    }
                }

                MemoryAction::Delete { path } => {
                    let encoded = urlencoding::encode(&path);
                    let res = memory_request(
                        &http,
                        &base_url,
                        &token,
                        "DELETE",
                        &format!("/v1/memory/files/{encoded}"),
                        None,
                    )
                    .await?;

                    if res.status().is_success() {
                        println!("Deleted: {path}");
                    } else {
                        let status = res.status();
                        let body = res.text().await?;
                        eprintln!("Error {status}: {body}");
                    }
                }
            }
        }
    }

    Ok(())
}

// --- Memory CLI helpers

fn auth_headers(token: &Option<String>) -> reqwest::header::HeaderMap {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(t) = token
        && let Ok(val) = reqwest::header::HeaderValue::from_str(&format!("Bearer {t}"))
    {
        headers.insert(reqwest::header::AUTHORIZATION, val);
    }
    headers
}

async fn memory_request(
    http: &reqwest::Client,
    base_url: &str,
    token: &Option<String>,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<reqwest::Response, Box<dyn std::error::Error>> {
    let url = format!("{base_url}{path}");
    let mut req = match method {
        "POST" => http.post(&url),
        "PUT" => http.put(&url),
        "DELETE" => http.delete(&url),
        _ => http.get(&url),
    };

    req = req.headers(auth_headers(token));

    if let Some(body) = body {
        req = req.json(&body);
    }

    let res = req.send().await?;

    if !res.status().is_success() && !res.status().is_redirection() {
        let status = res.status();
        if status == reqwest::StatusCode::NO_CONTENT {
            return Ok(res);
        }
        let body = res.text().await?;
        return Err(format!("HTTP {status}: {body}").into());
    }

    Ok(res)
}

/// Recursively collect .md files from a directory.
fn collect_md_files(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                if !name.starts_with('.') && name != "node_modules" {
                    files.extend(collect_md_files(&path));
                }
            } else if path.extension().is_some_and(|e| e == "md") {
                files.push(path);
            }
        }
    }
    files
}
