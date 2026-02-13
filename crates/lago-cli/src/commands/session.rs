use std::path::Path;

use lago_core::{Journal, Session, SessionConfig, SessionId};
use tracing::debug;

use crate::client::Client;
use crate::db::open_journal;

// TODO: Make this configurable
// const DEFAULT_HTTP_PORT: u16 = 8080;

/// Create a new session.
pub async fn create(
    data_dir: &Path,
    api_port: u16,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Try to use the API client first
    let client = Client::new(api_port);
    if client.health().await {
        debug!("using API client to create session");
        // TODO: Handle errors gracefully
        let res = client.create_session(name).await?;
        println!("{}", res.session_id);
        return Ok(());
    }

    // Fallback to direct DB access
    debug!("using direct DB access to create session");
    let journal = open_journal(data_dir)?;

    let session_id = SessionId::new();
    let session = Session {
        session_id: session_id.clone(),
        config: SessionConfig::new(name),
        created_at: lago_core::EventEnvelope::now_micros(),
        branches: vec![],
    };

    journal.put_session(session).await?;

    println!("{}", session_id);
    debug!(%session_id, name, "session created");
    Ok(())
}

/// List all sessions.
pub async fn list(data_dir: &Path, api_port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let mut sessions = Vec::new();

    // Try API client
    let client = Client::new(api_port);
    if match client.list_sessions().await {
        Ok(list) => {
            debug!("using API client to list sessions");
            // Map SessionResponse back to a simplified structure for display if needed,
            // or just use the response data directly.
            // The existing code expects `lago_core::session::Session` for display.
            // For now, let's construct lightweight Session objects or just change display logic.
            // To keep it simple, we'll refactor display logic to take a common trait or struct,
            // or just manual mapping.

            // Let's use a simpler approach:
            // If API works, print and return. If not, load from DB and print.

            if list.is_empty() {
                println!("No sessions found.");
                return Ok(());
            }

            println!("{:<28}  {:<20}  CREATED AT", "SESSION ID", "NAME");
            println!("{}", "-".repeat(70));

            for session in &list {
                let created = format_timestamp(session.created_at);
                println!(
                    "{:<28}  {:<20}  {}",
                    session.session_id, session.name, created,
                );
            }
            println!("\n{} session(s) total.", list.len());
            return Ok(());
        }
        Err(_) => false, // Fallback
    } {
        return Ok(());
    }

    // Fallback
    debug!("using direct DB access to list sessions");
    let journal = open_journal(data_dir)?;
    sessions = journal.list_sessions().await?;

    if sessions.is_empty() {
        println!("No sessions found.");
        return Ok(());
    }

    println!("{:<28}  {:<20}  CREATED AT", "SESSION ID", "NAME");
    println!("{}", "-".repeat(70));

    for session in &sessions {
        let created = format_timestamp(session.created_at);
        println!(
            "{:<28}  {:<20}  {}",
            session.session_id, session.config.name, created,
        );
    }

    println!("\n{} session(s) total.", sessions.len());
    Ok(())
}

/// Show details of a specific session.
pub async fn show(
    data_dir: &Path,
    api_port: u16,
    id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new(api_port);

    // Try API
    if let Ok(session) = client.get_session(id).await {
        debug!("using API client to show session");
        print_session_details(
            &session.session_id,
            &session.name,
            session.created_at,
            &session.model,
            &session.branches,
        );
        return Ok(());
    }

    // Fallback
    debug!("using direct DB access to show session");
    let journal = open_journal(data_dir)?;
    let session_id = SessionId::from_string(id);

    let session = journal
        .get_session(&session_id)
        .await?
        .ok_or_else(|| format!("session not found: {id}"))?;

    let branch_names: Vec<String> = session.branches.iter().map(|b| b.to_string()).collect();
    print_session_details(
        &session.session_id.to_string(),
        &session.config.name,
        session.created_at,
        &session.config.model,
        &branch_names,
    );

    Ok(())
}

fn print_session_details(id: &str, name: &str, created_at: u64, model: &str, branches: &[String]) {
    println!("Session ID:  {}", id);
    println!("Name:        {}", name);
    println!("Created At:  {}", format_timestamp(created_at));
    println!(
        "Model:       {}",
        if model.is_empty() { "(default)" } else { model }
    );

    if !branches.is_empty() {
        println!("Branches:");
        for branch in branches {
            println!("  - {branch}");
        }
    }
}

/// Format a microsecond timestamp to a human-readable string.
fn format_timestamp(micros: u64) -> String {
    let secs = micros / 1_000_000;
    let nanos = ((micros % 1_000_000) * 1000) as u32;
    let dt = std::time::UNIX_EPOCH + std::time::Duration::new(secs, nanos);
    let elapsed = dt.elapsed().unwrap_or(std::time::Duration::ZERO);

    if elapsed.as_secs() < 60 {
        "just now".to_string()
    } else if elapsed.as_secs() < 3600 {
        format!("{}m ago", elapsed.as_secs() / 60)
    } else if elapsed.as_secs() < 86400 {
        format!("{}h ago", elapsed.as_secs() / 3600)
    } else {
        format!("{}d ago", elapsed.as_secs() / 86400)
    }
}
