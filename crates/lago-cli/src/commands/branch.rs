use std::path::Path;

use lago_core::event::EventPayload;
use lago_core::{BranchId, EventEnvelope, EventId, EventQuery, Journal, Projection, SessionId};
use lago_fs::ManifestProjection;
use tracing::debug;

use crate::db::open_journal;

/// Create a new branch for a session.
pub async fn create(
    data_dir: &Path,
    session_id_str: &str,
    name: &str,
    fork_at: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let journal = open_journal(data_dir)?;
    let session_id = SessionId::from_string(session_id_str);

    // Verify the session exists
    journal
        .get_session(&session_id)
        .await?
        .ok_or_else(|| format!("session not found: {session_id_str}"))?;

    // Determine the fork point: use the provided seq, or the current head of "main"
    let main_branch = BranchId::from_string("main");
    let fork_point = match fork_at {
        Some(seq) => seq,
        None => journal.head_seq(&session_id, &main_branch).await?,
    };

    let new_branch_id = BranchId::new();
    let event = EventEnvelope {
        event_id: EventId::new(),
        session_id: session_id.clone(),
        branch_id: main_branch,
        run_id: None,
        seq: fork_point + 1,
        timestamp: EventEnvelope::now_micros(),
        parent_id: None,
        payload: EventPayload::BranchCreated {
            new_branch_id: new_branch_id.clone(),
            fork_point_seq: fork_point,
            name: name.to_string(),
        },
        metadata: std::collections::HashMap::new(),
    };

    journal.append(event).await?;

    println!("{}", new_branch_id);
    debug!(%new_branch_id, name, fork_point, "branch created");
    Ok(())
}

/// List all branches for a session.
///
/// Builds a `ManifestProjection` by replaying all events for the session,
/// then reads branch metadata from the projection's `BranchManager`.
pub async fn list(data_dir: &Path, session_id_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    let journal = open_journal(data_dir)?;
    let session_id = SessionId::from_string(session_id_str);

    // Verify the session exists
    journal
        .get_session(&session_id)
        .await?
        .ok_or_else(|| format!("session not found: {session_id_str}"))?;

    // Replay all events to build the branch manager state
    let query = EventQuery::new().session(session_id);
    let events = journal.read(query).await?;

    let mut projection = ManifestProjection::new();
    for event in &events {
        projection.on_event(event)?;
    }

    let branches = projection.branch_manager().list_branches();

    if branches.is_empty() {
        println!("No branches found. (The implicit 'main' branch has no BranchCreated event.)");
        return Ok(());
    }

    println!(
        "{:<28}  {:<16}  {:<10}  HEAD SEQ",
        "BRANCH ID", "NAME", "FORK SEQ"
    );
    println!("{}", "-".repeat(80));

    for branch in &branches {
        println!(
            "{:<28}  {:<16}  {:<10}  {}",
            branch.branch_id, branch.name, branch.fork_point_seq, branch.head_seq,
        );
    }

    println!("\n{} branch(es) total.", branches.len());
    Ok(())
}
