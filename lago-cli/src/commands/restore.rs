use std::path::Path;

use lago_core::event::EventPayload;
use lago_core::{BranchId, EventEnvelope, EventId, EventQuery, Journal, Projection, SessionId};
use lago_fs::ManifestProjection;
use tracing::debug;

use crate::db::open_journal;

/// Point-in-time restore: create a new branch forked at a historical sequence number.
pub async fn run(
    data_dir: &Path,
    session_id_str: &str,
    branch: &str,
    target_seq: u64,
    new_branch_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let journal = open_journal(data_dir)?;
    let session_id = SessionId::from_string(session_id_str);

    // Verify the session exists
    journal
        .get_session(&session_id)
        .await?
        .ok_or_else(|| format!("session not found: {session_id_str}"))?;

    // Resolve the source branch ID
    let source_branch_id = if branch == "main" {
        BranchId::from_string("main")
    } else {
        resolve_branch_id(&journal, &session_id, branch).await?
    };

    // Validate that target_seq exists on the source branch
    let head_seq = journal.head_seq(&session_id, &source_branch_id).await?;
    if target_seq > head_seq {
        return Err(format!(
            "target_seq {target_seq} exceeds branch '{branch}' head seq {head_seq}"
        )
        .into());
    }

    // Verify events exist at or before target_seq
    let verify_query = EventQuery::new()
        .session(session_id.clone())
        .branch(source_branch_id.clone())
        .before(target_seq + 1);
    let events_up_to_target = journal.read(verify_query).await?;

    if events_up_to_target.is_empty() {
        return Err(format!(
            "no events found on branch '{branch}' at or before seq {target_seq}"
        )
        .into());
    }

    // Check for duplicate branch name
    let all_query = EventQuery::new().session(session_id.clone());
    let all_events = journal.read(all_query).await?;
    for event in &all_events {
        if let EventPayload::BranchCreated { ref name, .. } = event.payload {
            if name == new_branch_name {
                return Err(format!("branch '{new_branch_name}' already exists").into());
            }
        }
    }

    // Create the restored branch
    let new_branch_id = BranchId::new();
    let branch_event = EventEnvelope {
        event_id: EventId::new(),
        session_id: session_id.clone(),
        branch_id: source_branch_id,
        run_id: None,
        seq: 0,
        timestamp: EventEnvelope::now_micros(),
        parent_id: None,
        payload: EventPayload::BranchCreated {
            new_branch_id: new_branch_id.clone().into(),
            fork_point_seq: target_seq,
            name: new_branch_name.to_string(),
        },
        metadata: std::collections::HashMap::from([
            ("restore".to_string(), "true".to_string()),
            ("restore_source_branch".to_string(), branch.to_string()),
            ("restore_target_seq".to_string(), target_seq.to_string()),
        ]),
        schema_version: 1,
    };

    journal.append(branch_event).await?;

    // Verify: replay events up to target_seq and show manifest size
    let replay_query = EventQuery::new()
        .session(session_id.clone())
        .branch(BranchId::from_string(branch))
        .before(target_seq + 1);
    let replay_events = journal.read(replay_query).await?;

    let mut projection = ManifestProjection::new();
    for event in &replay_events {
        projection.on_event(event)?;
    }

    let file_count = projection.manifest().entries().len();

    println!("Restored to seq {target_seq} on branch '{branch}'");
    println!("  New branch: {new_branch_name} ({})", new_branch_id);
    println!("  Events replayed: {}", events_up_to_target.len());
    println!("  Files in manifest: {file_count}");

    debug!(
        %new_branch_id,
        new_branch_name,
        target_seq,
        source_branch = branch,
        "point-in-time restore completed"
    );

    Ok(())
}

/// Resolve a branch name to its BranchId by scanning BranchCreated events.
async fn resolve_branch_id(
    journal: &dyn Journal,
    session_id: &SessionId,
    branch_name: &str,
) -> Result<BranchId, Box<dyn std::error::Error>> {
    let query = EventQuery::new().session(session_id.clone());
    let events = journal.read(query).await?;

    for event in &events {
        if let EventPayload::BranchCreated {
            ref new_branch_id,
            ref name,
            ..
        } = event.payload
        {
            if name == branch_name {
                return Ok(BranchId::from_string(new_branch_id.as_str()));
            }
        }
    }

    Err(format!("branch not found: {branch_name}").into())
}
