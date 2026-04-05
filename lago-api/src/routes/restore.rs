use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};

use lago_core::event::{EventEnvelope, EventPayload};
use lago_core::id::{BranchId, EventId, SeqNo, SessionId};
use lago_core::EventQuery;

use crate::error::ApiError;
use crate::state::AppState;

// --- Request / Response types

#[derive(Deserialize)]
pub struct RestoreRequest {
    /// Branch to restore from (defaults to "main").
    #[serde(default = "default_branch")]
    pub branch: String,
    /// Sequence number to restore to (inclusive). Must exist on the branch.
    pub target_seq: SeqNo,
    /// Name for the new restored branch.
    pub new_branch_name: String,
}

fn default_branch() -> String {
    "main".to_string()
}

#[derive(Serialize)]
pub struct RestoreResponse {
    pub branch_id: String,
    pub name: String,
    pub fork_point_seq: SeqNo,
    pub events_in_restored_branch: usize,
}

// --- Handler

/// POST /v1/sessions/:id/restore
///
/// Point-in-time recovery: creates a new branch forked at a historical
/// sequence number. The original branch and events are untouched.
///
/// The restored branch's manifest equals the state at `target_seq`:
/// replaying events[0..=target_seq] on the source branch.
pub async fn restore(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Json(body): Json<RestoreRequest>,
) -> Result<(axum::http::StatusCode, Json<RestoreResponse>), ApiError> {
    let session_id = SessionId::from_string(session_id.clone());

    // 1. Verify the session exists
    state
        .journal
        .get_session(&session_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("session not found: {session_id}")))?;

    // 2. Resolve the source branch ID
    let source_branch_id = resolve_branch_id(&state, &session_id, &body.branch).await?;

    // 3. Validate that target_seq exists on the source branch
    let head_seq = state
        .journal
        .head_seq(&session_id, &source_branch_id)
        .await?;

    if body.target_seq > head_seq {
        return Err(ApiError::BadRequest(format!(
            "target_seq {} exceeds branch '{}' head seq {}",
            body.target_seq, body.branch, head_seq
        )));
    }

    // Verify at least one event exists at or before target_seq
    let verify_query = EventQuery::new()
        .session(session_id.clone())
        .branch(source_branch_id.clone())
        .before(body.target_seq + 1); // before is exclusive
    let events_up_to_target = state.journal.read(verify_query).await?;

    if events_up_to_target.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "no events found on branch '{}' at or before seq {}",
            body.branch, body.target_seq
        )));
    }

    let events_count = events_up_to_target.len();

    // 4. Check that the new branch name doesn't already exist
    let all_events_query = EventQuery::new().session(session_id.clone());
    let all_events = state.journal.read(all_events_query).await?;

    for event in &all_events {
        if let EventPayload::BranchCreated { ref name, .. } = event.payload {
            if name == &body.new_branch_name {
                return Err(ApiError::Conflict(format!(
                    "branch '{}' already exists",
                    body.new_branch_name
                )));
            }
        }
    }

    // 5. Create the new branch forked at target_seq
    let new_branch_id = BranchId::new();

    let branch_event = EventEnvelope {
        event_id: EventId::new(),
        session_id: session_id.clone(),
        branch_id: source_branch_id.clone(),
        run_id: None,
        seq: 0, // Assigned by the journal
        timestamp: EventEnvelope::now_micros(),
        parent_id: None,
        payload: EventPayload::BranchCreated {
            new_branch_id: new_branch_id.clone().into(),
            fork_point_seq: body.target_seq,
            name: body.new_branch_name.clone(),
        },
        metadata: HashMap::from([
            ("restore".to_string(), "true".to_string()),
            (
                "restore_source_branch".to_string(),
                body.branch.clone(),
            ),
            (
                "restore_target_seq".to_string(),
                body.target_seq.to_string(),
            ),
        ]),
        schema_version: 1,
    };

    state.journal.append(branch_event).await?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(RestoreResponse {
            branch_id: new_branch_id.to_string(),
            name: body.new_branch_name,
            fork_point_seq: body.target_seq,
            events_in_restored_branch: events_count,
        }),
    ))
}

/// Resolve a branch name to its BranchId by scanning BranchCreated events.
/// "main" is always available as a well-known branch.
async fn resolve_branch_id(
    state: &AppState,
    session_id: &SessionId,
    branch_name: &str,
) -> Result<BranchId, ApiError> {
    if branch_name == "main" {
        return Ok(BranchId::from_string("main"));
    }

    let query = EventQuery::new().session(session_id.clone());
    let events = state.journal.read(query).await?;

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

    Err(ApiError::NotFound(format!(
        "branch not found: {branch_name}"
    )))
}
