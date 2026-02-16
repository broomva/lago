use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};

use lago_core::event::{EventEnvelope, EventPayload};
use lago_core::id::{BranchId, EventId, SeqNo, SessionId};

use crate::error::ApiError;
use crate::state::AppState;

// --- Request / Response types

#[derive(Deserialize)]
pub struct CreateBranchRequest {
    pub name: String,
    #[serde(default)]
    pub fork_point_seq: Option<SeqNo>,
}

#[derive(Serialize)]
pub struct BranchResponse {
    pub branch_id: String,
    pub name: String,
    pub fork_point_seq: SeqNo,
}

// --- Handlers

/// POST /v1/sessions/:id/branches
///
/// Creates a new branch forked from the session's "main" branch at the
/// given sequence number (defaults to the current head).
pub async fn create_branch(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Json(body): Json<CreateBranchRequest>,
) -> Result<(axum::http::StatusCode, Json<BranchResponse>), ApiError> {
    let session_id = SessionId::from_string(session_id.clone());
    let main_branch = BranchId::from_string("main");

    // Verify the session exists
    state
        .journal
        .get_session(&session_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("session not found: {session_id}")))?;

    // Determine fork point: use the provided seq or the current head
    let fork_point_seq = match body.fork_point_seq {
        Some(seq) => seq,
        None => state.journal.head_seq(&session_id, &main_branch).await?,
    };

    let new_branch_id = BranchId::new();

    // Emit a BranchCreated event on the main branch
    let event = EventEnvelope {
        event_id: EventId::new(),
        session_id: session_id.clone(),
        branch_id: main_branch.clone(),
        run_id: None,
        seq: 0, // Will be assigned by the journal
        timestamp: EventEnvelope::now_micros(),
        parent_id: None,
        payload: EventPayload::BranchCreated {
            new_branch_id: new_branch_id.clone().into(),
            fork_point_seq,
            name: body.name.clone(),
        },
        metadata: HashMap::new(),
        schema_version: 1,
    };

    state.journal.append(event).await?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(BranchResponse {
            branch_id: new_branch_id.to_string(),
            name: body.name,
            fork_point_seq,
        }),
    ))
}

/// GET /v1/sessions/:id/branches
///
/// Lists all branches for a session. Currently reads BranchCreated events
/// from the journal to reconstruct the branch list.
pub async fn list_branches(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> Result<Json<Vec<BranchResponse>>, ApiError> {
    let session_id = SessionId::from_string(session_id.clone());

    // Verify the session exists
    let _session = state
        .journal
        .get_session(&session_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("session not found: {session_id}")))?;

    // Read all events for this session to find BranchCreated events
    let query = lago_core::EventQuery::new().session(session_id.clone());
    let events = state.journal.read(query).await?;

    let mut branches: Vec<BranchResponse> = Vec::new();

    // The "main" branch always exists for a session
    branches.push(BranchResponse {
        branch_id: "main".to_string(),
        name: "main".to_string(),
        fork_point_seq: 0,
    });

    // Extract BranchCreated events
    for event in &events {
        if let EventPayload::BranchCreated {
            ref new_branch_id,
            fork_point_seq,
            ref name,
        } = event.payload
        {
            branches.push(BranchResponse {
                branch_id: new_branch_id.as_str().to_string(),
                name: name.clone(),
                fork_point_seq,
            });
        }
    }

    Ok(Json(branches))
}
