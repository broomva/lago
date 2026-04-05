use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};

use lago_core::EventQuery;
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

#[derive(Deserialize)]
pub struct MergeBranchRequest {
    pub target: String,
}

#[derive(Serialize)]
pub struct MergeBranchResponse {
    pub merged: bool,
    pub strategy: String,
    pub events_merged: usize,
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

/// POST /v1/sessions/:id/branches/:branch/merge
///
/// Merges the named branch INTO the target branch specified in the request body.
/// Phase 1: Fast-forward merge only — succeeds when the source branch's
/// fork_point_seq >= the target branch's head_seq, meaning the target has not
/// diverged. Returns 409 Conflict if a fast-forward is not possible.
pub async fn merge_branch(
    State(state): State<Arc<AppState>>,
    Path((session_id, source_branch_name)): Path<(String, String)>,
    Json(body): Json<MergeBranchRequest>,
) -> Result<Json<MergeBranchResponse>, ApiError> {
    let session_id = SessionId::from_string(session_id.clone());

    // Verify the session exists
    state
        .journal
        .get_session(&session_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("session not found: {session_id}")))?;

    // Resolve source and target branch IDs.
    // We need to scan BranchCreated events to map branch names to IDs.
    let all_events_query = EventQuery::new().session(session_id.clone());
    let all_events = state.journal.read(all_events_query).await?;

    // Build a name-to-id map from BranchCreated events. "main" always exists.
    let mut name_to_id: HashMap<String, BranchId> = HashMap::new();
    name_to_id.insert("main".to_string(), BranchId::from_string("main"));

    // Also track fork_point_seq per branch
    let mut branch_fork_points: HashMap<String, SeqNo> = HashMap::new();
    branch_fork_points.insert("main".to_string(), 0);

    for event in &all_events {
        if let EventPayload::BranchCreated {
            ref new_branch_id,
            fork_point_seq,
            ref name,
        } = event.payload
        {
            let lago_branch_id = BranchId::from_string(new_branch_id.as_str());
            name_to_id.insert(name.clone(), lago_branch_id);
            branch_fork_points.insert(name.clone(), fork_point_seq);
        }
    }

    // Look up source branch
    let source_branch_id = name_to_id
        .get(&source_branch_name)
        .cloned()
        .ok_or_else(|| {
            ApiError::NotFound(format!("source branch not found: {source_branch_name}"))
        })?;

    let source_fork_point = branch_fork_points
        .get(&source_branch_name)
        .copied()
        .unwrap_or(0);

    // Look up target branch
    let target_branch_id = name_to_id
        .get(&body.target)
        .cloned()
        .ok_or_else(|| ApiError::NotFound(format!("target branch not found: {}", body.target)))?;

    // Fast-forward check: verify the target branch has not received any
    // content events after the source's fork point. BranchCreated events
    // are metadata (they record the creation of other branches) and do not
    // constitute divergence, so we exclude them from the check.
    let target_events_query = EventQuery::new()
        .session(session_id.clone())
        .branch(target_branch_id.clone())
        .after(source_fork_point);
    let target_events_after_fork = state.journal.read(target_events_query).await?;

    let has_content_divergence = target_events_after_fork
        .iter()
        .any(|e| !matches!(e.payload, EventPayload::BranchCreated { .. }));

    if has_content_divergence {
        let target_head_seq = state
            .journal
            .head_seq(&session_id, &target_branch_id)
            .await?;
        return Err(ApiError::Conflict(format!(
            "fast-forward not possible: source branch '{}' forked at seq {} \
             but target branch '{}' has diverged (head at seq {}). \
             A three-way merge is required.",
            source_branch_name, source_fork_point, body.target, target_head_seq
        )));
    }

    // Read all events from the source branch
    let source_query = EventQuery::new()
        .session(session_id.clone())
        .branch(source_branch_id.clone());
    let source_events = state.journal.read(source_query).await?;

    // Copy each source event to the target branch with new event IDs
    let mut merged_events: Vec<EventEnvelope> = Vec::new();
    for source_event in &source_events {
        let mut merged = source_event.clone();
        merged.event_id = EventId::new();
        merged.branch_id = target_branch_id.clone();
        merged.seq = 0; // Will be assigned by the journal
        merged.timestamp = EventEnvelope::now_micros();
        merged_events.push(merged);
    }

    let events_merged = merged_events.len();

    // Append all merged events to the target branch
    if !merged_events.is_empty() {
        state.journal.append_batch(merged_events).await?;
    }

    // Emit a BranchMerged custom event on the target branch
    let merge_event = EventEnvelope {
        event_id: EventId::new(),
        session_id: session_id.clone(),
        branch_id: target_branch_id.clone(),
        run_id: None,
        seq: 0, // Will be assigned by the journal
        timestamp: EventEnvelope::now_micros(),
        parent_id: None,
        payload: EventPayload::Custom {
            event_type: "BranchMerged".to_string(),
            data: serde_json::json!({
                "source_branch": source_branch_name,
                "source_branch_id": source_branch_id.as_str(),
                "target_branch": body.target,
                "target_branch_id": target_branch_id.as_str(),
                "strategy": "fast-forward",
                "events_merged": events_merged,
            }),
        },
        metadata: HashMap::new(),
        schema_version: 1,
    };

    state.journal.append(merge_event).await?;

    Ok(Json(MergeBranchResponse {
        merged: true,
        strategy: "fast-forward".to_string(),
        events_merged,
    }))
}
