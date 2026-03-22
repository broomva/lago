//! Named snapshot (tag) API for Lago sessions.
//!
//! Snapshots record named points-in-time in a session's event history.
//! They are stored as `SnapshotCreated` events in the journal and can be
//! used to reconstruct manifests at any tagged point.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use lago_core::event::{EventPayload, SnapshotType};
use lago_core::id::{BlobHash, BranchId, EventId, SessionId, SnapshotId};
use lago_core::{EventEnvelope, EventQuery, ManifestEntry};

use crate::error::ApiError;
use crate::state::AppState;

// --- Request/Response types

#[derive(Deserialize)]
pub struct CreateSnapshotRequest {
    /// Human-readable tag name (e.g., "v1.0", "release-2026-03").
    pub name: String,
}

#[derive(Serialize)]
pub struct SnapshotResponse {
    pub name: String,
    pub branch: String,
    pub seq: u64,
    pub created_at: u64,
}

#[derive(Serialize)]
pub struct SnapshotManifestResponse {
    pub snapshot: String,
    pub session_id: String,
    pub branch: String,
    pub seq: u64,
    pub entries: Vec<ManifestEntry>,
}

#[derive(Debug, Deserialize, Default)]
pub struct SnapshotQuery {
    /// Branch to operate on (default: main).
    #[serde(default = "default_branch")]
    pub branch: String,
}

fn default_branch() -> String {
    "main".to_string()
}

// --- Handlers

/// POST /v1/sessions/:id/snapshots
///
/// Creates a named snapshot (tag) at the current head of the specified branch.
/// Stores a `SnapshotCreated` event in the journal.
pub async fn create_snapshot(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Query(query): Query<SnapshotQuery>,
    Json(body): Json<CreateSnapshotRequest>,
) -> Result<(StatusCode, Json<SnapshotResponse>), ApiError> {
    let session_id = SessionId::from_string(session_id);
    let branch_id = BranchId::from_string(query.branch.clone());

    // Verify session exists
    state
        .journal
        .get_session(&session_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("session not found: {session_id}")))?;

    // Check for duplicate tag name on this branch
    let existing = find_snapshot(&state, &session_id, &branch_id, &body.name).await?;
    if existing.is_some() {
        return Err(ApiError::BadRequest(format!(
            "snapshot '{}' already exists on branch '{}'",
            body.name, query.branch
        )));
    }

    // Get current head seq
    let head_seq = state.journal.head_seq(&session_id, &branch_id).await?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Create the SnapshotCreated event
    let envelope = EventEnvelope {
        event_id: EventId::default(),
        session_id: session_id.clone(),
        branch_id: branch_id.clone(),
        run_id: None,
        seq: 0, // Journal assigns real seq
        timestamp: now,
        parent_id: None,
        payload: EventPayload::SnapshotCreated {
            snapshot_id: SnapshotId::from_string(&body.name).into(),
            snapshot_type: SnapshotType::Full,
            covers_through_seq: head_seq,
            data_hash: BlobHash::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
            .into(),
        },
        metadata: Default::default(),
        schema_version: 1,
    };

    state.journal.append(envelope).await?;

    Ok((
        StatusCode::CREATED,
        Json(SnapshotResponse {
            name: body.name,
            branch: query.branch,
            seq: head_seq,
            created_at: now,
        }),
    ))
}

/// GET /v1/sessions/:id/snapshots
///
/// Lists all named snapshots (tags) in the session.
pub async fn list_snapshots(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Query(query): Query<SnapshotQuery>,
) -> Result<Json<Vec<SnapshotResponse>>, ApiError> {
    let session_id = SessionId::from_string(session_id);
    let branch_id = BranchId::from_string(query.branch.clone());

    // Verify session exists
    state
        .journal
        .get_session(&session_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("session not found: {session_id}")))?;

    let snapshots = collect_snapshots(&state, &session_id, &branch_id).await?;

    let responses: Vec<SnapshotResponse> = snapshots
        .iter()
        .map(|(name, seq, timestamp)| SnapshotResponse {
            name: name.clone(),
            branch: query.branch.clone(),
            seq: *seq,
            created_at: *timestamp,
        })
        .collect();

    Ok(Json(responses))
}

/// GET /v1/sessions/:id/snapshots/:name/manifest
///
/// Returns the manifest at the point-in-time captured by the named snapshot.
pub async fn get_snapshot_manifest(
    State(state): State<Arc<AppState>>,
    Path((session_id, snapshot_name)): Path<(String, String)>,
    Query(query): Query<SnapshotQuery>,
) -> Result<Json<SnapshotManifestResponse>, ApiError> {
    let session_id = SessionId::from_string(session_id.clone());
    let branch_id = BranchId::from_string(query.branch.clone());

    // Verify session exists
    state
        .journal
        .get_session(&session_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("session not found: {session_id}")))?;

    // Find the snapshot
    let (_, covers_through_seq, _) = find_snapshot(&state, &session_id, &branch_id, &snapshot_name)
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(format!(
                "snapshot '{}' not found on branch '{}'",
                snapshot_name, query.branch
            ))
        })?;

    // Build manifest from events up to the snapshot point (inclusive)
    let entries =
        build_manifest_at_seq(&state, &session_id, &branch_id, covers_through_seq).await?;

    Ok(Json(SnapshotManifestResponse {
        snapshot: snapshot_name,
        session_id: session_id.to_string(),
        branch: query.branch,
        seq: covers_through_seq,
        entries,
    }))
}

// --- Internal helpers

/// Find a snapshot by name in a session+branch. Returns (name, seq, timestamp).
async fn find_snapshot(
    state: &Arc<AppState>,
    session_id: &SessionId,
    branch_id: &BranchId,
    name: &str,
) -> Result<Option<(String, u64, u64)>, ApiError> {
    let snapshots = collect_snapshots(state, session_id, branch_id).await?;
    Ok(snapshots.into_iter().find(|(n, _, _)| n == name))
}

/// Collect all snapshots from a session+branch. Returns Vec<(name, seq, timestamp)>.
async fn collect_snapshots(
    state: &Arc<AppState>,
    session_id: &SessionId,
    branch_id: &BranchId,
) -> Result<Vec<(String, u64, u64)>, ApiError> {
    let query = EventQuery::new()
        .session(session_id.clone())
        .branch(branch_id.clone())
        .with_kind("SnapshotCreated");

    let events = state.journal.read(query).await?;

    let mut snapshots = Vec::new();
    for event in &events {
        if let EventPayload::SnapshotCreated {
            snapshot_id,
            covers_through_seq,
            ..
        } = &event.payload
        {
            snapshots.push((
                snapshot_id.as_str().to_string(),
                *covers_through_seq,
                event.timestamp,
            ));
        }
    }

    Ok(snapshots)
}

/// Build a manifest from events up to a specific sequence number (inclusive).
async fn build_manifest_at_seq(
    state: &Arc<AppState>,
    session_id: &SessionId,
    branch_id: &BranchId,
    through_seq: u64,
) -> Result<Vec<ManifestEntry>, ApiError> {
    // before_seq is exclusive in the journal, so add 1 for inclusive
    let query = EventQuery::new()
        .session(session_id.clone())
        .branch(branch_id.clone())
        .before(through_seq + 1);

    let events = state.journal.read(query).await?;

    let mut manifest = lago_fs::Manifest::new();

    for event in &events {
        match &event.payload {
            EventPayload::FileWrite {
                path,
                blob_hash,
                size_bytes,
                content_type,
            } => {
                manifest.apply_write(
                    path.clone(),
                    lago_core::BlobHash::from_hex(blob_hash.as_str()),
                    *size_bytes,
                    content_type.clone(),
                    event.timestamp,
                );
            }
            EventPayload::FileDelete { path } => {
                manifest.apply_delete(path);
            }
            EventPayload::FileRename { old_path, new_path } => {
                manifest.apply_rename(old_path, new_path.clone());
            }
            _ => {}
        }
    }

    Ok(manifest.entries().values().cloned().collect())
}
