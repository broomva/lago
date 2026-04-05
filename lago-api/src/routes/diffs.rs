use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;

use lago_core::EventQuery;
use lago_core::event::EventPayload;
use lago_core::id::{BranchId, SessionId};
use lago_fs::diff::{self, DiffEntry};

use crate::error::ApiError;
use crate::state::AppState;

// --- Query types

/// Diff references: branch name, snapshot name, or sequence number.
#[derive(Deserialize)]
pub struct DiffQuery {
    /// Source reference (branch name, snapshot name prefixed with "snap:", or seq number).
    pub from: String,
    /// Target reference (branch name, snapshot name prefixed with "snap:", or seq number).
    /// Defaults to HEAD of the session's main branch.
    #[serde(default)]
    pub to: Option<String>,
    /// Branch context when using sequence numbers (default: main).
    #[serde(default = "default_branch")]
    pub branch: String,
}

fn default_branch() -> String {
    "main".to_string()
}

// --- Handlers

/// GET /v1/sessions/:id/diff?from=<ref>&to=<ref>
///
/// Returns the diff between two points in a session's history.
/// References can be:
///   - A branch name (e.g., "main", "experiment")
///   - A snapshot name prefixed with "snap:" (e.g., "snap:v1.0")
///   - A sequence number (e.g., "42")
pub async fn get_diff(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Query(query): Query<DiffQuery>,
) -> Result<Json<Vec<DiffEntry>>, ApiError> {
    let session_id = SessionId::from_string(session_id.clone());

    // Verify session exists
    state
        .journal
        .get_session(&session_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("session not found: {session_id}")))?;

    let from_manifest =
        resolve_ref_to_manifest(&state, &session_id, &query.from, &query.branch).await?;
    let to_ref = query.to.unwrap_or_else(|| query.branch.clone());
    let to_manifest = resolve_ref_to_manifest(&state, &session_id, &to_ref, &query.branch).await?;

    let diff_entries = diff::diff(&from_manifest, &to_manifest);
    Ok(Json(diff_entries))
}

// --- Internal helpers

/// Resolve a reference string to a manifest.
async fn resolve_ref_to_manifest(
    state: &Arc<AppState>,
    session_id: &SessionId,
    reference: &str,
    default_branch: &str,
) -> Result<lago_fs::Manifest, ApiError> {
    // Try parsing as a sequence number first
    if let Ok(seq) = reference.parse::<u64>() {
        return build_manifest_at_seq(state, session_id, default_branch, seq).await;
    }

    // Check if it's a snapshot reference (snap:name)
    if let Some(snap_name) = reference.strip_prefix("snap:") {
        return build_manifest_at_snapshot(state, session_id, snap_name).await;
    }

    // Otherwise treat as a branch name — build manifest at HEAD
    let branch_id = BranchId::from_string(reference);
    build_manifest_at_head(state, session_id, &branch_id).await
}

/// Build manifest from all events on a branch up to HEAD.
async fn build_manifest_at_head(
    state: &Arc<AppState>,
    session_id: &SessionId,
    branch_id: &BranchId,
) -> Result<lago_fs::Manifest, ApiError> {
    let query = EventQuery::new()
        .session(session_id.clone())
        .branch(branch_id.clone());
    let events = state.journal.read(query).await?;
    Ok(build_manifest_from_events(&events))
}

/// Build manifest from events up to a specific sequence number.
async fn build_manifest_at_seq(
    state: &Arc<AppState>,
    session_id: &SessionId,
    branch: &str,
    max_seq: u64,
) -> Result<lago_fs::Manifest, ApiError> {
    let branch_id = BranchId::from_string(branch);
    let query = EventQuery::new()
        .session(session_id.clone())
        .branch(branch_id);
    let events = state.journal.read(query).await?;

    let mut manifest = lago_fs::Manifest::new();
    for event in &events {
        if event.seq > max_seq {
            break;
        }
        apply_event_to_manifest(&mut manifest, event);
    }
    Ok(manifest)
}

/// Build manifest at a named snapshot point.
///
/// Finds the `SnapshotCreated` event whose `snapshot_id` matches the given name,
/// then builds the manifest from events up to `covers_through_seq`.
async fn build_manifest_at_snapshot(
    state: &Arc<AppState>,
    session_id: &SessionId,
    snapshot_name: &str,
) -> Result<lago_fs::Manifest, ApiError> {
    // Query all SnapshotCreated events and find by snapshot_id
    let query = EventQuery::new()
        .session(session_id.clone())
        .with_kind("SnapshotCreated");
    let events = state.journal.read(query).await?;

    let mut covers_seq = None;
    let mut branch = "main".to_string();

    for event in &events {
        if let EventPayload::SnapshotCreated {
            snapshot_id,
            covers_through_seq,
            ..
        } = &event.payload
        {
            if snapshot_id.as_str() == snapshot_name {
                covers_seq = Some(*covers_through_seq);
                branch = event.branch_id.as_str().to_string();
                break;
            }
        }
    }

    let seq = covers_seq
        .ok_or_else(|| ApiError::NotFound(format!("snapshot not found: {snapshot_name}")))?;

    build_manifest_at_seq(state, session_id, &branch, seq).await
}

/// Replay file events to build a manifest.
fn build_manifest_from_events(events: &[lago_core::event::EventEnvelope]) -> lago_fs::Manifest {
    let mut manifest = lago_fs::Manifest::new();
    for event in events {
        apply_event_to_manifest(&mut manifest, event);
    }
    manifest
}

fn apply_event_to_manifest(
    manifest: &mut lago_fs::Manifest,
    event: &lago_core::event::EventEnvelope,
) {
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
