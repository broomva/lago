use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use lago_core::event::{EventEnvelope, EventPayload};
use lago_core::hashline::{HashLineEdit, HashLineFile};
use lago_core::id::{BranchId, EventId, SessionId};
use lago_core::{EventQuery, ManifestEntry};

use crate::error::ApiError;
use crate::state::AppState;

// --- Response types

#[derive(Serialize)]
pub struct FileWriteResponse {
    pub path: String,
    pub blob_hash: String,
    pub size_bytes: u64,
}

#[derive(Serialize)]
pub struct ManifestResponse {
    pub session_id: String,
    pub entries: Vec<ManifestEntry>,
}

// --- Query types

#[derive(Debug, Deserialize, Default)]
pub struct FileReadQuery {
    /// Optional format: "hashline" returns content in hashline format.
    #[serde(default)]
    pub format: Option<String>,
    /// Branch to read from (default: main).
    #[serde(default = "default_branch")]
    pub branch: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct BranchQuery {
    /// Branch to operate on (default: main).
    #[serde(default = "default_branch")]
    pub branch: String,
}

fn default_branch() -> String {
    "main".to_string()
}

// --- Handlers

/// GET /v1/sessions/:id/files/*path
///
/// Reads a file from the session's virtual filesystem by replaying the
/// manifest from journal events and fetching the blob from the store.
///
/// Supports `?format=hashline` to return content in hashline format
/// (`N:HHHH|content` per line) with `x-format: hashline` header.
pub async fn read_file(
    State(state): State<Arc<AppState>>,
    Path((session_id, file_path)): Path<(String, String)>,
    Query(query): Query<FileReadQuery>,
) -> Result<axum::http::Response<axum::body::Body>, ApiError> {
    let session_id = SessionId::from_string(session_id.clone());
    let branch_id = BranchId::from_string(query.branch.clone());
    let file_path = normalize_path(&file_path);

    // Verify session exists
    state
        .journal
        .get_session(&session_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("session not found: {session_id}")))?;

    // Build manifest from events
    let manifest = build_manifest(&state, &session_id, &branch_id).await?;

    let entry = manifest
        .iter()
        .find(|e| e.path == file_path)
        .ok_or_else(|| ApiError::NotFound(format!("file not found: {file_path}")))?;

    let data = state
        .blob_store
        .get(&entry.blob_hash)
        .map_err(|e| ApiError::Internal(format!("failed to read blob: {e}")))?;

    // If hashline format requested, convert
    if query.format.as_deref() == Some("hashline") {
        let text = String::from_utf8(data)
            .map_err(|_| ApiError::BadRequest("file is not valid UTF-8".to_string()))?;
        let hashline_file = HashLineFile::from_content(&text);
        let hashline_text = hashline_file.to_hashline_text();

        return Ok(axum::http::Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .header("x-format", "hashline")
            .header("x-blob-hash", entry.blob_hash.as_str())
            .body(axum::body::Body::from(hashline_text))
            .unwrap());
    }

    let content_type = entry
        .content_type
        .clone()
        .unwrap_or_else(|| "application/octet-stream".to_string());

    Ok(axum::http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", content_type)
        .header("x-blob-hash", entry.blob_hash.as_str())
        .body(axum::body::Body::from(data))
        .unwrap())
}

/// PATCH /v1/sessions/:id/files/*path
///
/// Applies hashline edits to a file. Accepts a JSON array of `HashLineEdit`
/// operations, applies them to the current file content, stores the result
/// as a new blob, and emits a `FileWrite` event.
pub async fn patch_file(
    State(state): State<Arc<AppState>>,
    Path((session_id, file_path)): Path<(String, String)>,
    Query(branch): Query<BranchQuery>,
    Json(edits): Json<Vec<HashLineEdit>>,
) -> Result<(StatusCode, Json<FileWriteResponse>), ApiError> {
    let session_id = SessionId::from_string(session_id.clone());
    let branch_id = BranchId::from_string(branch.branch);
    let file_path = normalize_path(&file_path);

    // Verify session exists
    state
        .journal
        .get_session(&session_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("session not found: {session_id}")))?;

    // Build manifest and read current file
    let manifest = build_manifest(&state, &session_id, &branch_id).await?;
    let entry = manifest
        .iter()
        .find(|e| e.path == file_path)
        .ok_or_else(|| ApiError::NotFound(format!("file not found: {file_path}")))?;

    let data = state
        .blob_store
        .get(&entry.blob_hash)
        .map_err(|e| ApiError::Internal(format!("failed to read blob: {e}")))?;

    let text = String::from_utf8(data)
        .map_err(|_| ApiError::BadRequest("file is not valid UTF-8".to_string()))?;

    // Apply hashline edits
    let hashline_file = HashLineFile::from_content(&text);
    let new_content = hashline_file
        .apply_edits(&edits)
        .map_err(lago_core::LagoError::from)?;

    // Store new blob
    let blob_hash = state
        .blob_store
        .put(new_content.as_bytes())
        .map_err(|e| ApiError::Internal(format!("failed to store blob: {e}")))?;

    let size_bytes = new_content.len() as u64;

    // Emit a FileWrite event
    let event = EventEnvelope {
        event_id: EventId::new(),
        session_id: session_id.clone(),
        branch_id,
        run_id: None,
        seq: 0,
        timestamp: EventEnvelope::now_micros(),
        parent_id: None,
        payload: EventPayload::FileWrite {
            path: file_path.clone(),
            blob_hash: blob_hash.clone().into(),
            size_bytes,
            content_type: None,
        },
        metadata: HashMap::new(),
        schema_version: 1,
    };

    state.journal.append(event).await?;

    Ok((
        StatusCode::OK,
        Json(FileWriteResponse {
            path: file_path,
            blob_hash: blob_hash.to_string(),
            size_bytes,
        }),
    ))
}

/// PUT /v1/sessions/:id/files/*path
///
/// Writes a file to the session's virtual filesystem. The file contents are
/// stored as a blob and a `FileWrite` event is appended to the journal.
pub async fn write_file(
    State(state): State<Arc<AppState>>,
    Path((session_id, file_path)): Path<(String, String)>,
    Query(branch): Query<BranchQuery>,
    body: Bytes,
) -> Result<(StatusCode, Json<FileWriteResponse>), ApiError> {
    let session_id = SessionId::from_string(session_id.clone());
    let branch_id = BranchId::from_string(branch.branch);
    let file_path = normalize_path(&file_path);

    // Verify session exists
    state
        .journal
        .get_session(&session_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("session not found: {session_id}")))?;

    // Store the blob
    let blob_hash = state
        .blob_store
        .put(&body)
        .map_err(|e| ApiError::Internal(format!("failed to store blob: {e}")))?;

    let size_bytes = body.len() as u64;

    // Emit a FileWrite event
    let event = EventEnvelope {
        event_id: EventId::new(),
        session_id: session_id.clone(),
        branch_id,
        run_id: None,
        seq: 0,
        timestamp: EventEnvelope::now_micros(),
        parent_id: None,
        payload: EventPayload::FileWrite {
            path: file_path.clone(),
            blob_hash: blob_hash.clone().into(),
            size_bytes,
            content_type: None,
        },
        metadata: HashMap::new(),
        schema_version: 1,
    };

    state.journal.append(event).await?;

    Ok((
        StatusCode::CREATED,
        Json(FileWriteResponse {
            path: file_path,
            blob_hash: blob_hash.to_string(),
            size_bytes,
        }),
    ))
}

/// DELETE /v1/sessions/:id/files/*path
///
/// Removes a file from the session's virtual filesystem by appending a
/// `FileDelete` event.
pub async fn delete_file(
    State(state): State<Arc<AppState>>,
    Path((session_id, file_path)): Path<(String, String)>,
    Query(branch): Query<BranchQuery>,
) -> Result<StatusCode, ApiError> {
    let session_id = SessionId::from_string(session_id.clone());
    let branch_id = BranchId::from_string(branch.branch);
    let file_path = normalize_path(&file_path);

    // Verify session exists
    state
        .journal
        .get_session(&session_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("session not found: {session_id}")))?;

    let event = EventEnvelope {
        event_id: EventId::new(),
        session_id: session_id.clone(),
        branch_id,
        run_id: None,
        seq: 0,
        timestamp: EventEnvelope::now_micros(),
        parent_id: None,
        payload: EventPayload::FileDelete {
            path: file_path.clone(),
        },
        metadata: HashMap::new(),
        schema_version: 1,
    };

    state.journal.append(event).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// GET /v1/sessions/:id/manifest
///
/// Returns the full manifest (list of all files) for a session by replaying
/// file events from the journal.
pub async fn get_manifest(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Query(branch): Query<BranchQuery>,
) -> Result<Json<ManifestResponse>, ApiError> {
    let session_id = SessionId::from_string(session_id.clone());
    let branch_id = BranchId::from_string(branch.branch);

    // Verify session exists
    state
        .journal
        .get_session(&session_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("session not found: {session_id}")))?;

    let entries = build_manifest(&state, &session_id, &branch_id).await?;

    Ok(Json(ManifestResponse {
        session_id: session_id.to_string(),
        entries,
    }))
}

// --- Internal helpers

/// Build a manifest by replaying file events from the journal.
async fn build_manifest(
    state: &Arc<AppState>,
    session_id: &SessionId,
    branch_id: &BranchId,
) -> Result<Vec<ManifestEntry>, ApiError> {
    let query = EventQuery::new()
        .session(session_id.clone())
        .branch(branch_id.clone());
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
                // Convert aios_protocol::BlobHash -> lago_core::BlobHash
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

    let entries: Vec<ManifestEntry> = manifest.entries().values().cloned().collect();

    Ok(entries)
}

/// Ensure the path starts with '/' for consistency.
fn normalize_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}
