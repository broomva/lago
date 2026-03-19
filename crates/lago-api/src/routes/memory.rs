//! Auth-protected memory endpoints scoped to the user's Lago session.
//!
//! These routes provide the HTTP API for the context engine: file CRUD,
//! server-side scored search, wikilink resolution, and graph traversal.

use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use lago_auth::UserContext;
use lago_core::ManifestEntry;
use lago_knowledge::{KnowledgeIndex, SearchResult, TraversalResult};

use crate::error::ApiError;
use crate::state::AppState;

// Re-use the file helpers from the files module
use super::files::{FileWriteResponse, ManifestResponse};

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SearchRequest {
    pub query: String,
    #[serde(default = "default_max_results")]
    pub max_results: usize,
    #[serde(default)]
    pub follow_links: bool,
}

fn default_max_results() -> usize {
    10
}

#[derive(Serialize)]
pub struct SearchResponse {
    pub results: Vec<SearchResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linked_notes: Option<Vec<LinkedNote>>,
}

#[derive(Serialize)]
pub struct LinkedNote {
    pub path: String,
    pub name: String,
    pub depth: usize,
    pub links: Vec<String>,
}

#[derive(Deserialize)]
pub struct TraverseRequest {
    pub target: String,
    #[serde(default = "default_depth")]
    pub depth: usize,
    #[serde(default = "default_max_notes")]
    pub max_notes: usize,
}

fn default_depth() -> usize {
    1
}

fn default_max_notes() -> usize {
    15
}

#[derive(Serialize)]
pub struct TraverseResponse {
    pub notes: Vec<TraversalResult>,
}

#[derive(Serialize)]
pub struct NoteResponse {
    pub path: String,
    pub name: String,
    #[serde(with = "yaml_as_json")]
    pub frontmatter: serde_yaml::Value,
    pub body: String,
    pub links: Vec<String>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a manifest for the user's vault session.
async fn user_manifest(
    state: &Arc<AppState>,
    user: &UserContext,
) -> Result<Vec<ManifestEntry>, ApiError> {
    let session_id = &user.lago_session_id;
    let branch_id = lago_core::BranchId::from_string("main".to_string());

    let query = lago_core::EventQuery::new()
        .session(session_id.clone())
        .branch(branch_id);
    let events = state.journal.read(query).await?;

    let mut manifest = lago_fs::Manifest::new();
    for event in &events {
        match &event.payload {
            lago_core::EventPayload::FileWrite {
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
            lago_core::EventPayload::FileDelete { path } => {
                manifest.apply_delete(path);
            }
            lago_core::EventPayload::FileRename { old_path, new_path } => {
                manifest.apply_rename(old_path, new_path.clone());
            }
            _ => {}
        }
    }

    Ok(manifest.entries().values().cloned().collect())
}

/// Build a knowledge index for the user's vault, with 30s TTL caching.
fn build_knowledge_index(
    manifest: &[ManifestEntry],
    state: &Arc<AppState>,
) -> Result<KnowledgeIndex, ApiError> {
    KnowledgeIndex::build(manifest, &state.blob_store)
        .map_err(|e| ApiError::Internal(format!("failed to build knowledge index: {e}")))
}

/// Ensure the path starts with '/'.
fn normalize_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /v1/memory/manifest — list all files in the user's vault.
pub async fn get_manifest(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<UserContext>,
) -> Result<Json<ManifestResponse>, ApiError> {
    let entries = user_manifest(&state, &user).await?;

    Ok(Json(ManifestResponse {
        session_id: user.lago_session_id.to_string(),
        entries,
    }))
}

/// GET /v1/memory/files/{*path} — read a file from the user's vault.
pub async fn read_file(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<UserContext>,
    Path(file_path): Path<String>,
) -> Result<axum::http::Response<axum::body::Body>, ApiError> {
    let file_path = normalize_path(&file_path);
    let manifest = user_manifest(&state, &user).await?;

    let entry = manifest
        .iter()
        .find(|e| e.path == file_path)
        .ok_or_else(|| ApiError::NotFound(format!("file not found: {file_path}")))?;

    let data = state
        .blob_store
        .get(&entry.blob_hash)
        .map_err(|e| ApiError::Internal(format!("failed to read blob: {e}")))?;

    let content_type = entry
        .content_type
        .clone()
        .unwrap_or_else(|| "text/markdown".to_string());

    Ok(axum::http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", content_type)
        .header("x-blob-hash", entry.blob_hash.as_str())
        .body(axum::body::Body::from(data))
        .unwrap())
}

/// PUT /v1/memory/files/{*path} — write a file to the user's vault.
pub async fn write_file(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<UserContext>,
    Path(file_path): Path<String>,
    body: Bytes,
) -> Result<(StatusCode, Json<FileWriteResponse>), ApiError> {
    let file_path = normalize_path(&file_path);
    let session_id = user.lago_session_id.clone();
    let branch_id = lago_core::BranchId::from_string("main".to_string());

    let blob_hash = state
        .blob_store
        .put(&body)
        .map_err(|e| ApiError::Internal(format!("failed to store blob: {e}")))?;

    let size_bytes = body.len() as u64;

    let event = lago_core::event::EventEnvelope {
        event_id: lago_core::EventId::new(),
        session_id,
        branch_id,
        run_id: None,
        seq: 0,
        timestamp: lago_core::event::EventEnvelope::now_micros(),
        parent_id: None,
        payload: lago_core::EventPayload::FileWrite {
            path: file_path.clone(),
            blob_hash: blob_hash.clone().into(),
            size_bytes,
            content_type: Some("text/markdown".to_string()),
        },
        metadata: std::collections::HashMap::new(),
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

/// DELETE /v1/memory/files/{*path} — delete a file from the user's vault.
pub async fn delete_file(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<UserContext>,
    Path(file_path): Path<String>,
) -> Result<StatusCode, ApiError> {
    let file_path = normalize_path(&file_path);
    let session_id = user.lago_session_id.clone();
    let branch_id = lago_core::BranchId::from_string("main".to_string());

    let event = lago_core::event::EventEnvelope {
        event_id: lago_core::EventId::new(),
        session_id,
        branch_id,
        run_id: None,
        seq: 0,
        timestamp: lago_core::event::EventEnvelope::now_micros(),
        parent_id: None,
        payload: lago_core::EventPayload::FileDelete { path: file_path },
        metadata: std::collections::HashMap::new(),
        schema_version: 1,
    };

    state.journal.append(event).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// POST /v1/memory/search — search with scoring + optional graph traversal.
pub async fn search(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<UserContext>,
    Json(body): Json<SearchRequest>,
) -> Result<Json<SearchResponse>, ApiError> {
    let manifest = user_manifest(&state, &user).await?;
    let index = build_knowledge_index(&manifest, &state)?;

    let results = index.search(&body.query, body.max_results);

    let linked_notes = if body.follow_links && !results.is_empty() {
        // Collect unique wikilink targets from top results
        let mut seen_paths: std::collections::HashSet<String> =
            results.iter().map(|r| r.path.clone()).collect();

        let mut linked = Vec::new();
        for result in &results {
            for link in &result.links {
                if let Some(note) = index.resolve_wikilink(link) {
                    if seen_paths.insert(note.path.clone()) {
                        linked.push(LinkedNote {
                            path: note.path.clone(),
                            name: note.name.clone(),
                            depth: 1,
                            links: note.links.clone(),
                        });
                    }
                }
                if linked.len() >= 10 {
                    break;
                }
            }
        }

        if linked.is_empty() {
            None
        } else {
            Some(linked)
        }
    } else {
        None
    };

    Ok(Json(SearchResponse {
        results,
        linked_notes,
    }))
}

/// POST /v1/memory/traverse — BFS graph traversal from a note.
pub async fn traverse(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<UserContext>,
    Json(body): Json<TraverseRequest>,
) -> Result<Json<TraverseResponse>, ApiError> {
    let manifest = user_manifest(&state, &user).await?;
    let index = build_knowledge_index(&manifest, &state)?;

    let notes = index.traverse(&body.target, body.depth, body.max_notes);

    Ok(Json(TraverseResponse { notes }))
}

/// GET /v1/memory/note/{name} — resolve a wikilink to a full note.
pub async fn read_note(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<UserContext>,
    Path(name): Path<String>,
) -> Result<Json<NoteResponse>, ApiError> {
    let manifest = user_manifest(&state, &user).await?;
    let index = build_knowledge_index(&manifest, &state)?;

    let note = index
        .resolve_wikilink(&name)
        .ok_or_else(|| ApiError::NotFound(format!("note not found: {name}")))?;

    Ok(Json(NoteResponse {
        path: note.path.clone(),
        name: note.name.clone(),
        frontmatter: note.frontmatter.clone(),
        body: note.body.clone(),
        links: note.links.clone(),
    }))
}

// ---------------------------------------------------------------------------
// Serde helper for YAML → JSON serialization
// ---------------------------------------------------------------------------

mod yaml_as_json {
    use serde::{Serialize, Serializer};

    pub fn serialize<S>(value: &serde_yaml::Value, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let json = yaml_to_json(value);
        json.serialize(serializer)
    }

    fn yaml_to_json(value: &serde_yaml::Value) -> serde_json::Value {
        match value {
            serde_yaml::Value::Null => serde_json::Value::Null,
            serde_yaml::Value::Bool(b) => serde_json::Value::Bool(*b),
            serde_yaml::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    serde_json::Value::Number(i.into())
                } else if let Some(f) = n.as_f64() {
                    serde_json::json!(f)
                } else {
                    serde_json::Value::Null
                }
            }
            serde_yaml::Value::String(s) => serde_json::Value::String(s.clone()),
            serde_yaml::Value::Sequence(seq) => {
                serde_json::Value::Array(seq.iter().map(yaml_to_json).collect())
            }
            serde_yaml::Value::Mapping(map) => {
                let mut obj = serde_json::Map::new();
                for (k, v) in map {
                    let key = match k {
                        serde_yaml::Value::String(s) => s.clone(),
                        _ => format!("{k:?}"),
                    };
                    obj.insert(key, yaml_to_json(v));
                }
                serde_json::Value::Object(obj)
            }
            serde_yaml::Value::Tagged(tagged) => yaml_to_json(&tagged.value),
        }
    }
}
