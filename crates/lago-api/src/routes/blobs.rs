use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Serialize;

use lago_core::id::BlobHash;

use crate::error::ApiError;
use crate::state::AppState;

// --- Response types

#[derive(Serialize)]
pub struct BlobPutResponse {
    pub hash: String,
    pub size_bytes: u64,
}

// --- Handlers

/// GET /v1/blobs/:hash
///
/// Returns the raw blob data for the given content hash.
pub async fn get_blob(
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
) -> Result<axum::http::Response<axum::body::Body>, ApiError> {
    let blob_hash = BlobHash::from_hex(hash);

    let data = state.blob_store.get(&blob_hash).map_err(|e| match e {
        lago_core::LagoError::BlobNotFound(h) => ApiError::NotFound(format!("blob not found: {h}")),
        other => ApiError::Internal(format!("failed to read blob: {other}")),
    })?;

    Ok(axum::http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .header("x-blob-hash", blob_hash.as_str())
        .body(axum::body::Body::from(data))
        .unwrap())
}

/// PUT /v1/blobs/:hash
///
/// Stores a blob at the given content hash. The server verifies the hash
/// matches the uploaded content.
pub async fn put_blob(
    State(state): State<Arc<AppState>>,
    Path(expected_hash): Path<String>,
    body: Bytes,
) -> Result<(StatusCode, axum::Json<BlobPutResponse>), ApiError> {
    let blob_hash = state
        .blob_store
        .put(&body)
        .map_err(|e| ApiError::Internal(format!("failed to store blob: {e}")))?;

    // Verify the uploaded content matches the expected hash
    if blob_hash.as_str() != expected_hash {
        return Err(ApiError::BadRequest(format!(
            "hash mismatch: expected {expected_hash}, got {blob_hash}"
        )));
    }

    Ok((
        StatusCode::CREATED,
        axum::Json(BlobPutResponse {
            hash: blob_hash.to_string(),
            size_bytes: body.len() as u64,
        }),
    ))
}
