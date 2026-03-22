use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};

use lago_core::id::BlobHash;

use crate::error::ApiError;
use crate::state::AppState;

// --- Response types

#[derive(Serialize)]
pub struct BlobPutResponse {
    pub hash: String,
    pub size_bytes: u64,
}

/// Query parameters for blob GET requests.
#[derive(Deserialize, Default)]
pub struct BlobQueryParams {
    /// Override content-type (e.g., `?ct=image/png`).
    pub ct: Option<String>,
}

// --- Content-type inference

/// Infer MIME type from raw bytes using magic byte detection,
/// with an optional query-param override.
fn infer_content_type(data: &[u8], ct_override: Option<&str>) -> String {
    if let Some(ct) = ct_override {
        return ct.to_string();
    }
    infer::get(data)
        .map(|kind| kind.mime_type().to_string())
        .unwrap_or_else(|| "application/octet-stream".to_string())
}

// --- Handlers

/// GET /v1/blobs/:hash
///
/// Returns the raw blob data with inferred content-type and caching headers.
pub async fn get_blob(
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
    Query(params): Query<BlobQueryParams>,
    headers: HeaderMap,
) -> Result<axum::http::Response<axum::body::Body>, ApiError> {
    serve_blob(&state, &hash, params.ct.as_deref(), &headers)
}

/// GET /v1/public/blobs/:hash
///
/// Unauthenticated public blob access with CORS headers.
pub async fn get_public_blob(
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
    Query(params): Query<BlobQueryParams>,
    headers: HeaderMap,
) -> Result<axum::http::Response<axum::body::Body>, ApiError> {
    let mut response = serve_blob(&state, &hash, params.ct.as_deref(), &headers)?;
    // Ensure CORS headers for cross-origin embedding
    response
        .headers_mut()
        .insert("access-control-allow-origin", "*".parse().unwrap());
    Ok(response)
}

/// Shared blob serving logic with content-type inference and caching headers.
fn serve_blob(
    state: &AppState,
    hash_hex: &str,
    ct_override: Option<&str>,
    headers: &HeaderMap,
) -> Result<axum::http::Response<axum::body::Body>, ApiError> {
    let blob_hash = BlobHash::from_hex(hash_hex);

    // ETag-based conditional request: If-None-Match → 304
    if let Some(etag) = headers.get("if-none-match") {
        if let Ok(etag_str) = etag.to_str() {
            let etag_clean = etag_str.trim_matches('"');
            if etag_clean == blob_hash.as_str() {
                return Ok(axum::http::Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .header("etag", format!("\"{}\"", blob_hash.as_str()))
                    .header("cache-control", "public, max-age=31536000, immutable")
                    .body(axum::body::Body::empty())
                    .unwrap());
            }
        }
    }

    let data = state.blob_store.get(&blob_hash).map_err(|e| match e {
        lago_core::LagoError::BlobNotFound(h) => ApiError::NotFound(format!("blob not found: {h}")),
        other => ApiError::Internal(format!("failed to read blob: {other}")),
    })?;

    let content_type = infer_content_type(&data, ct_override);

    Ok(axum::http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", &content_type)
        .header("x-blob-hash", blob_hash.as_str())
        .header("etag", format!("\"{}\"", blob_hash.as_str()))
        .header("cache-control", "public, max-age=31536000, immutable")
        .body(axum::body::Body::from(data))
        .unwrap())
}

// --- Upload validation (SEC-2)

/// Maximum upload size per blob (512 MB).
const MAX_BLOB_SIZE: usize = 512 * 1024 * 1024;

/// MIME types that are never allowed to be uploaded.
const BLOCKED_MIME_TYPES: &[&str] = &[
    "application/x-executable",
    "application/x-mach-binary",
    "application/x-elf",
    "application/x-dosexec",
    "application/x-sharedlib",
    "application/vnd.microsoft.portable-executable",
];

/// PUT /v1/blobs/:hash
///
/// Stores a blob at the given content hash. The server verifies the hash
/// matches the uploaded content. Validates size and content-type.
pub async fn put_blob(
    State(state): State<Arc<AppState>>,
    Path(expected_hash): Path<String>,
    body: Bytes,
) -> Result<(StatusCode, axum::Json<BlobPutResponse>), ApiError> {
    // Size validation
    if body.len() > MAX_BLOB_SIZE {
        return Err(ApiError::BadRequest(format!(
            "blob too large: {} bytes (max {})",
            body.len(),
            MAX_BLOB_SIZE
        )));
    }

    // Content-type validation via magic bytes — reject executables/scripts
    if let Some(kind) = infer::get(&body) {
        let mime = kind.mime_type();
        if BLOCKED_MIME_TYPES.contains(&mime) {
            return Err(ApiError::BadRequest(format!(
                "content type not allowed: {mime}"
            )));
        }
    }

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
