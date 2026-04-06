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

// --- Range request parsing

/// Parsed byte range from a `Range: bytes=START-END` header.
struct ByteRange {
    start: u64,
    end: u64, // inclusive
}

/// Parse a simple `Range: bytes=START-END` header.
/// Supports: `bytes=0-499`, `bytes=500-`, `bytes=-500` (suffix).
/// Only handles a single range (not multi-range).
fn parse_range(header: &str, total: u64) -> Option<ByteRange> {
    let spec = header.strip_prefix("bytes=")?;

    // Reject multi-range
    if spec.contains(',') {
        return None;
    }

    let (start_str, end_str) = spec.split_once('-')?;

    if start_str.is_empty() {
        // Suffix range: bytes=-500 → last 500 bytes
        let suffix_len: u64 = end_str.parse().ok()?;
        if suffix_len == 0 || suffix_len > total {
            return None;
        }
        Some(ByteRange {
            start: total - suffix_len,
            end: total - 1,
        })
    } else {
        let start: u64 = start_str.parse().ok()?;
        let end = if end_str.is_empty() {
            total - 1
        } else {
            end_str.parse::<u64>().ok()?.min(total - 1)
        };
        if start > end || start >= total {
            return None;
        }
        Some(ByteRange { start, end })
    }
}

// --- Handlers

/// GET /v1/blobs/:hash
///
/// Returns the raw blob data with inferred content-type, caching headers,
/// and Range request support (206 Partial Content).
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
    let hdrs = response.headers_mut();
    hdrs.insert("access-control-allow-origin", "*".parse().unwrap());
    hdrs.insert(
        "access-control-expose-headers",
        "Content-Range, Accept-Ranges, Content-Length"
            .parse()
            .unwrap(),
    );
    Ok(response)
}

/// Shared blob serving logic with content-type inference, caching headers,
/// and HTTP Range support for media streaming.
fn serve_blob(
    state: &AppState,
    hash_hex: &str,
    ct_override: Option<&str>,
    headers: &HeaderMap,
) -> Result<axum::http::Response<axum::body::Body>, ApiError> {
    let blob_hash = BlobHash::from_hex(hash_hex);

    // ETag-based conditional request: If-None-Match → 304
    if let Some(etag) = headers.get("if-none-match")
        && let Ok(etag_str) = etag.to_str()
    {
        let etag_clean = etag_str.trim_matches('"');
        if etag_clean == blob_hash.as_str() {
            return Ok(axum::http::Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header("etag", format!("\"{}\"", blob_hash.as_str()))
                .header("cache-control", "public, max-age=31536000, immutable")
                .header("accept-ranges", "bytes")
                .body(axum::body::Body::empty())
                .unwrap());
        }
    }

    let data = state.blob_store.get(&blob_hash).map_err(|e| match e {
        lago_core::LagoError::BlobNotFound(h) => ApiError::NotFound(format!("blob not found: {h}")),
        other => ApiError::Internal(format!("failed to read blob: {other}")),
    })?;

    let total_size = data.len() as u64;
    let content_type = infer_content_type(&data, ct_override);

    // Check for Range header → serve partial content
    if let Some(range_header) = headers.get("range")
        && let Ok(range_str) = range_header.to_str()
    {
        if let Some(range) = parse_range(range_str, total_size) {
            let start = range.start as usize;
            let end = range.end as usize;
            let slice = &data[start..=end];
            let content_length = slice.len() as u64;

            return Ok(axum::http::Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .header("content-type", &content_type)
                .header("content-length", content_length.to_string())
                .header(
                    "content-range",
                    format!("bytes {}-{}/{}", range.start, range.end, total_size),
                )
                .header("accept-ranges", "bytes")
                .header("x-blob-hash", blob_hash.as_str())
                .header("etag", format!("\"{}\"", blob_hash.as_str()))
                .header("cache-control", "public, max-age=31536000, immutable")
                .body(axum::body::Body::from(slice.to_vec()))
                .unwrap());
        } else {
            // Invalid range → 416 Range Not Satisfiable
            return Ok(axum::http::Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header("content-range", format!("bytes */{total_size}"))
                .header("accept-ranges", "bytes")
                .body(axum::body::Body::empty())
                .unwrap());
        }
    }

    // Full response with Content-Length and Accept-Ranges
    Ok(axum::http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", &content_type)
        .header("content-length", total_size.to_string())
        .header("accept-ranges", "bytes")
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
