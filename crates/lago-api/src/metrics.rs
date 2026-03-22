//! Prometheus metrics for the Lago API.
//!
//! Defines named metrics and an axum middleware layer that records
//! per-request counters and latency histograms automatically.

use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use metrics::{counter, gauge, histogram};

use crate::state::AppState;

// ---------------------------------------------------------------------------
// Metric name constants
// ---------------------------------------------------------------------------

/// Total blob operations (get + put).
pub const BLOBS_TOTAL: &str = "lago_blobs_total";

/// Total events appended to the journal.
pub const JOURNAL_EVENTS_TOTAL: &str = "lago_journal_events_total";

/// Total HTTP requests (labelled by method, path, status).
pub const HTTP_REQUESTS_TOTAL: &str = "lago_http_requests_total";

/// HTTP request duration in seconds (histogram).
pub const HTTP_REQUEST_DURATION_SECONDS: &str = "lago_http_request_duration_seconds";

/// Number of currently active sessions.
pub const ACTIVE_SESSIONS: &str = "lago_active_sessions";

// ---------------------------------------------------------------------------
// Convenience helpers for application code
// ---------------------------------------------------------------------------

/// Increment the blob operations counter.
pub fn record_blob_operation(op: &str) {
    counter!(BLOBS_TOTAL, "operation" => op.to_owned()).increment(1);
}

/// Increment the journal events counter.
pub fn record_journal_event(kind: &str) {
    counter!(JOURNAL_EVENTS_TOTAL, "kind" => kind.to_owned()).increment(1);
}

/// Set the active sessions gauge to the given value.
pub fn set_active_sessions(count: u64) {
    gauge!(ACTIVE_SESSIONS).set(count as f64);
}

// ---------------------------------------------------------------------------
// Axum middleware — records request count + latency
// ---------------------------------------------------------------------------

/// Middleware that records `lago_http_requests_total` and
/// `lago_http_request_duration_seconds` for every request.
pub async fn http_metrics_middleware(
    State(_state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_owned();
    let start = Instant::now();

    let response = next.run(req).await;

    let status = response.status().as_u16().to_string();
    let duration = start.elapsed().as_secs_f64();

    counter!(
        HTTP_REQUESTS_TOTAL,
        "method" => method.clone(),
        "path" => path.clone(),
        "status" => status.clone(),
    )
    .increment(1);

    histogram!(
        HTTP_REQUEST_DURATION_SECONDS,
        "method" => method,
        "path" => path,
        "status" => status,
    )
    .record(duration);

    response
}
