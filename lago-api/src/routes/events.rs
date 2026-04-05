use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::http::{HeaderName, HeaderValue};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

use lago_core::EventQuery;
use lago_core::event::EventEnvelope;
use lago_core::id::{BranchId, SeqNo, SessionId};

use crate::error::ApiError;
use crate::sse::format::{SseFormat, SseFrame};
use crate::sse::{anthropic, lago, openai, vercel};
use crate::state::AppState;

// --- Query params

#[derive(Deserialize, Default)]
pub struct EventStreamQuery {
    /// Output format: openai, anthropic, vercel, or lago (default).
    #[serde(default = "default_format")]
    pub format: String,
    /// Only return events after this sequence number.
    pub after_seq: Option<SeqNo>,
    /// Branch name (default: "main").
    #[serde(default = "default_branch")]
    pub branch: String,
}

fn default_format() -> String {
    "lago".to_string()
}

fn default_branch() -> String {
    "main".to_string()
}

/// Resolve the SSE format adapter from the query parameter string.
fn resolve_format(name: &str) -> Result<Arc<dyn SseFormat>, ApiError> {
    match name {
        "openai" => Ok(Arc::new(openai::OpenAiFormat)),
        "anthropic" => Ok(Arc::new(anthropic::AnthropicFormat)),
        "vercel" => Ok(Arc::new(vercel::VercelFormat)),
        "lago" | "" => Ok(Arc::new(lago::LagoFormat)),
        other => Err(ApiError::BadRequest(format!(
            "unknown format: {other}. Supported: openai, anthropic, vercel, lago"
        ))),
    }
}

/// Parse the `Last-Event-ID` header to determine where to resume streaming.
fn parse_last_event_id(headers: &HeaderMap) -> Option<SeqNo> {
    headers
        .get("Last-Event-ID")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<SeqNo>().ok())
}

/// Convert an `SseFrame` into an axum `SseEvent`.
fn frame_to_sse_event(frame: SseFrame) -> SseEvent {
    let mut event = SseEvent::default().data(frame.data);
    if let Some(name) = frame.event {
        event = event.event(name);
    }
    if let Some(id) = frame.id {
        event = event.id(id);
    }
    event
}

// ─── Request / response types for write endpoints ─────────────────────────

#[derive(Deserialize)]
pub struct AppendEventRequest {
    pub event: EventEnvelope,
}

#[derive(Serialize)]
pub struct AppendEventResponse {
    pub seq: SeqNo,
}

#[derive(Deserialize, Default)]
pub struct ReadEventsQuery {
    #[serde(default = "default_branch")]
    pub branch: String,
    #[serde(default)]
    pub after_seq: SeqNo,
    pub limit: Option<usize>,
}

#[derive(Deserialize, Default)]
pub struct HeadQuery {
    #[serde(default = "default_branch")]
    pub branch: String,
}

#[derive(Serialize)]
pub struct HeadSeqResponse {
    pub seq: SeqNo,
}

// ─── POST /v1/sessions/:id/events ─────────────────────────────────────────

/// POST /v1/sessions/:id/events
///
/// Append a single event to the journal. The `seq` field in the request body
/// is ignored — the journal assigns a monotonically increasing sequence number.
/// Returns `{ seq }` with the assigned sequence.
pub async fn append_event(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Json(body): Json<AppendEventRequest>,
) -> Result<Json<AppendEventResponse>, ApiError> {
    let mut event = body.event;
    // Ensure session_id on the envelope matches the path parameter.
    event.session_id = SessionId::from_string(session_id);
    let seq = state.journal.append(event).await?;
    Ok(Json(AppendEventResponse { seq }))
}

// ─── GET /v1/sessions/:id/events/read ─────────────────────────────────────

/// GET /v1/sessions/:id/events/read?branch=main&after_seq=0&limit=100
///
/// Batch-read events from the journal. Unlike the SSE stream endpoint this
/// returns immediately with the current events — it does not tail.
pub async fn read_events(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Query(query): Query<ReadEventsQuery>,
) -> Result<Json<Vec<EventEnvelope>>, ApiError> {
    let session_id = SessionId::from_string(session_id);
    let branch_id = BranchId::from_string(query.branch);

    let mut q = EventQuery::new()
        .session(session_id)
        .branch(branch_id)
        .after(query.after_seq.saturating_sub(1));
    if let Some(limit) = query.limit {
        q = q.limit(limit);
    }

    let events = state.journal.read(q).await?;
    Ok(Json(events))
}

// ─── GET /v1/sessions/:id/events/head ─────────────────────────────────────

/// GET /v1/sessions/:id/events/head?branch=main
///
/// Returns the current head sequence number for a session+branch.
/// Returns `{ seq: 0 }` if the session has no events yet.
pub async fn head_seq(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Query(query): Query<HeadQuery>,
) -> Result<Json<HeadSeqResponse>, ApiError> {
    let session_id = SessionId::from_string(session_id);
    let branch_id = BranchId::from_string(query.branch);
    let seq = state.journal.head_seq(&session_id, &branch_id).await?;
    Ok(Json(HeadSeqResponse { seq }))
}

// ─── SSE stream ───────────────────────────────────────────────────────────

/// GET /v1/sessions/:id/events
///
/// Streams events for a session in the requested format using Server-Sent Events.
/// Supports reconnection via the `Last-Event-ID` header and keep-alive pings
/// every 15 seconds.
#[instrument(skip(state, query, headers), fields(lago.stream_id = %session_id))]
pub async fn stream_events(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Query(query): Query<EventStreamQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let session_id = SessionId::from_string(session_id);
    let branch_id = BranchId::from_string(query.branch.clone());
    let format = resolve_format(&query.format)?;

    // Determine the starting sequence number. The `Last-Event-ID` header takes
    // precedence, falling back to the `after_seq` query parameter, and finally
    // defaulting to 0 (stream from the beginning).
    let after_seq = parse_last_event_id(&headers)
        .or(query.after_seq)
        .unwrap_or(0);

    debug!(
        session = %session_id,
        branch = %branch_id,
        after_seq = after_seq,
        format = format.name(),
        "starting SSE event stream"
    );

    // Verify session exists
    state
        .journal
        .get_session(&session_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("session not found: {session_id}")))?;

    // Open a tailing event stream from the journal
    let event_stream = state
        .journal
        .stream(session_id, branch_id, after_seq)
        .await?;

    // Map journal events through the format adapter, producing SSE frames.
    // The format Arc is cloned for each item so the closure is 'static + Send.
    let format_for_stream = Arc::clone(&format);
    let sse_stream = event_stream.filter_map(move |result| {
        let format = Arc::clone(&format_for_stream);
        async move {
            match result {
                Ok(envelope) => {
                    let frames = format.format(&envelope);
                    if frames.is_empty() {
                        None
                    } else {
                        let events: Vec<SseEvent> =
                            frames.into_iter().map(frame_to_sse_event).collect();
                        Some(events)
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "error reading event from journal stream");
                    None
                }
            }
        }
    });

    // Flatten: each envelope may produce multiple SSE events
    let flat_stream = sse_stream
        .flat_map(futures::stream::iter)
        .map(Ok::<_, Infallible>);

    let combined_stream: futures::stream::BoxStream<'static, Result<SseEvent, Infallible>> =
        if let Some(done_frame) = format.done_frame() {
            flat_stream
                .chain(futures::stream::once(async move {
                    Ok::<_, Infallible>(frame_to_sse_event(done_frame))
                }))
                .boxed()
        } else {
            flat_stream.boxed()
        };

    let sse = Sse::new(combined_stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("ping"),
    );
    let mut response = sse.into_response();
    for (name, value) in format.extra_headers() {
        if let (Ok(header_name), Ok(header_value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            response.headers_mut().insert(header_name, header_value);
        }
    }

    Ok(response)
}
