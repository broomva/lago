//! End-to-end integration tests for session lifecycle, event ingestion,
//! SSE streaming, and branch management through the lago-api HTTP layer.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use lago_api::build_router;
use lago_api::state::AppState;
use lago_core::{BranchId, EventEnvelope, EventId, EventPayload, SessionId};
use lago_journal::RedbJournal;
use lago_store::BlobStore;

fn test_state() -> (tempfile::TempDir, Arc<AppState>) {
    let dir = tempfile::tempdir().unwrap();
    let journal = RedbJournal::open(dir.path().join("test.redb")).unwrap();
    let blob_store = BlobStore::open(dir.path().join("blobs")).unwrap();
    let state = Arc::new(AppState {
        journal: Arc::new(journal) as Arc<dyn lago_core::Journal>,
        blob_store: Arc::new(blob_store),
        data_dir: dir.path().to_path_buf(),
    });
    (dir, state)
}

async fn body_string(body: Body) -> String {
    let bytes = body.collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

async fn body_json(body: Body) -> serde_json::Value {
    let s = body_string(body).await;
    serde_json::from_str(&s).unwrap()
}

async fn create_session(app: &axum::Router, name: &str) -> String {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/sessions")
        .header("content-type", "application/json")
        .body(Body::from(format!(r#"{{"name":"{name}"}}"#)))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = body_json(resp.into_body()).await;
    json["session_id"].as_str().unwrap().to_string()
}

fn make_envelope(
    session_id: &SessionId,
    branch_id: &BranchId,
    payload: EventPayload,
) -> EventEnvelope {
    EventEnvelope {
        event_id: EventId::default(),
        session_id: session_id.clone(),
        branch_id: branch_id.clone(),
        run_id: None,
        seq: 0, // journal assigns real seq
        timestamp: 0,
        parent_id: None,
        payload,
        metadata: Default::default(),
        schema_version: 1,
    }
}

// ─── Session CRUD ───────────────────────────────────────────────

#[tokio::test]
async fn create_and_get_session() {
    let (_dir, state) = test_state();
    let app = build_router(state);

    let session_id = create_session(&app, "my-session").await;
    assert!(!session_id.is_empty());

    let req = Request::builder()
        .uri(format!("/v1/sessions/{session_id}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    assert_eq!(json["session_id"], session_id);
}

#[tokio::test]
async fn list_sessions_returns_all() {
    let (_dir, state) = test_state();
    let app = build_router(state);

    create_session(&app, "session-a").await;
    create_session(&app, "session-b").await;

    let req = Request::builder()
        .uri("/v1/sessions")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    let sessions = json.as_array().unwrap();
    assert_eq!(sessions.len(), 2);
}

#[tokio::test]
async fn get_nonexistent_session_returns_404() {
    let (_dir, state) = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/v1/sessions/nonexistent-id")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── Branch Management ──────────────────────────────────────────

#[tokio::test]
async fn create_and_list_branches() {
    let (_dir, state) = test_state();
    let app = build_router(state);

    let session_id = create_session(&app, "branch-test").await;

    // List branches — should have "main" by default
    let req = Request::builder()
        .uri(format!("/v1/sessions/{session_id}/branches"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_json(resp.into_body()).await;
    let branches = json.as_array().unwrap();
    assert!(!branches.is_empty(), "Should have at least a main branch");

    // Create a new branch
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/sessions/{session_id}/branches"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"feature-x"}"#))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert!(
        resp.status().is_success(),
        "Branch creation should succeed, got: {}",
        resp.status()
    );

    // List again — should have 2 branches
    let req = Request::builder()
        .uri(format!("/v1/sessions/{session_id}/branches"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let json = body_json(resp.into_body()).await;
    let branches = json.as_array().unwrap();
    assert_eq!(branches.len(), 2, "Should have main + feature-x");
}

// ─── SSE Streaming ──────────────────────────────────────────────

#[tokio::test]
async fn sse_events_endpoint_returns_event_stream() {
    let (_dir, state) = test_state();
    let journal = state.journal.clone();

    // Create session via API
    let app = build_router(state);
    let session_id = create_session(&app, "sse-test").await;

    // Append an event directly to journal
    let sid = SessionId::from_string(&session_id);
    let branch_id = BranchId::from("main");
    let envelope = make_envelope(
        &sid,
        &branch_id,
        EventPayload::Message {
            role: "assistant".to_string(),
            content: "Hello from SSE".to_string(),
            model: None,
            token_usage: None,
        },
    );
    journal.append(envelope).await.unwrap();

    // Request SSE stream in Lago format
    let req = Request::builder()
        .uri(format!("/v1/sessions/{session_id}/events?format=lago"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("text/event-stream"),
        "Should be SSE content type, got: {content_type}"
    );
}

#[tokio::test]
async fn sse_openai_format_returns_200() {
    let (_dir, state) = test_state();
    let app = build_router(state);
    let session_id = create_session(&app, "openai-test").await;

    let req = Request::builder()
        .uri(format!("/v1/sessions/{session_id}/events?format=openai"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ─── Health Check ───────────────────────────────────────────────

#[tokio::test]
async fn health_returns_ok() {
    let (_dir, state) = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ─── Event Ingestion via Journal + Read Back ────────────────────

#[tokio::test]
async fn ingest_events_then_read_session() {
    let (_dir, state) = test_state();
    let journal = state.journal.clone();
    let app = build_router(state);

    let session_id = create_session(&app, "ingest-test").await;
    let sid = SessionId::from_string(&session_id);
    let branch_id = BranchId::from("main");

    // Ingest events directly into journal
    let events = vec![
        make_envelope(
            &sid,
            &branch_id,
            EventPayload::Message {
                role: "user".to_string(),
                content: "Hello agent".to_string(),
                model: None,
                token_usage: None,
            },
        ),
        make_envelope(
            &sid,
            &branch_id,
            EventPayload::Message {
                role: "assistant".to_string(),
                content: "Hello human".to_string(),
                model: Some("test-model".to_string()),
                token_usage: None,
            },
        ),
    ];
    journal.append_batch(events).await.unwrap();

    // Read session via API
    let req = Request::builder()
        .uri(format!("/v1/sessions/{session_id}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
