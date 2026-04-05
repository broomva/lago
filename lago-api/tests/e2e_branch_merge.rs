//! End-to-end integration tests for branch merge (fast-forward).

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

    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let prometheus_handle = recorder.handle();
    // Ignore error if global recorder is already set from another test
    let _ = metrics::set_global_recorder(recorder);

    let state = Arc::new(AppState {
        journal: Arc::new(journal) as Arc<dyn lago_core::Journal>,
        blob_store: Arc::new(blob_store),
        data_dir: dir.path().to_path_buf(),
        started_at: std::time::Instant::now(),
        auth: None,
        policy_engine: None,
        rbac_manager: None,
        hook_runner: None,
        rate_limiter: None,
        prometheus_handle,
        manifest_cache: tokio::sync::RwLock::new(std::collections::HashMap::new()),
    });
    (dir, state)
}

async fn body_json(body: Body) -> serde_json::Value {
    let bytes = body.collect().await.unwrap().to_bytes();
    let s = String::from_utf8(bytes.to_vec()).unwrap();
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

async fn create_branch(app: &axum::Router, session_id: &str, name: &str) -> String {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/sessions/{session_id}/branches"))
        .header("content-type", "application/json")
        .body(Body::from(format!(r#"{{"name":"{name}"}}"#)))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert!(resp.status().is_success(), "branch creation should succeed");
    let json = body_json(resp.into_body()).await;
    json["branch_id"].as_str().unwrap().to_string()
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
        seq: 0,
        timestamp: 0,
        parent_id: None,
        payload,
        metadata: Default::default(),
        schema_version: 1,
    }
}

// ─── Fast-forward merge succeeds ──────────────────────────────

#[tokio::test]
async fn fast_forward_merge_succeeds_when_source_is_ahead() {
    let (_dir, state) = test_state();
    let journal = state.journal.clone();
    let app = build_router(state);

    // 1. Create a session
    let session_id = create_session(&app, "merge-test").await;
    let sid = SessionId::from_string(&session_id);

    // 2. Create a feature branch (fork_point defaults to current main head)
    let feature_branch_id = create_branch(&app, &session_id, "feature").await;

    // 3. Append events on the feature branch
    let feature_bid = BranchId::from_string(&feature_branch_id);
    let events = vec![
        make_envelope(
            &sid,
            &feature_bid,
            EventPayload::Message {
                role: "user".to_string(),
                content: "feature work 1".to_string(),
                model: None,
                token_usage: None,
            },
        ),
        make_envelope(
            &sid,
            &feature_bid,
            EventPayload::Message {
                role: "assistant".to_string(),
                content: "feature work 2".to_string(),
                model: None,
                token_usage: None,
            },
        ),
    ];
    journal.append_batch(events).await.unwrap();

    // 4. Merge feature -> main via the API
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/sessions/{session_id}/branches/feature/merge"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"target":"main"}"#))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "fast-forward merge should succeed"
    );

    let json = body_json(resp.into_body()).await;
    assert_eq!(json["merged"], true);
    assert_eq!(json["strategy"], "fast-forward");
    assert_eq!(json["events_merged"], 2);
}

// ─── Non-fast-forward returns 409 ──────────────────────────────

#[tokio::test]
async fn non_fast_forward_returns_409() {
    let (_dir, state) = test_state();
    let journal = state.journal.clone();
    let app = build_router(state);

    // 1. Create a session
    let session_id = create_session(&app, "conflict-test").await;
    let sid = SessionId::from_string(&session_id);
    let main_bid = BranchId::from_string("main");

    // 2. Create a feature branch (fork_point defaults to current main head)
    let feature_branch_id = create_branch(&app, &session_id, "feature").await;

    // 3. Advance main AFTER the feature branch was created.
    //    This makes a fast-forward impossible because main has moved past
    //    the feature branch's fork point.
    let main_events = vec![
        make_envelope(
            &sid,
            &main_bid,
            EventPayload::Message {
                role: "user".to_string(),
                content: "main advanced 1".to_string(),
                model: None,
                token_usage: None,
            },
        ),
        make_envelope(
            &sid,
            &main_bid,
            EventPayload::Message {
                role: "assistant".to_string(),
                content: "main advanced 2".to_string(),
                model: None,
                token_usage: None,
            },
        ),
    ];
    journal.append_batch(main_events).await.unwrap();

    // 4. Also append events on the feature branch
    let feature_bid = BranchId::from_string(&feature_branch_id);
    let feature_events = vec![make_envelope(
        &sid,
        &feature_bid,
        EventPayload::Message {
            role: "user".to_string(),
            content: "feature work".to_string(),
            model: None,
            token_usage: None,
        },
    )];
    journal.append_batch(feature_events).await.unwrap();

    // 5. Try to merge feature -> main: should fail with 409
    let req = Request::builder()
        .method("POST")
        .uri(format!("/v1/sessions/{session_id}/branches/feature/merge"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"target":"main"}"#))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "non-fast-forward merge should return 409"
    );

    let json = body_json(resp.into_body()).await;
    assert_eq!(json["error"], "conflict");
    assert!(
        json["message"]
            .as_str()
            .unwrap()
            .contains("fast-forward not possible"),
        "error message should explain fast-forward is not possible"
    );
}
