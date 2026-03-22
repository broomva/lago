//! End-to-end integration tests for the file operations pipeline.
//!
//! Tests exercise the full stack: HTTP router → handlers → journal + blob store,
//! covering file write/read, hashline format, hashline PATCH edits, manifest,
//! and the agent lifecycle event variants.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use lago_api::build_router;
use lago_api::state::AppState;
use lago_journal::RedbJournal;
use lago_store::BlobStore;

/// Spin up a fresh AppState with real redb journal + blob store in a tempdir.
fn test_state() -> (tempfile::TempDir, Arc<AppState>) {
    let dir = tempfile::tempdir().unwrap();
    let journal = RedbJournal::open(dir.path().join("test.redb")).unwrap();
    let blob_store = BlobStore::open(dir.path().join("blobs")).unwrap();

    // Build a Prometheus recorder for tests. If global recorder is already
    // installed by another test, handle() still works for rendering.
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let prometheus_handle = recorder.handle();
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
    });
    (dir, state)
}

/// Helper to read the full response body as a string.
async fn body_string(body: Body) -> String {
    let bytes = body.collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Helper to read the full response body as JSON.
async fn body_json(body: Body) -> serde_json::Value {
    let s = body_string(body).await;
    serde_json::from_str(&s).unwrap()
}

/// Create a session via POST, return the session_id.
async fn create_session(app: &axum::Router) -> String {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/sessions")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"test-session"}"#))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = body_json(resp.into_body()).await;
    json["session_id"].as_str().unwrap().to_string()
}

/// Write a file via PUT, return the response JSON.
async fn write_file(
    app: &axum::Router,
    session_id: &str,
    path: &str,
    content: &str,
) -> serde_json::Value {
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/v1/sessions/{session_id}/files/{path}"))
        .body(Body::from(content.to_string()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    body_json(resp.into_body()).await
}

/// Read a file via GET, return (status, headers, body_string).
async fn read_file(
    app: &axum::Router,
    session_id: &str,
    path: &str,
    query: &str,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let uri = if query.is_empty() {
        format!("/v1/sessions/{session_id}/files/{path}")
    } else {
        format!("/v1/sessions/{session_id}/files/{path}?{query}")
    };
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = body_string(resp.into_body()).await;
    (status, headers, body)
}

// ============================================================
// Tests
// ============================================================

#[tokio::test]
async fn health_check() {
    let (_dir, state) = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn full_file_write_read_cycle() {
    let (_dir, state) = test_state();
    let app = build_router(state);

    // 1. Create session
    let session_id = create_session(&app).await;

    // 2. Write a file
    let content = "fn main() {\n    println!(\"hello\");\n}\n";
    let write_resp = write_file(&app, &session_id, "src/main.rs", content).await;
    assert_eq!(write_resp["path"], "/src/main.rs");
    assert!(write_resp["blob_hash"].as_str().unwrap().len() > 10);
    assert_eq!(write_resp["size_bytes"], content.len());

    // 3. Read it back
    let (status, headers, body) = read_file(&app, &session_id, "src/main.rs", "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, content);
    assert!(headers.get("x-blob-hash").is_some());
}

#[tokio::test]
async fn read_file_hashline_format() {
    let (_dir, state) = test_state();
    let app = build_router(state);

    let session_id = create_session(&app).await;

    let content = "aaa\nbbb\nccc";
    write_file(&app, &session_id, "test.txt", content).await;

    // Read in hashline format
    let (status, headers, body) = read_file(&app, &session_id, "test.txt", "format=hashline").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get("x-format").unwrap().to_str().unwrap(),
        "hashline"
    );
    assert_eq!(
        headers.get("content-type").unwrap().to_str().unwrap(),
        "text/plain"
    );

    // Verify hashline format: each line is N:HHHH|content
    let lines: Vec<&str> = body.split('\n').collect();
    assert_eq!(lines.len(), 3);

    for (i, line) in lines.iter().enumerate() {
        let parts: Vec<&str> = line.splitn(2, '|').collect();
        assert_eq!(parts.len(), 2, "line {i} missing pipe separator");
        let prefix = parts[0];
        let hash_parts: Vec<&str> = prefix.splitn(2, ':').collect();
        assert_eq!(hash_parts.len(), 2);
        // Line number is 1-indexed
        assert_eq!(
            hash_parts[0],
            &(i + 1).to_string(),
            "wrong line number on line {i}"
        );
        // Hash is 4 hex chars
        assert_eq!(hash_parts[1].len(), 4, "hash not 4 chars on line {i}");
    }

    // Verify content is preserved
    assert!(body.contains("|aaa"));
    assert!(body.contains("|bbb"));
    assert!(body.contains("|ccc"));
}

#[tokio::test]
async fn patch_file_hashline_replace() {
    let (_dir, state) = test_state();
    let app = build_router(state);

    let session_id = create_session(&app).await;

    // Write initial file
    let content = "line_one\nline_two\nline_three";
    write_file(&app, &session_id, "edit.txt", content).await;

    // Read in hashline format to get hashes
    let (_, _, hashline_text) = read_file(&app, &session_id, "edit.txt", "format=hashline").await;
    let lines: Vec<&str> = hashline_text.split('\n').collect();

    // Parse the hash for line 2
    let line2_prefix: Vec<&str> = lines[1].splitn(2, '|').collect();
    let line2_hash: Vec<&str> = line2_prefix[0].splitn(2, ':').collect();
    let hash_2 = line2_hash[1];

    // PATCH: replace line 2
    let edits = serde_json::json!([{
        "op": "Replace",
        "anchor_hash": hash_2,
        "line_num": 2,
        "new_content": "LINE_TWO_MODIFIED"
    }]);

    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/v1/sessions/{session_id}/files/edit.txt"))
        .header("content-type", "application/json")
        .body(Body::from(edits.to_string()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let patch_resp = body_json(resp.into_body()).await;
    assert_eq!(patch_resp["path"], "/edit.txt");

    // Read back and verify
    let (_, _, body) = read_file(&app, &session_id, "edit.txt", "").await;
    assert_eq!(body, "line_one\nLINE_TWO_MODIFIED\nline_three");
}

#[tokio::test]
async fn patch_file_hashline_insert_and_delete() {
    let (_dir, state) = test_state();
    let app = build_router(state);

    let session_id = create_session(&app).await;

    // Write initial file
    let content = "alpha\ngamma";
    write_file(&app, &session_id, "ins.txt", content).await;

    // Get hashes
    let (_, _, hl) = read_file(&app, &session_id, "ins.txt", "format=hashline").await;
    let lines: Vec<&str> = hl.split('\n').collect();
    let hash_1 = lines[0].splitn(2, '|').collect::<Vec<_>>()[0]
        .splitn(2, ':')
        .collect::<Vec<_>>()[1];

    // Insert "beta" after line 1
    let edits = serde_json::json!([{
        "op": "InsertAfter",
        "anchor_hash": hash_1,
        "line_num": 1,
        "new_content": "beta"
    }]);

    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/v1/sessions/{session_id}/files/ins.txt"))
        .header("content-type", "application/json")
        .body(Body::from(edits.to_string()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (_, _, body) = read_file(&app, &session_id, "ins.txt", "").await;
    assert_eq!(body, "alpha\nbeta\ngamma");

    // Now delete line 2 ("beta") from the updated file
    let (_, _, hl2) = read_file(&app, &session_id, "ins.txt", "format=hashline").await;
    let lines2: Vec<&str> = hl2.split('\n').collect();
    assert_eq!(lines2.len(), 3);
    let hash_beta = lines2[1].splitn(2, '|').collect::<Vec<_>>()[0]
        .splitn(2, ':')
        .collect::<Vec<_>>()[1];

    let edits = serde_json::json!([{
        "op": "Delete",
        "anchor_hash": hash_beta,
        "line_num": 2
    }]);

    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/v1/sessions/{session_id}/files/ins.txt"))
        .header("content-type", "application/json")
        .body(Body::from(edits.to_string()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (_, _, body) = read_file(&app, &session_id, "ins.txt", "").await;
    assert_eq!(body, "alpha\ngamma");
}

#[tokio::test]
async fn patch_file_hashline_replace_range() {
    let (_dir, state) = test_state();
    let app = build_router(state);

    let session_id = create_session(&app).await;

    let content = "head\nold_1\nold_2\nold_3\ntail";
    write_file(&app, &session_id, "range.txt", content).await;

    // Get hashes for lines 2 and 4
    let (_, _, hl) = read_file(&app, &session_id, "range.txt", "format=hashline").await;
    let lines: Vec<&str> = hl.split('\n').collect();

    let parse_hash = |line: &str| -> String {
        line.splitn(2, '|').collect::<Vec<_>>()[0]
            .splitn(2, ':')
            .collect::<Vec<_>>()[1]
            .to_string()
    };

    let hash_2 = parse_hash(lines[1]);
    let hash_4 = parse_hash(lines[3]);

    // Replace lines 2-4 with two new lines
    let edits = serde_json::json!([{
        "op": "ReplaceRange",
        "start_hash": hash_2,
        "start_line": 2,
        "end_hash": hash_4,
        "end_line": 4,
        "new_content": "new_A\nnew_B"
    }]);

    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/v1/sessions/{session_id}/files/range.txt"))
        .header("content-type", "application/json")
        .body(Body::from(edits.to_string()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (_, _, body) = read_file(&app, &session_id, "range.txt", "").await;
    assert_eq!(body, "head\nnew_A\nnew_B\ntail");
}

#[tokio::test]
async fn patch_file_hash_mismatch_returns_400() {
    let (_dir, state) = test_state();
    let app = build_router(state);

    let session_id = create_session(&app).await;
    write_file(&app, &session_id, "err.txt", "hello\nworld").await;

    // Send edit with wrong hash
    let edits = serde_json::json!([{
        "op": "Replace",
        "anchor_hash": "0000",
        "line_num": 1,
        "new_content": "goodbye"
    }]);

    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/v1/sessions/{session_id}/files/err.txt"))
        .header("content-type", "application/json")
        .body(Body::from(edits.to_string()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp.into_body()).await;
    assert_eq!(json["error"], "hashline_error");
}

#[tokio::test]
async fn patch_nonexistent_file_returns_404() {
    let (_dir, state) = test_state();
    let app = build_router(state);

    let session_id = create_session(&app).await;

    let edits = serde_json::json!([{
        "op": "Replace",
        "anchor_hash": "0000",
        "line_num": 1,
        "new_content": "x"
    }]);

    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/v1/sessions/{session_id}/files/nope.txt"))
        .header("content-type", "application/json")
        .body(Body::from(edits.to_string()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn manifest_tracks_file_operations() {
    let (_dir, state) = test_state();
    let app = build_router(state);

    let session_id = create_session(&app).await;

    // Write two files
    write_file(&app, &session_id, "a.txt", "aaa").await;
    write_file(&app, &session_id, "b.txt", "bbb").await;

    // Check manifest
    let req = Request::builder()
        .uri(format!("/v1/sessions/{session_id}/manifest"))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp.into_body()).await;
    let entries = json["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);

    let paths: Vec<&str> = entries
        .iter()
        .map(|e| e["path"].as_str().unwrap())
        .collect();
    assert!(paths.contains(&"/a.txt"));
    assert!(paths.contains(&"/b.txt"));

    // Delete one file
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/sessions/{session_id}/files/a.txt"))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Manifest should only have b.txt
    let req = Request::builder()
        .uri(format!("/v1/sessions/{session_id}/manifest"))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    let json = body_json(resp.into_body()).await;
    let entries = json["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["path"], "/b.txt");
}

#[tokio::test]
async fn overwrite_file_updates_content() {
    let (_dir, state) = test_state();
    let app = build_router(state);

    let session_id = create_session(&app).await;

    // Write v1
    write_file(&app, &session_id, "doc.txt", "version 1").await;
    let (_, _, body) = read_file(&app, &session_id, "doc.txt", "").await;
    assert_eq!(body, "version 1");

    // Overwrite with v2
    write_file(&app, &session_id, "doc.txt", "version 2").await;
    let (_, _, body) = read_file(&app, &session_id, "doc.txt", "").await;
    assert_eq!(body, "version 2");

    // Manifest should still show 1 file
    let req = Request::builder()
        .uri(format!("/v1/sessions/{session_id}/manifest"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let json = body_json(resp.into_body()).await;
    assert_eq!(json["entries"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn multiple_hashline_edits_in_one_patch() {
    let (_dir, state) = test_state();
    let app = build_router(state);

    let session_id = create_session(&app).await;

    let content = "line1\nline2\nline3\nline4";
    write_file(&app, &session_id, "multi.txt", content).await;

    // Get hashes
    let (_, _, hl) = read_file(&app, &session_id, "multi.txt", "format=hashline").await;
    let lines: Vec<&str> = hl.split('\n').collect();

    let parse_hash = |line: &str| -> String {
        line.splitn(2, '|').collect::<Vec<_>>()[0]
            .splitn(2, ':')
            .collect::<Vec<_>>()[1]
            .to_string()
    };

    let hash_1 = parse_hash(lines[0]);
    let hash_3 = parse_hash(lines[2]);

    // Replace line 1 and line 3 simultaneously (non-overlapping)
    let edits = serde_json::json!([
        {
            "op": "Replace",
            "anchor_hash": hash_1,
            "line_num": 1,
            "new_content": "LINE1"
        },
        {
            "op": "Replace",
            "anchor_hash": hash_3,
            "line_num": 3,
            "new_content": "LINE3"
        }
    ]);

    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/v1/sessions/{session_id}/files/multi.txt"))
        .header("content-type", "application/json")
        .body(Body::from(edits.to_string()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (_, _, body) = read_file(&app, &session_id, "multi.txt", "").await;
    assert_eq!(body, "LINE1\nline2\nLINE3\nline4");
}

#[tokio::test]
async fn read_nonexistent_session_returns_404() {
    let (_dir, state) = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/v1/sessions/NOSUCHSESSION/files/foo.txt")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn read_nonexistent_file_returns_404() {
    let (_dir, state) = test_state();
    let app = build_router(state);

    let session_id = create_session(&app).await;

    let req = Request::builder()
        .uri(format!("/v1/sessions/{session_id}/files/nope.txt"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn hashline_edit_then_re_read_hashes_update() {
    let (_dir, state) = test_state();
    let app = build_router(state);

    let session_id = create_session(&app).await;

    write_file(&app, &session_id, "h.txt", "old_line\nkeeper").await;

    // Get initial hashes
    let (_, _, hl1) = read_file(&app, &session_id, "h.txt", "format=hashline").await;
    let lines1: Vec<&str> = hl1.split('\n').collect();
    let hash_old = lines1[0].splitn(2, '|').collect::<Vec<_>>()[0]
        .splitn(2, ':')
        .collect::<Vec<_>>()[1]
        .to_string();

    // Replace line 1
    let edits = serde_json::json!([{
        "op": "Replace",
        "anchor_hash": hash_old,
        "line_num": 1,
        "new_content": "new_line"
    }]);

    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/v1/sessions/{session_id}/files/h.txt"))
        .header("content-type", "application/json")
        .body(Body::from(edits.to_string()))
        .unwrap();
    app.clone().oneshot(req).await.unwrap();

    // Re-read: hash for line 1 should have changed, line 2 unchanged
    let (_, _, hl2) = read_file(&app, &session_id, "h.txt", "format=hashline").await;
    let lines2: Vec<&str> = hl2.split('\n').collect();

    let hash_new = lines2[0].splitn(2, '|').collect::<Vec<_>>()[0]
        .splitn(2, ':')
        .collect::<Vec<_>>()[1]
        .to_string();
    let hash_keeper_after = lines2[1].splitn(2, '|').collect::<Vec<_>>()[0]
        .splitn(2, ':')
        .collect::<Vec<_>>()[1]
        .to_string();
    let hash_keeper_before = lines1[1].splitn(2, '|').collect::<Vec<_>>()[0]
        .splitn(2, ':')
        .collect::<Vec<_>>()[1]
        .to_string();

    assert_ne!(hash_old, hash_new, "hash should change after edit");
    assert_eq!(
        hash_keeper_before, hash_keeper_after,
        "unchanged line should keep same hash"
    );
    assert!(lines2[0].ends_with("|new_line"));
    assert!(lines2[1].ends_with("|keeper"));
}

#[tokio::test]
async fn session_list_and_get() {
    let (_dir, state) = test_state();
    let app = build_router(state);

    // Empty initially
    let req = Request::builder()
        .uri("/v1/sessions")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let json = body_json(resp.into_body()).await;
    assert_eq!(json.as_array().unwrap().len(), 0);

    // Create one
    let session_id = create_session(&app).await;

    // List shows 1
    let req = Request::builder()
        .uri("/v1/sessions")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let json = body_json(resp.into_body()).await;
    assert_eq!(json.as_array().unwrap().len(), 1);

    // Get by ID
    let req = Request::builder()
        .uri(format!("/v1/sessions/{session_id}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp.into_body()).await;
    assert_eq!(json["session_id"], session_id);
    assert_eq!(json["name"], "test-session");
}

#[tokio::test]
async fn empty_patch_is_noop() {
    let (_dir, state) = test_state();
    let app = build_router(state);

    let session_id = create_session(&app).await;
    write_file(&app, &session_id, "noop.txt", "unchanged").await;

    // PATCH with empty edits array
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/v1/sessions/{session_id}/files/noop.txt"))
        .header("content-type", "application/json")
        .body(Body::from("[]"))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (_, _, body) = read_file(&app, &session_id, "noop.txt", "").await;
    assert_eq!(body, "unchanged");
}

#[tokio::test]
async fn large_file_hashline_roundtrip() {
    let (_dir, state) = test_state();
    let app = build_router(state);

    let session_id = create_session(&app).await;

    // Generate a 500-line file
    let content: String = (1..=500)
        .map(|i| format!("line number {i} with some content to make it realistic"))
        .collect::<Vec<_>>()
        .join("\n");

    write_file(&app, &session_id, "big.txt", &content).await;

    // Read in hashline format
    let (status, _, hl) = read_file(&app, &session_id, "big.txt", "format=hashline").await;
    assert_eq!(status, StatusCode::OK);

    let hl_lines: Vec<&str> = hl.split('\n').collect();
    assert_eq!(hl_lines.len(), 500);

    // Verify first and last line numbers
    assert!(hl_lines[0].starts_with("1:"));
    assert!(hl_lines[499].starts_with("500:"));

    // Edit line 250 via PATCH
    let hash_250 = hl_lines[249].splitn(2, '|').collect::<Vec<_>>()[0]
        .splitn(2, ':')
        .collect::<Vec<_>>()[1]
        .to_string();

    let edits = serde_json::json!([{
        "op": "Replace",
        "anchor_hash": hash_250,
        "line_num": 250,
        "new_content": "REPLACED LINE 250"
    }]);

    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/v1/sessions/{session_id}/files/big.txt"))
        .header("content-type", "application/json")
        .body(Body::from(edits.to_string()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify the edit persisted
    let (_, _, updated) = read_file(&app, &session_id, "big.txt", "").await;
    let updated_lines: Vec<&str> = updated.split('\n').collect();
    assert_eq!(updated_lines.len(), 500);
    assert_eq!(updated_lines[249], "REPLACED LINE 250");
    // Other lines unchanged
    assert!(updated_lines[0].starts_with("line number 1"));
    assert!(updated_lines[498].starts_with("line number 499"));
}
