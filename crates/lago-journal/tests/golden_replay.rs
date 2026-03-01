//! Golden fixture replay tests for the Lago journal.
//!
//! These tests load deterministic JSON fixture files from `conformance/fixtures/`,
//! append them to a fresh RedbJournal, and verify that events survive the full
//! serialization/storage/deserialization pipeline with correct payloads, sequence
//! assignment, and branch isolation.
//!
//! Payload assertions use JSON round-trip (serde_json::to_value) to verify field
//! content. This is intentional: golden tests validate the storage pipeline
//! end-to-end, independent of Rust enum variant resolution across crate boundaries.

use lago_core::event::EventEnvelope;
use lago_core::id::{BranchId, SessionId};
use lago_core::{EventQuery, Journal};
use lago_journal::RedbJournal;
use tempfile::TempDir;

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../conformance/fixtures");

fn load_fixture(name: &str) -> Vec<EventEnvelope> {
    let path = format!("{FIXTURES_DIR}/{name}");
    let data = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

fn setup() -> (TempDir, RedbJournal) {
    let dir = TempDir::new().unwrap();
    let journal = RedbJournal::open(&dir.path().join("golden.redb")).unwrap();
    (dir, journal)
}

async fn ingest(journal: &RedbJournal, fixtures: &[EventEnvelope]) {
    for event in fixtures {
        journal.append(event.clone()).await.unwrap();
    }
}

/// Helper: serialize a payload to serde_json::Value for field-level assertions.
fn payload_json(envelope: &EventEnvelope) -> serde_json::Value {
    serde_json::to_value(&envelope.payload).unwrap()
}

// ─── simple-chat fixtures ───────────────────────────────────────────────────

#[tokio::test]
async fn golden_simple_chat_replay_deterministic() {
    let fixtures = load_fixture("simple-chat.json");
    assert_eq!(
        fixtures.len(),
        4,
        "simple-chat fixture should have 4 events"
    );

    let (_dir, journal) = setup();
    ingest(&journal, &fixtures).await;

    let events = journal
        .read(
            EventQuery::new()
                .session(SessionId::from_string("GOLDEN-SIMPLE-CHAT"))
                .branch(BranchId::from_string("main")),
        )
        .await
        .unwrap();
    assert_eq!(events.len(), 4);

    // Event 0: SessionCreated
    let p0 = payload_json(&events[0]);
    assert_eq!(p0["type"], "SessionCreated");
    assert_eq!(p0["name"], "simple-chat");

    // Event 1: user message
    let p1 = payload_json(&events[1]);
    assert_eq!(p1["type"], "Message");
    assert_eq!(p1["role"], "user");
    assert_eq!(p1["content"], "Hello, agent!");

    // Event 2: assistant message with token_usage
    let p2 = payload_json(&events[2]);
    assert_eq!(p2["type"], "Message");
    assert_eq!(p2["role"], "assistant");
    assert_eq!(p2["content"], "Hello! How can I help you today?");
    assert_eq!(p2["model"], "gpt-4");
    assert_eq!(p2["token_usage"]["prompt_tokens"], 10);
    assert_eq!(p2["token_usage"]["completion_tokens"], 8);
    assert_eq!(p2["token_usage"]["total_tokens"], 18);

    // Event 3: user message
    let p3 = payload_json(&events[3]);
    assert_eq!(p3["type"], "Message");
    assert_eq!(p3["role"], "user");
    assert_eq!(p3["content"], "Thanks, goodbye!");
}

#[tokio::test]
async fn golden_simple_chat_head_seq() {
    let fixtures = load_fixture("simple-chat.json");
    let (_dir, journal) = setup();
    ingest(&journal, &fixtures).await;

    let head = journal
        .head_seq(
            &SessionId::from_string("GOLDEN-SIMPLE-CHAT"),
            &BranchId::from_string("main"),
        )
        .await
        .unwrap();
    assert_eq!(head, 4, "head_seq should equal event count after ingest");
}

// ─── tool-round-trip fixtures ───────────────────────────────────────────────

#[tokio::test]
async fn golden_tool_round_trip_replay() {
    let fixtures = load_fixture("tool-round-trip.json");
    assert_eq!(
        fixtures.len(),
        6,
        "tool-round-trip fixture should have 6 events"
    );

    let (_dir, journal) = setup();
    ingest(&journal, &fixtures).await;

    let events = journal
        .read(
            EventQuery::new()
                .session(SessionId::from_string("GOLDEN-TOOL-RT"))
                .branch(BranchId::from_string("main")),
        )
        .await
        .unwrap();
    assert_eq!(events.len(), 6);

    // ToolCallRequested at index 2
    let p2 = payload_json(&events[2]);
    assert_eq!(p2["type"], "ToolCallRequested");
    assert_eq!(p2["call_id"], "call-001");
    assert_eq!(p2["tool_name"], "read_file");
    assert_eq!(p2["arguments"]["path"], "/etc/hostname");
    assert_eq!(p2["category"], "fs");

    // ToolCallCompleted at index 3
    let p3 = payload_json(&events[3]);
    assert_eq!(p3["type"], "ToolCallCompleted");
    assert_eq!(p3["call_id"], "call-001");
    assert_eq!(p3["tool_name"], "read_file");
    assert_eq!(p3["result"]["content"], "agent-host");
    assert_eq!(p3["duration_ms"], 12);
    assert_eq!(p3["status"], "ok");

    // SessionClosed at index 5
    let p5 = payload_json(&events[5]);
    assert_eq!(p5["type"], "SessionClosed");
    assert_eq!(p5["reason"], "completed");
}

#[tokio::test]
async fn golden_tool_round_trip_event_by_id() {
    let fixtures = load_fixture("tool-round-trip.json");
    let (_dir, journal) = setup();
    ingest(&journal, &fixtures).await;

    // Each event should be retrievable by its event_id
    for fixture in &fixtures {
        let found = journal
            .get_event(&fixture.event_id)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("event {} not found", fixture.event_id.as_str()));
        assert_eq!(found.event_id, fixture.event_id);
    }
}

// ─── branch-fork fixtures ───────────────────────────────────────────────────

#[tokio::test]
async fn golden_branch_fork_isolation() {
    let fixtures = load_fixture("branch-fork.json");
    assert_eq!(
        fixtures.len(),
        7,
        "branch-fork fixture should have 7 events"
    );

    let (_dir, journal) = setup();
    ingest(&journal, &fixtures).await;

    // Main branch: events at indices 0,1,2,3,6 (5 events on main)
    let main_events = journal
        .read(
            EventQuery::new()
                .session(SessionId::from_string("GOLDEN-BRANCH-FORK"))
                .branch(BranchId::from_string("main")),
        )
        .await
        .unwrap();
    assert_eq!(main_events.len(), 5, "main branch should have 5 events");

    // Feature-x branch: events at indices 4,5 (2 events)
    let feature_events = journal
        .read(
            EventQuery::new()
                .session(SessionId::from_string("GOLDEN-BRANCH-FORK"))
                .branch(BranchId::from_string("feature-x")),
        )
        .await
        .unwrap();
    assert_eq!(
        feature_events.len(),
        2,
        "feature-x branch should have 2 events"
    );

    // Verify branch isolation: feature-x events are user and assistant messages
    let fp0 = payload_json(&feature_events[0]);
    assert_eq!(fp0["type"], "Message");
    assert_eq!(fp0["role"], "user");
    assert_eq!(fp0["content"], "Implement feature X");

    let fp1 = payload_json(&feature_events[1]);
    assert_eq!(fp1["type"], "Message");
    assert_eq!(fp1["role"], "assistant");
    assert_eq!(fp1["content"], "Feature X implemented.");
}

#[tokio::test]
async fn golden_branch_fork_cursor_replay() {
    let fixtures = load_fixture("branch-fork.json");
    let (_dir, journal) = setup();
    ingest(&journal, &fixtures).await;

    // Read main branch from cursor position 3 (should return events 4 and 5)
    let events = journal
        .read(
            EventQuery::new()
                .session(SessionId::from_string("GOLDEN-BRANCH-FORK"))
                .branch(BranchId::from_string("main"))
                .after(3),
        )
        .await
        .unwrap();
    assert_eq!(
        events.len(),
        2,
        "reading after seq 3 should return 2 events"
    );
    assert_eq!(events[0].seq, 4);
    assert_eq!(events[1].seq, 5);
}

// ─── forward-compat fixtures ────────────────────────────────────────────────

#[tokio::test]
async fn golden_forward_compat_custom_survives() {
    let fixtures = load_fixture("forward-compat.json");
    assert_eq!(
        fixtures.len(),
        4,
        "forward-compat fixture should have 4 events"
    );

    let (_dir, journal) = setup();
    ingest(&journal, &fixtures).await;

    let events = journal
        .read(
            EventQuery::new()
                .session(SessionId::from_string("GOLDEN-FORWARD-COMPAT"))
                .branch(BranchId::from_string("main")),
        )
        .await
        .unwrap();
    assert_eq!(events.len(), 4);

    // Event at index 2: unknown "VisionResult" preserved as Custom wrapper.
    // After storage round-trip, the Custom variant serializes as:
    //   {"type": "Custom", "event_type": "VisionResult", "data": {original fields}}
    let p2 = payload_json(&events[2]);
    assert_eq!(p2["type"], "Custom");
    assert_eq!(p2["event_type"], "VisionResult");
    assert_eq!(p2["data"]["image_hash"], "abc123");
    assert_eq!(p2["data"]["confidence"], 0.95);
    assert_eq!(p2["data"]["labels"][0], "cat");
    assert_eq!(p2["data"]["labels"][1], "outdoor");
}

#[tokio::test]
async fn golden_forward_compat_known_events_unaffected() {
    let fixtures = load_fixture("forward-compat.json");
    let (_dir, journal) = setup();
    ingest(&journal, &fixtures).await;

    let events = journal
        .read(
            EventQuery::new()
                .session(SessionId::from_string("GOLDEN-FORWARD-COMPAT"))
                .branch(BranchId::from_string("main")),
        )
        .await
        .unwrap();

    // SessionCreated (index 0) should still deserialize correctly
    let p0 = payload_json(&events[0]);
    assert_eq!(p0["type"], "SessionCreated");
    assert_eq!(p0["name"], "forward-compat");

    // Message (index 1) should still deserialize correctly
    let p1 = payload_json(&events[1]);
    assert_eq!(p1["type"], "Message");
    assert_eq!(p1["role"], "user");
    assert_eq!(p1["content"], "Do something futuristic");

    // Message (index 3) should still deserialize correctly alongside the Custom event
    let p3 = payload_json(&events[3]);
    assert_eq!(p3["type"], "Message");
    assert_eq!(p3["role"], "assistant");
    assert_eq!(p3["content"], "I see a cat outdoors.");
}
