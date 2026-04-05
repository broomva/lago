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

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn load_fixture(name: &str) -> Vec<EventEnvelope> {
    let path = format!("{FIXTURES_DIR}/{name}");
    let data = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

fn setup() -> (TempDir, RedbJournal) {
    let dir = TempDir::new().unwrap();
    let journal = RedbJournal::open(dir.path().join("golden.redb")).unwrap();
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

// ─── branch-merge fixtures ──────────────────────────────────────────────────

#[tokio::test]
async fn golden_branch_merge_main_events_intact() {
    let fixtures = load_fixture("branch-merge.json");
    assert_eq!(
        fixtures.len(),
        8,
        "branch-merge fixture should have 8 events"
    );

    let (_dir, journal) = setup();
    ingest(&journal, &fixtures).await;

    // Main branch: SessionCreated, 2 Messages, BranchCreated, concurrent Message, BranchMerged = 6 events
    let main_events = journal
        .read(
            EventQuery::new()
                .session(SessionId::from_string("GOLDEN-BRANCH-MERGE"))
                .branch(BranchId::from_string("main")),
        )
        .await
        .unwrap();
    assert_eq!(main_events.len(), 6, "main branch should have 6 events");

    // Verify event types in order
    let p0 = payload_json(&main_events[0]);
    assert_eq!(p0["type"], "SessionCreated");
    assert_eq!(p0["name"], "branch-merge");

    let p1 = payload_json(&main_events[1]);
    assert_eq!(p1["type"], "Message");
    assert_eq!(p1["role"], "user");
    assert_eq!(p1["content"], "Start the experiment");

    let p2 = payload_json(&main_events[2]);
    assert_eq!(p2["type"], "Message");
    assert_eq!(p2["role"], "assistant");

    let p3 = payload_json(&main_events[3]);
    assert_eq!(p3["type"], "BranchCreated");
    assert_eq!(p3["new_branch_id"], "experiment");
    assert_eq!(p3["fork_point_seq"], 3);

    let p4 = payload_json(&main_events[4]);
    assert_eq!(p4["type"], "Message");
    assert_eq!(p4["role"], "user");
    assert_eq!(p4["content"], "Continue work on main while experiment runs");

    let p5 = payload_json(&main_events[5]);
    assert_eq!(p5["type"], "BranchMerged");
    assert_eq!(p5["source_branch_id"], "experiment");
    assert_eq!(p5["merge_seq"], 2);
}

#[tokio::test]
async fn golden_branch_merge_experiment_isolated() {
    let fixtures = load_fixture("branch-merge.json");
    let (_dir, journal) = setup();
    ingest(&journal, &fixtures).await;

    // Experiment branch: exactly 2 events (user + assistant messages)
    let experiment_events = journal
        .read(
            EventQuery::new()
                .session(SessionId::from_string("GOLDEN-BRANCH-MERGE"))
                .branch(BranchId::from_string("experiment")),
        )
        .await
        .unwrap();
    assert_eq!(
        experiment_events.len(),
        2,
        "experiment branch should have exactly 2 events"
    );

    let ep0 = payload_json(&experiment_events[0]);
    assert_eq!(ep0["type"], "Message");
    assert_eq!(ep0["role"], "user");
    assert_eq!(ep0["content"], "Run the experiment on this branch");

    let ep1 = payload_json(&experiment_events[1]);
    assert_eq!(ep1["type"], "Message");
    assert_eq!(ep1["role"], "assistant");
    assert_eq!(ep1["content"], "Experiment complete. Results are positive.");
}

#[tokio::test]
async fn golden_branch_merge_head_sequences() {
    let fixtures = load_fixture("branch-merge.json");
    let (_dir, journal) = setup();
    ingest(&journal, &fixtures).await;

    let main_head = journal
        .head_seq(
            &SessionId::from_string("GOLDEN-BRANCH-MERGE"),
            &BranchId::from_string("main"),
        )
        .await
        .unwrap();
    assert_eq!(main_head, 6, "main branch head_seq should be 6");

    let experiment_head = journal
        .head_seq(
            &SessionId::from_string("GOLDEN-BRANCH-MERGE"),
            &BranchId::from_string("experiment"),
        )
        .await
        .unwrap();
    assert_eq!(experiment_head, 2, "experiment branch head_seq should be 2");
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

// ─── forward-compat-evolution fixtures ──────────────────────────────────────

#[tokio::test]
async fn golden_forward_compat_evolution_mixed_versions() {
    let fixtures = load_fixture("forward-compat-evolution.json");
    assert_eq!(
        fixtures.len(),
        5,
        "forward-compat-evolution fixture should have 5 events"
    );

    let (_dir, journal) = setup();
    ingest(&journal, &fixtures).await;

    let events = journal
        .read(
            EventQuery::new()
                .session(SessionId::from_string("GOLDEN-FORWARD-COMPAT-EVOLUTION"))
                .branch(BranchId::from_string("main")),
        )
        .await
        .unwrap();
    assert_eq!(events.len(), 5, "all 5 events should survive round-trip");

    // v2 unknown "AgentMetrics" becomes Custom
    let p2 = payload_json(&events[2]);
    assert_eq!(p2["type"], "Custom");
    assert_eq!(p2["event_type"], "AgentMetrics");
    assert_eq!(p2["data"]["metrics"]["tokens_used"], 1500);
    assert_eq!(p2["data"]["metrics"]["latency_ms"], 230);
    assert_eq!(p2["data"]["sampling_rate"], 0.5);

    // v2 unknown "CodeReview" becomes Custom
    let p3 = payload_json(&events[3]);
    assert_eq!(p3["type"], "Custom");
    assert_eq!(p3["event_type"], "CodeReview");
    assert_eq!(p3["data"]["file"], "src/main.rs");
    assert_eq!(p3["data"]["diff_hash"], "sha256:abcdef1234567890");
    assert_eq!(p3["data"]["verdict"], "approve");
}

#[tokio::test]
async fn golden_forward_compat_evolution_preserves_schema_version() {
    let fixtures = load_fixture("forward-compat-evolution.json");
    let (_dir, journal) = setup();
    ingest(&journal, &fixtures).await;

    let events = journal
        .read(
            EventQuery::new()
                .session(SessionId::from_string("GOLDEN-FORWARD-COMPAT-EVOLUTION"))
                .branch(BranchId::from_string("main")),
        )
        .await
        .unwrap();

    // v1 events
    assert_eq!(events[0].schema_version, 1, "SessionCreated should be v1");
    assert_eq!(events[1].schema_version, 1, "Message should be v1");
    // v2 events
    assert_eq!(events[2].schema_version, 2, "AgentMetrics should be v2");
    assert_eq!(events[3].schema_version, 2, "CodeReview should be v2");
    // v1 event after unknowns
    assert_eq!(events[4].schema_version, 1, "trailing Message should be v1");
}

#[tokio::test]
async fn golden_forward_compat_evolution_known_events_unaffected() {
    let fixtures = load_fixture("forward-compat-evolution.json");
    let (_dir, journal) = setup();
    ingest(&journal, &fixtures).await;

    let events = journal
        .read(
            EventQuery::new()
                .session(SessionId::from_string("GOLDEN-FORWARD-COMPAT-EVOLUTION"))
                .branch(BranchId::from_string("main")),
        )
        .await
        .unwrap();

    // Known v1 events at indices 0, 1, 4 should be unaffected by v2 unknowns
    let p0 = payload_json(&events[0]);
    assert_eq!(p0["type"], "SessionCreated");
    assert_eq!(p0["name"], "forward-compat-evolution");

    let p1 = payload_json(&events[1]);
    assert_eq!(p1["type"], "Message");
    assert_eq!(p1["role"], "user");
    assert_eq!(p1["content"], "Run the metrics pipeline");

    let p4 = payload_json(&events[4]);
    assert_eq!(p4["type"], "Message");
    assert_eq!(p4["role"], "assistant");
    assert_eq!(p4["content"], "Metrics collected and code reviewed.");
}
