//! Topology-B end-to-end wire test for BRO-1017.
//!
//! Boots a minimal `RedbJournal`, exposes `lago.v1.LagoSubstrate` on a
//! tempdir UDS, dials it via the `lago-proxy` crate's `LagoProxy`
//! builder, and asserts that:
//!
//! 1. `LagoProxy::append_event(ns, ty, payload)` actually produces a
//!    real journal entry on disk (not the placeholder
//!    `idem_persist`-as-append shim that the previous proxy used).
//! 2. `LagoProxy::list_namespaces(prefix)` returns the real
//!    namespaces journaled by the substrate (sessions registered via
//!    `put_session` AND event-only namespaces created by `Append`).
//! 3. End-to-end through a temp UDS: spin up the substrate server,
//!    construct a `LagoProxy` against it, exercise both methods, and
//!    verify the round-trip is sourced from a real `RedbJournal`.
//!
//! This is the contract Phase 2 of the four-PR Topology-B audit
//! (entity page `research/entities/concept/topology-b-substrate-stub-gap.md`)
//! demanded a real wire for. lifed isn't wired in here — adding it
//! would pull lagod into the `lifed`/`lago-proxy` dep tree and break
//! `scripts/verify_dependencies_lifed.sh`. The lifed→lago-proxy
//! boundary is already covered by lifed's own integration suite (it
//! exercises the proxy trait), so end-to-end coverage in production
//! is the COMPOSITION of those two suites — mirroring the BRO-1016
//! arcan-side test.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aios_protocol::EventKind;
use lago_core::{BranchId, EventQuery, Journal, Session, SessionConfig, SessionId};
use lago_journal::RedbJournal;
use lago_proxy::LagoProxy;
use lago_substrate_proto::lago::v1::lago_substrate_server::LagoSubstrateServer;
use lagod::substrate::SubstrateService;
use tempfile::TempDir;
use tokio::sync::oneshot;

/// Spin up the substrate gRPC server on a tempdir UDS socket and
/// return the socket path + shutdown handle. The server consumes a
/// shared `Arc<dyn Journal>` so the test can read its state after
/// driving calls through the proxy.
struct SubstrateUnderTest {
    socket: PathBuf,
    _tempdir: TempDir,
    journal: Arc<RedbJournal>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    server_handle: Option<tokio::task::JoinHandle<()>>,
}

impl SubstrateUnderTest {
    async fn start() -> Self {
        let tempdir = TempDir::new().expect("tempdir");
        let socket = tempdir.path().join("lagod.sock");
        let db_path = tempdir.path().join("journal.redb");
        let journal = Arc::new(RedbJournal::open(&db_path).expect("open journal"));

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let service = SubstrateService::new(Arc::clone(&journal) as Arc<dyn Journal>);
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind UDS");
        let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener);

        let server_handle = tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(LagoSubstrateServer::new(service))
                .serve_with_incoming_shutdown(incoming, async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        // Wait for the socket to appear.
        for _ in 0..200 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(socket.exists(), "substrate socket bound");

        Self {
            socket,
            _tempdir: tempdir,
            journal,
            shutdown_tx: Some(shutdown_tx),
            server_handle: Some(server_handle),
        }
    }

    async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.server_handle.take() {
            let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
        }
    }
}

#[tokio::test]
async fn append_actually_writes_to_journal() {
    let env = SubstrateUnderTest::start().await;
    let proxy = LagoProxy::connect(env.socket.clone())
        .await
        .expect("dial substrate UDS");

    let namespace = "session/bro-1017-append";
    let event_type = "saga.test";
    let payload = serde_json::json!({"step": "started", "n": 7});
    let payload_bytes = serde_json::to_vec(&payload).expect("encode payload");

    // BEFORE BRO-1017 this would have routed through `idem_persist`
    // and never produced an `EventQuery` hit. AFTER BRO-1017 the
    // substrate journals a real `EventKind::Custom` envelope.
    proxy
        .append_event(namespace, event_type, payload_bytes)
        .await
        .expect("append_event");

    // Substrate-side proof: read the journal directly. The event must
    // be visible to `Events.Read` / `Subscribe` callers downstream.
    let events = env
        .journal
        .read(
            EventQuery::new()
                .session(SessionId::from_string(namespace))
                .branch(BranchId::from_string("main")),
        )
        .await
        .expect("read journal");

    assert_eq!(events.len(), 1, "exactly one journaled event");
    let envelope = &events[0];
    assert_eq!(envelope.session_id.as_str(), namespace);
    assert_eq!(envelope.branch_id.as_str(), "main");
    assert!(envelope.seq >= 1, "monotonic seq assigned");
    match &envelope.payload {
        EventKind::Custom {
            event_type: et,
            data,
        } => {
            assert_eq!(et, event_type);
            assert_eq!(data, &payload);
        }
        other => panic!("expected EventKind::Custom, got: {other:?}"),
    }

    // Issuing the same logical event again produces ANOTHER row (the
    // substrate is append-only, NOT idempotent at this layer — that's
    // a lifed-saga concern). Phase 2 documents this; the dedup-by-key
    // shim is gone.
    let payload_bytes2 = serde_json::to_vec(&payload).expect("encode payload again");
    proxy
        .append_event(namespace, event_type, payload_bytes2)
        .await
        .expect("append_event #2");
    let events2 = env
        .journal
        .read(
            EventQuery::new()
                .session(SessionId::from_string(namespace))
                .branch(BranchId::from_string("main")),
        )
        .await
        .expect("read journal #2");
    assert_eq!(events2.len(), 2, "re-issued event becomes a second row");
    assert_eq!(events2[1].seq, events2[0].seq + 1);

    env.shutdown().await;
}

#[tokio::test]
async fn list_namespaces_returns_real_namespaces() {
    let env = SubstrateUnderTest::start().await;
    let proxy = LagoProxy::connect(env.socket.clone())
        .await
        .expect("dial substrate UDS");

    // BEFORE BRO-1017 this would have returned `Vec::new()` regardless
    // of journal state. AFTER BRO-1017 the substrate enumerates both
    // `put_session`-registered sessions and event-only namespaces.

    // 1. Register one "real" session via put_session (the path arcand
    //    uses for its kernel-bound event journal).
    let registered_sid = "session/bro-1017-registered";
    env.journal
        .put_session(Session {
            session_id: SessionId::from_string(registered_sid),
            config: SessionConfig {
                name: "registered".to_string(),
                model: "test".to_string(),
                params: std::collections::HashMap::new(),
            },
            created_at: lago_core::EventEnvelope::now_micros(),
            branches: vec![],
        })
        .await
        .expect("put_session");

    // 2. Append into a DIFFERENT namespace via the proxy — this
    //    namespace exists only in the event journal, NOT the sessions
    //    table (matches lifed's saga journaling path:
    //    `system/lifed/saga/<id>`).
    let event_only_ns = "system/lifed/saga/bro-1017-saga";
    let payload = serde_json::json!({"event": "first"});
    proxy
        .append_event(
            event_only_ns,
            "saga.started",
            serde_json::to_vec(&payload).unwrap(),
        )
        .await
        .expect("append_event");

    // 3. Append a third namespace under a different prefix so prefix
    //    filtering can be tested.
    let other_ns = "other/bro-1017-ns";
    proxy
        .append_event(other_ns, "external", serde_json::to_vec(&payload).unwrap())
        .await
        .expect("append_event other");

    // List with no prefix — should pick up all three.
    let mut all = proxy
        .list_namespaces("")
        .await
        .expect("list_namespaces all");
    all.sort();
    assert!(
        all.contains(&registered_sid.to_string()),
        "registered session present: {all:?}"
    );
    assert!(
        all.contains(&event_only_ns.to_string()),
        "event-only namespace present: {all:?}"
    );
    assert!(
        all.contains(&other_ns.to_string()),
        "other namespace present: {all:?}"
    );

    // List with `session/` prefix — picks up only the registered one.
    let session_only = proxy
        .list_namespaces("session/")
        .await
        .expect("list_namespaces session/");
    assert!(
        session_only.iter().all(|n| n.starts_with("session/")),
        "all results start with prefix: {session_only:?}"
    );
    assert!(session_only.contains(&registered_sid.to_string()));
    assert!(!session_only.contains(&event_only_ns.to_string()));

    // List with `system/lifed/` prefix — picks up the saga namespace.
    let saga_only = proxy
        .list_namespaces("system/lifed/")
        .await
        .expect("list_namespaces system/lifed/");
    assert_eq!(saga_only, vec![event_only_ns.to_string()]);

    env.shutdown().await;
}

#[tokio::test]
async fn proxy_to_server_round_trip() {
    // End-to-end smoke: drive several appends + a list_namespaces
    // call through the proxy and confirm the server-emitted shape
    // matches what the proxy hands back. Bridges the unit tests of
    // each layer with a single observable round-trip.
    let env = SubstrateUnderTest::start().await;
    let proxy = LagoProxy::connect(env.socket.clone())
        .await
        .expect("dial substrate UDS");

    let ns = "session/bro-1017-round-trip";
    for i in 0..5u32 {
        let payload = serde_json::json!({"i": i});
        proxy
            .append_event(ns, "tick", serde_json::to_vec(&payload).unwrap())
            .await
            .expect("append");
    }

    // Substrate side: 5 events on the main branch.
    let events = env
        .journal
        .read(
            EventQuery::new()
                .session(SessionId::from_string(ns))
                .branch(BranchId::from_string("main")),
        )
        .await
        .expect("journal read");
    assert_eq!(events.len(), 5);
    let seqs: Vec<_> = events.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, vec![1, 2, 3, 4, 5]);

    // Proxy side: `list_namespaces` sees the namespace despite no
    // `put_session` call (the path-only-event-journal case).
    let ns_list = proxy
        .list_namespaces("session/bro-1017-")
        .await
        .expect("list_namespaces");
    assert_eq!(ns_list, vec![ns.to_string()]);

    // Empty payload is accepted (proto says "an empty payload is
    // stored as JSON null").
    proxy
        .append_event(ns, "empty", Vec::new())
        .await
        .expect("append empty");
    let events_after = env
        .journal
        .read(EventQuery::new().session(SessionId::from_string(ns)))
        .await
        .expect("journal read after empty");
    assert_eq!(events_after.len(), 6);
    match &events_after[5].payload {
        EventKind::Custom { event_type, data } => {
            assert_eq!(event_type, "empty");
            assert!(data.is_null(), "empty payload stored as JSON null");
        }
        other => panic!("expected EventKind::Custom, got: {other:?}"),
    }

    env.shutdown().await;
}
