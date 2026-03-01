use std::sync::Arc;

use aios_protocol::{
    BranchId as ProtocolBranchId, EventRecord, EventRecordStream, EventStorePort, KernelError,
    SessionId as ProtocolSessionId,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::{StreamExt, stream::BoxStream};
use lago_core::protocol_bridge;
use lago_core::{EventQuery, Journal};
use tracing::warn;

fn to_kernel_error(error: impl std::fmt::Display) -> KernelError {
    KernelError::Runtime(error.to_string())
}

fn micros_to_datetime(timestamp_micros: u64) -> Result<DateTime<Utc>, KernelError> {
    DateTime::<Utc>::from_timestamp_micros(timestamp_micros as i64).ok_or_else(|| {
        KernelError::InvalidState(format!("invalid timestamp micros: {timestamp_micros}"))
    })
}

fn envelope_to_record(envelope: aios_protocol::EventEnvelope) -> Result<EventRecord, KernelError> {
    Ok(EventRecord {
        event_id: envelope.event_id,
        session_id: envelope.session_id,
        agent_id: envelope.agent_id,
        branch_id: envelope.branch_id,
        sequence: envelope.seq,
        timestamp: micros_to_datetime(envelope.timestamp)?,
        actor: envelope.actor,
        schema: envelope.schema,
        causation_id: envelope.parent_id,
        correlation_id: envelope.metadata.get("correlation_id").cloned(),
        trace_id: envelope.trace_id,
        span_id: envelope.span_id,
        digest: envelope.digest,
        kind: envelope.kind,
    })
}

#[derive(Clone)]
pub struct LagoAiosEventStoreAdapter {
    journal: Arc<dyn Journal>,
}

impl LagoAiosEventStoreAdapter {
    pub fn new(journal: Arc<dyn Journal>) -> Self {
        Self { journal }
    }
}

#[async_trait]
impl EventStorePort for LagoAiosEventStoreAdapter {
    async fn append(&self, event: EventRecord) -> Result<EventRecord, KernelError> {
        let protocol_envelope = event.to_envelope();
        let lago_envelope =
            protocol_bridge::from_protocol(&protocol_envelope).ok_or_else(|| {
                KernelError::Serialization("failed converting protocol envelope".to_owned())
            })?;
        let assigned_seq = self
            .journal
            .append(lago_envelope)
            .await
            .map_err(to_kernel_error)?;

        let mut persisted = event;
        persisted.sequence = assigned_seq;
        Ok(persisted)
    }

    async fn read(
        &self,
        session_id: ProtocolSessionId,
        branch_id: ProtocolBranchId,
        from_sequence: u64,
        limit: usize,
    ) -> Result<Vec<EventRecord>, KernelError> {
        let query = EventQuery::new()
            .session(session_id.into())
            .branch(branch_id.into())
            .after(from_sequence.saturating_sub(1))
            .limit(limit);
        let events = self.journal.read(query).await.map_err(to_kernel_error)?;

        events
            .into_iter()
            .map(|envelope| {
                let protocol = envelope.to_protocol().ok_or_else(|| {
                    KernelError::Serialization("failed converting lago envelope".to_owned())
                })?;
                envelope_to_record(protocol)
            })
            .collect()
    }

    async fn head(
        &self,
        session_id: ProtocolSessionId,
        branch_id: ProtocolBranchId,
    ) -> Result<u64, KernelError> {
        self.journal
            .head_seq(&session_id.into(), &branch_id.into())
            .await
            .map_err(to_kernel_error)
    }

    async fn subscribe(
        &self,
        session_id: ProtocolSessionId,
        branch_id: ProtocolBranchId,
        after_sequence: u64,
    ) -> Result<EventRecordStream, KernelError> {
        let stream = self
            .journal
            .stream(
                session_id.clone().into(),
                branch_id.clone().into(),
                after_sequence,
            )
            .await
            .map_err(to_kernel_error)?;

        let adapted = stream.filter_map(|item| async move {
            match item {
                Ok(envelope) => {
                    let protocol = match envelope.to_protocol() {
                        Some(protocol) => protocol,
                        None => {
                            warn!("failed converting lago event envelope to protocol");
                            return Some(Err(KernelError::Serialization(
                                "failed converting lago envelope".to_owned(),
                            )));
                        }
                    };
                    Some(envelope_to_record(protocol))
                }
                Err(error) => Some(Err(to_kernel_error(error))),
            }
        });

        Ok(Box::pin(adapted) as BoxStream<'static, Result<EventRecord, KernelError>>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aios_protocol::EventKind;
    use futures_util::StreamExt;
    use lago_journal::RedbJournal;
    use tempfile::TempDir;

    fn setup() -> (TempDir, LagoAiosEventStoreAdapter) {
        let dir = TempDir::new().unwrap();
        let journal = Arc::new(RedbJournal::open(&dir.path().join("test.redb")).unwrap());
        (dir, LagoAiosEventStoreAdapter::new(journal))
    }

    fn make_record(session: &str, branch: &str, kind: EventKind) -> EventRecord {
        EventRecord::new(
            ProtocolSessionId::from_string(session),
            ProtocolBranchId::from_string(branch),
            0, // seq ignored — journal assigns monotonic sequences
            kind,
        )
    }

    #[tokio::test]
    async fn append_returns_assigned_sequence() {
        let (_dir, adapter) = setup();
        let record = make_record(
            "sess-1",
            "main",
            EventKind::Message {
                role: "user".into(),
                content: "hello".into(),
                model: None,
                token_usage: None,
            },
        );
        let result = adapter.append(record).await.unwrap();
        assert_eq!(result.sequence, 1);
    }

    #[tokio::test]
    async fn append_and_read_round_trip() {
        let (_dir, adapter) = setup();
        let sid = ProtocolSessionId::from_string("sess-rt");
        let bid = ProtocolBranchId::from_string("main");

        let record = make_record(
            "sess-rt",
            "main",
            EventKind::Message {
                role: "assistant".into(),
                content: "Hello, world!".into(),
                model: Some("gpt-4".into()),
                token_usage: None,
            },
        );
        adapter.append(record).await.unwrap();

        let events = adapter.read(sid, bid, 0, 100).await.unwrap();
        assert_eq!(events.len(), 1);
        if let EventKind::Message {
            role,
            content,
            model,
            ..
        } = &events[0].kind
        {
            assert_eq!(role, "assistant");
            assert_eq!(content, "Hello, world!");
            assert_eq!(model.as_deref(), Some("gpt-4"));
        } else {
            panic!("expected Message variant, got {:?}", events[0].kind);
        }
    }

    #[tokio::test]
    async fn append_multiple_sequences_monotonic() {
        let (_dir, adapter) = setup();
        let mut seqs = Vec::new();
        for i in 0..3 {
            let record = make_record(
                "sess-mono",
                "main",
                EventKind::Message {
                    role: "user".into(),
                    content: format!("msg {i}"),
                    model: None,
                    token_usage: None,
                },
            );
            let result = adapter.append(record).await.unwrap();
            seqs.push(result.sequence);
        }
        assert_eq!(seqs, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn read_with_from_sequence_filter() {
        let (_dir, adapter) = setup();
        let sid = ProtocolSessionId::from_string("sess-filter");
        let bid = ProtocolBranchId::from_string("main");

        for i in 0..5 {
            let record = make_record(
                "sess-filter",
                "main",
                EventKind::Message {
                    role: "user".into(),
                    content: format!("msg {i}"),
                    model: None,
                    token_usage: None,
                },
            );
            adapter.append(record).await.unwrap();
        }

        // from_sequence=3 should return events with seq >= 3
        let events = adapter.read(sid, bid, 3, 100).await.unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].sequence, 3);
        assert_eq!(events[1].sequence, 4);
        assert_eq!(events[2].sequence, 5);
    }

    #[tokio::test]
    async fn read_with_limit() {
        let (_dir, adapter) = setup();
        let sid = ProtocolSessionId::from_string("sess-lim");
        let bid = ProtocolBranchId::from_string("main");

        for i in 0..10 {
            let record = make_record(
                "sess-lim",
                "main",
                EventKind::Message {
                    role: "user".into(),
                    content: format!("msg {i}"),
                    model: None,
                    token_usage: None,
                },
            );
            adapter.append(record).await.unwrap();
        }

        let events = adapter.read(sid, bid, 0, 3).await.unwrap();
        assert_eq!(events.len(), 3);
    }

    #[tokio::test]
    async fn read_empty_session_returns_empty() {
        let (_dir, adapter) = setup();
        let sid = ProtocolSessionId::from_string("nonexistent");
        let bid = ProtocolBranchId::from_string("main");

        let events = adapter.read(sid, bid, 0, 100).await.unwrap();
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn head_returns_zero_for_new_session() {
        let (_dir, adapter) = setup();
        let sid = ProtocolSessionId::from_string("new-sess");
        let bid = ProtocolBranchId::from_string("main");

        let head = adapter.head(sid, bid).await.unwrap();
        assert_eq!(head, 0);
    }

    #[tokio::test]
    async fn head_tracks_appends() {
        let (_dir, adapter) = setup();
        let sid = ProtocolSessionId::from_string("sess-head");
        let bid = ProtocolBranchId::from_string("main");

        for i in 0..4 {
            let record = make_record(
                "sess-head",
                "main",
                EventKind::Message {
                    role: "user".into(),
                    content: format!("msg {i}"),
                    model: None,
                    token_usage: None,
                },
            );
            adapter.append(record).await.unwrap();
        }

        let head = adapter.head(sid, bid).await.unwrap();
        assert_eq!(head, 4);
    }

    #[tokio::test]
    async fn subscribe_replays_existing_events() {
        use std::time::Duration;

        let (_dir, adapter) = setup();
        let sid = ProtocolSessionId::from_string("sess-sub");
        let bid = ProtocolBranchId::from_string("main");

        // Append events before subscribing
        for i in 0..3 {
            let record = make_record(
                "sess-sub",
                "main",
                EventKind::Message {
                    role: "user".into(),
                    content: format!("msg {i}"),
                    model: None,
                    token_usage: None,
                },
            );
            adapter.append(record).await.unwrap();
        }

        // Subscribe from seq 0 — should replay all existing events
        let mut stream = adapter.subscribe(sid, bid, 0).await.unwrap();

        // Use timeout since the stream tails indefinitely after replaying
        let first = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("timeout waiting for first event")
            .unwrap()
            .unwrap();
        assert_eq!(first.sequence, 1);

        let second = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("timeout waiting for second event")
            .unwrap()
            .unwrap();
        assert_eq!(second.sequence, 2);

        let third = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("timeout waiting for third event")
            .unwrap()
            .unwrap();
        assert_eq!(third.sequence, 3);
    }

    #[tokio::test]
    async fn tool_call_event_survives_round_trip() {
        let (_dir, adapter) = setup();
        let sid = ProtocolSessionId::from_string("sess-tool");
        let bid = ProtocolBranchId::from_string("main");

        let record = make_record(
            "sess-tool",
            "main",
            EventKind::ToolCallRequested {
                call_id: "call-42".into(),
                tool_name: "read_file".into(),
                arguments: serde_json::json!({"path": "/etc/hosts"}),
                category: Some("fs".into()),
            },
        );
        adapter.append(record).await.unwrap();

        let events = adapter.read(sid, bid, 0, 100).await.unwrap();
        assert_eq!(events.len(), 1);
        if let EventKind::ToolCallRequested {
            call_id,
            tool_name,
            arguments,
            category,
        } = &events[0].kind
        {
            assert_eq!(call_id, "call-42");
            assert_eq!(tool_name, "read_file");
            assert_eq!(arguments["path"], "/etc/hosts");
            assert_eq!(category.as_deref(), Some("fs"));
        } else {
            panic!(
                "expected ToolCallRequested variant, got {:?}",
                events[0].kind
            );
        }
    }

    #[tokio::test]
    async fn custom_event_survives_round_trip() {
        let (_dir, adapter) = setup();
        let sid = ProtocolSessionId::from_string("sess-custom");
        let bid = ProtocolBranchId::from_string("main");

        let record = make_record(
            "sess-custom",
            "main",
            EventKind::Custom {
                event_type: "my.future.event".into(),
                data: serde_json::json!({"key": "value", "count": 42}),
            },
        );
        adapter.append(record).await.unwrap();

        let events = adapter.read(sid, bid, 0, 100).await.unwrap();
        assert_eq!(events.len(), 1);
        if let EventKind::Custom { event_type, data } = &events[0].kind {
            assert_eq!(event_type, "my.future.event");
            assert_eq!(data["key"], "value");
            assert_eq!(data["count"], 42);
        } else {
            panic!("expected Custom variant, got {:?}", events[0].kind);
        }
    }
}
