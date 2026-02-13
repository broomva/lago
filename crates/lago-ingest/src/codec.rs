use lago_core::{BranchId, EventEnvelope, EventId, RunId, SessionId, event::EventPayload};

// --- Proto generated types
use crate::proto;

/// Convert a core EventEnvelope to a proto EventEnvelope.
pub fn event_to_proto(event: &EventEnvelope) -> proto::EventEnvelope {
    proto::EventEnvelope {
        event_id: event.event_id.to_string(),
        session_id: event.session_id.to_string(),
        branch_id: event.branch_id.to_string(),
        run_id: event.run_id.as_ref().map(|r| r.to_string()),
        seq: event.seq,
        timestamp: event.timestamp,
        parent_id: event.parent_id.as_ref().map(|p| p.to_string()),
        payload_json: serde_json::to_string(&event.payload).unwrap_or_default(),
        metadata: event.metadata.clone(),
    }
}

/// Convert a proto EventEnvelope to a core EventEnvelope.
pub fn event_from_proto(proto: proto::EventEnvelope) -> Result<EventEnvelope, serde_json::Error> {
    let payload: EventPayload = serde_json::from_str(&proto.payload_json)?;

    Ok(EventEnvelope {
        event_id: EventId::from_string(proto.event_id),
        session_id: SessionId::from_string(proto.session_id),
        branch_id: BranchId::from_string(proto.branch_id),
        run_id: proto.run_id.map(RunId::from_string),
        seq: proto.seq,
        timestamp: proto.timestamp,
        parent_id: proto.parent_id.map(EventId::from_string),
        payload,
        metadata: proto.metadata,
    })
}

/// Create a proto Ack.
pub fn make_ack(event_id: &str, seq: u64, success: bool, error: Option<String>) -> proto::Ack {
    proto::Ack {
        event_id: event_id.to_string(),
        seq,
        success,
        error,
    }
}

/// Create a proto Heartbeat.
pub fn make_heartbeat() -> proto::Heartbeat {
    proto::Heartbeat {
        timestamp: EventEnvelope::now_micros(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lago_core::event::{EventPayload, RiskLevel, SpanStatus, TokenUsage};
    use lago_core::id::*;
    use std::collections::HashMap;

    fn make_envelope(payload: EventPayload, seq: u64) -> EventEnvelope {
        EventEnvelope {
            event_id: EventId::from_string("EVT001"),
            session_id: SessionId::from_string("SESS001"),
            branch_id: BranchId::from_string("main"),
            run_id: Some(RunId::from_string("RUN001")),
            seq,
            timestamp: 1_700_000_000_000_000,
            parent_id: Some(EventId::from_string("EVT000")),
            payload,
            metadata: HashMap::from([("key".to_string(), "val".to_string())]),
        }
    }

    #[test]
    fn message_event_roundtrip() {
        let original = make_envelope(
            EventPayload::Message {
                role: "assistant".to_string(),
                content: "Hello!".to_string(),
                model: Some("gpt-4".to_string()),
                token_usage: Some(TokenUsage {
                    prompt_tokens: 10,
                    completion_tokens: 20,
                    total_tokens: 30,
                }),
            },
            42,
        );

        let proto = event_to_proto(&original);
        assert_eq!(proto.event_id, "EVT001");
        assert_eq!(proto.session_id, "SESS001");
        assert_eq!(proto.branch_id, "main");
        assert_eq!(proto.run_id, Some("RUN001".to_string()));
        assert_eq!(proto.seq, 42);
        assert_eq!(proto.timestamp, 1_700_000_000_000_000);
        assert_eq!(proto.parent_id, Some("EVT000".to_string()));
        assert_eq!(proto.metadata["key"], "val");
        assert!(proto.payload_json.contains("Message"));

        let back = event_from_proto(proto).unwrap();
        assert_eq!(back.event_id.as_str(), "EVT001");
        assert_eq!(back.session_id.as_str(), "SESS001");
        assert_eq!(back.seq, 42);
        assert_eq!(back.run_id.as_ref().unwrap().as_str(), "RUN001");
        assert_eq!(back.parent_id.as_ref().unwrap().as_str(), "EVT000");
        if let EventPayload::Message {
            role,
            content,
            model,
            ..
        } = &back.payload
        {
            assert_eq!(role, "assistant");
            assert_eq!(content, "Hello!");
            assert_eq!(model.as_deref(), Some("gpt-4"));
        } else {
            panic!("wrong payload variant");
        }
    }

    #[test]
    fn file_write_event_roundtrip() {
        let original = make_envelope(
            EventPayload::FileWrite {
                path: "/src/lib.rs".to_string(),
                blob_hash: BlobHash::from_hex("deadbeef"),
                size_bytes: 2048,
                content_type: Some("text/rust".to_string()),
            },
            7,
        );
        let proto = event_to_proto(&original);
        let back = event_from_proto(proto).unwrap();
        if let EventPayload::FileWrite {
            path,
            blob_hash,
            size_bytes,
            ..
        } = &back.payload
        {
            assert_eq!(path, "/src/lib.rs");
            assert_eq!(blob_hash.as_str(), "deadbeef");
            assert_eq!(*size_bytes, 2048);
        } else {
            panic!("wrong payload variant");
        }
    }

    #[test]
    fn tool_invoke_roundtrip() {
        let original = make_envelope(
            EventPayload::ToolInvoke {
                call_id: "call-1".to_string(),
                tool_name: "exec".to_string(),
                arguments: serde_json::json!({"cmd": "ls -la"}),
                category: Some("shell".to_string()),
            },
            1,
        );
        let proto = event_to_proto(&original);
        let back = event_from_proto(proto).unwrap();
        if let EventPayload::ToolInvoke { tool_name, .. } = &back.payload {
            assert_eq!(tool_name, "exec");
        } else {
            panic!("wrong payload variant");
        }
    }

    #[test]
    fn tool_result_roundtrip() {
        let original = make_envelope(
            EventPayload::ToolResult {
                call_id: "call-1".to_string(),
                tool_name: "exec".to_string(),
                result: serde_json::json!({"stdout": "hello"}),
                duration_ms: 150,
                status: SpanStatus::Ok,
            },
            2,
        );
        let proto = event_to_proto(&original);
        let back = event_from_proto(proto).unwrap();
        if let EventPayload::ToolResult {
            status,
            duration_ms,
            ..
        } = &back.payload
        {
            assert_eq!(*status, SpanStatus::Ok);
            assert_eq!(*duration_ms, 150);
        } else {
            panic!("wrong payload variant");
        }
    }

    #[test]
    fn approval_events_roundtrip() {
        let original = make_envelope(
            EventPayload::ApprovalRequested {
                approval_id: ApprovalId::from_string("APR001"),
                call_id: "call-1".to_string(),
                tool_name: "rm".to_string(),
                arguments: serde_json::json!({}),
                risk: RiskLevel::Critical,
            },
            3,
        );
        let back = event_from_proto(event_to_proto(&original)).unwrap();
        if let EventPayload::ApprovalRequested { risk, .. } = &back.payload {
            assert_eq!(*risk, RiskLevel::Critical);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn event_without_optional_fields_roundtrip() {
        let original = EventEnvelope {
            event_id: EventId::from_string("E1"),
            session_id: SessionId::from_string("S1"),
            branch_id: BranchId::from_string("main"),
            run_id: None,
            seq: 1,
            timestamp: 100,
            parent_id: None,
            payload: EventPayload::FileDelete {
                path: "/tmp/x".to_string(),
            },
            metadata: HashMap::new(),
        };
        let proto = event_to_proto(&original);
        assert!(proto.run_id.is_none());
        assert!(proto.parent_id.is_none());
        assert!(proto.metadata.is_empty());

        let back = event_from_proto(proto).unwrap();
        assert!(back.run_id.is_none());
        assert!(back.parent_id.is_none());
    }

    #[test]
    fn invalid_payload_json_returns_error() {
        let bad_proto = proto::EventEnvelope {
            event_id: "E1".into(),
            session_id: "S1".into(),
            branch_id: "main".into(),
            run_id: None,
            seq: 1,
            timestamp: 100,
            parent_id: None,
            payload_json: "{not valid json!!!".into(),
            metadata: HashMap::new(),
        };
        assert!(event_from_proto(bad_proto).is_err());
    }

    #[test]
    fn make_ack_success() {
        let ack = make_ack("EVT001", 42, true, None);
        assert_eq!(ack.event_id, "EVT001");
        assert_eq!(ack.seq, 42);
        assert!(ack.success);
        assert!(ack.error.is_none());
    }

    #[test]
    fn make_ack_failure() {
        let ack = make_ack("EVT002", 0, false, Some("boom".into()));
        assert_eq!(ack.event_id, "EVT002");
        assert!(!ack.success);
        assert_eq!(ack.error.as_deref(), Some("boom"));
    }

    #[test]
    fn heartbeat_has_timestamp() {
        let hb = make_heartbeat();
        assert!(hb.timestamp > 0);
    }
}
