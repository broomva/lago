//! Event types for Lago.
//!
//! As of this version, Lago uses `aios_protocol::EventKind` as the canonical
//! payload type for all events. The `EventPayload` type alias preserves
//! backward compatibility with existing code that references `EventPayload`.

use crate::id::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Re-export the canonical event payload from aios-protocol ──────────────

/// The event payload type used by Lago.
///
/// This is the canonical `aios_protocol::EventKind` — all events stored
/// in Lago's journal use the Agent OS protocol types directly.
pub type EventPayload = aios_protocol::EventKind;

// ─── Re-export supporting types from aios-protocol ─────────────────────────

pub use aios_protocol::MemoryScope;
pub use aios_protocol::event::{
    ApprovalDecision, PolicyDecisionKind, RiskLevel, SnapshotType, SpanStatus, TokenUsage,
};

// ─── EventEnvelope ─────────────────────────────────────────────────────────

/// The universal unit of state change in Lago.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub event_id: EventId,
    pub session_id: SessionId,
    pub branch_id: BranchId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<RunId>,
    pub seq: SeqNo,
    pub timestamp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<EventId>,
    pub payload: EventPayload,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    /// Schema version for forward compatibility. Defaults to 1.
    #[serde(default = "default_schema_version")]
    pub schema_version: u8,
}

fn default_schema_version() -> u8 {
    1
}

impl EventEnvelope {
    pub fn now_micros() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_envelope(payload: EventPayload) -> EventEnvelope {
        EventEnvelope {
            event_id: EventId::from_string("EVT001"),
            session_id: SessionId::from_string("SESS001"),
            branch_id: BranchId::from_string("main"),
            run_id: None,
            seq: 1,
            timestamp: 1_700_000_000_000_000,
            parent_id: None,
            payload,
            metadata: HashMap::new(),
            schema_version: 1,
        }
    }

    #[test]
    fn now_micros_returns_nonzero() {
        let ts = EventEnvelope::now_micros();
        assert!(ts > 0);
    }

    #[test]
    fn now_micros_is_monotonic() {
        let a = EventEnvelope::now_micros();
        let b = EventEnvelope::now_micros();
        assert!(b >= a);
    }

    #[test]
    fn message_payload_serde_roundtrip() {
        let payload = EventPayload::Message {
            role: "assistant".to_string(),
            content: "Hello, world!".to_string(),
            model: Some("gpt-4".to_string()),
            token_usage: Some(TokenUsage {
                prompt_tokens: 10,
                completion_tokens: 20,
                total_tokens: 30,
            }),
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"type\":\"Message\""));
        assert!(json.contains("\"role\":\"assistant\""));
        let back: EventPayload = serde_json::from_str(&json).unwrap();
        if let EventPayload::Message { role, content, .. } = back {
            assert_eq!(role, "assistant");
            assert_eq!(content, "Hello, world!");
        } else {
            panic!("deserialized to wrong variant");
        }
    }

    #[test]
    fn message_delta_serde_roundtrip() {
        let payload = EventPayload::TextDelta {
            delta: "chunk".to_string(),
            index: Some(3),
        };
        let json = serde_json::to_string(&payload).unwrap();
        let back: EventPayload = serde_json::from_str(&json).unwrap();
        if let EventPayload::TextDelta { delta, index, .. } = back {
            assert_eq!(delta, "chunk");
            assert_eq!(index, Some(3));
        } else {
            panic!("deserialized to wrong variant");
        }
    }

    #[test]
    fn file_write_serde_roundtrip() {
        let payload = EventPayload::FileWrite {
            path: "/src/main.rs".to_string(),
            blob_hash: BlobHash::from_hex("abcdef").into(),
            size_bytes: 1024,
            content_type: Some("text/rust".to_string()),
        };
        let json = serde_json::to_string(&payload).unwrap();
        let back: EventPayload = serde_json::from_str(&json).unwrap();
        if let EventPayload::FileWrite {
            path,
            blob_hash,
            size_bytes,
            ..
        } = back
        {
            assert_eq!(path, "/src/main.rs");
            assert_eq!(blob_hash.as_str(), "abcdef");
            assert_eq!(size_bytes, 1024);
        } else {
            panic!("deserialized to wrong variant");
        }
    }

    #[test]
    fn tool_invoke_result_serde_roundtrip() {
        let invoke = EventPayload::ToolCallRequested {
            call_id: "call-1".to_string(),
            tool_name: "read_file".to_string(),
            arguments: serde_json::json!({"path": "/etc/hosts"}),
            category: Some("fs".to_string()),
        };
        let result = EventPayload::ToolCallCompleted {
            tool_run_id: aios_protocol::ToolRunId::default(),
            call_id: Some("call-1".to_string()),
            tool_name: "read_file".to_string(),
            result: serde_json::json!({"content": "127.0.0.1 localhost"}),
            duration_ms: 42,
            status: SpanStatus::Ok,
        };
        let j1 = serde_json::to_string(&invoke).unwrap();
        let j2 = serde_json::to_string(&result).unwrap();
        assert!(j1.contains("\"type\":\"ToolCallRequested\""));
        assert!(j2.contains("\"type\":\"ToolCallCompleted\""));

        let back: EventPayload = serde_json::from_str(&j2).unwrap();
        if let EventPayload::ToolCallCompleted { status, .. } = back {
            assert_eq!(status, SpanStatus::Ok);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn approval_serde_roundtrip() {
        let requested = EventPayload::ApprovalRequested {
            approval_id: ApprovalId::from_string("APR001").into(),
            call_id: "call-1".to_string(),
            tool_name: "rm".to_string(),
            arguments: serde_json::json!({"path": "/"}),
            risk: RiskLevel::Critical,
        };
        let json = serde_json::to_string(&requested).unwrap();
        assert!(json.contains("\"risk\":\"critical\""));

        let resolved = EventPayload::ApprovalResolved {
            approval_id: ApprovalId::from_string("APR001").into(),
            decision: ApprovalDecision::Denied,
            reason: Some("too dangerous".to_string()),
        };
        let j2 = serde_json::to_string(&resolved).unwrap();
        assert!(j2.contains("\"decision\":\"denied\""));
    }

    #[test]
    fn branch_events_serde_roundtrip() {
        let created = EventPayload::BranchCreated {
            new_branch_id: BranchId::from_string("feature-x").into(),
            fork_point_seq: 42,
            name: "feature-x".to_string(),
        };
        let json = serde_json::to_string(&created).unwrap();
        let back: EventPayload = serde_json::from_str(&json).unwrap();
        if let EventPayload::BranchCreated { fork_point_seq, .. } = back {
            assert_eq!(fork_point_seq, 42);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn custom_event_serde_roundtrip() {
        let custom = EventPayload::Custom {
            event_type: "my.custom.event".to_string(),
            data: serde_json::json!({"key": "value"}),
        };
        let json = serde_json::to_string(&custom).unwrap();
        let back: EventPayload = serde_json::from_str(&json).unwrap();
        if let EventPayload::Custom { event_type, data } = back {
            assert_eq!(event_type, "my.custom.event");
            assert_eq!(data["key"], "value");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn full_envelope_serde_roundtrip() {
        let envelope = EventEnvelope {
            event_id: EventId::from_string("EVT001"),
            session_id: SessionId::from_string("SESS001"),
            branch_id: BranchId::from_string("main"),
            run_id: Some(RunId::from_string("RUN001")),
            seq: 42,
            timestamp: 1_700_000_000_000_000,
            parent_id: Some(EventId::from_string("EVT000")),
            payload: EventPayload::Message {
                role: "user".to_string(),
                content: "hi".to_string(),
                model: None,
                token_usage: None,
            },
            metadata: HashMap::from([("key".to_string(), "val".to_string())]),
            schema_version: 1,
        };
        let json = serde_json::to_string(&envelope).unwrap();
        let back: EventEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.seq, 42);
        assert_eq!(back.event_id.as_str(), "EVT001");
        assert_eq!(back.run_id.as_ref().unwrap().as_str(), "RUN001");
        assert_eq!(back.parent_id.as_ref().unwrap().as_str(), "EVT000");
        assert_eq!(back.metadata["key"], "val");
    }

    #[test]
    fn envelope_optional_fields_skip_when_none() {
        let envelope = make_test_envelope(EventPayload::FileDelete {
            path: "/tmp/test".to_string(),
        });
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(!json.contains("run_id"));
        assert!(!json.contains("parent_id"));
    }

    #[test]
    fn span_status_serde() {
        assert_eq!(serde_json::to_string(&SpanStatus::Ok).unwrap(), "\"ok\"");
        assert_eq!(
            serde_json::to_string(&SpanStatus::Error).unwrap(),
            "\"error\""
        );
        assert_eq!(
            serde_json::to_string(&SpanStatus::Timeout).unwrap(),
            "\"timeout\""
        );
        assert_eq!(
            serde_json::to_string(&SpanStatus::Cancelled).unwrap(),
            "\"cancelled\""
        );
    }

    #[test]
    fn risk_level_serde() {
        assert_eq!(serde_json::to_string(&RiskLevel::Low).unwrap(), "\"low\"");
        assert_eq!(
            serde_json::to_string(&RiskLevel::Critical).unwrap(),
            "\"critical\""
        );
    }

    #[test]
    fn snapshot_type_serde() {
        assert_eq!(
            serde_json::to_string(&SnapshotType::Full).unwrap(),
            "\"full\""
        );
        assert_eq!(
            serde_json::to_string(&SnapshotType::Incremental).unwrap(),
            "\"incremental\""
        );
    }

    #[test]
    fn policy_decision_kind_serde() {
        assert_eq!(
            serde_json::to_string(&PolicyDecisionKind::RequireApproval).unwrap(),
            "\"require_approval\""
        );
    }

    #[test]
    fn sandbox_created_serde_roundtrip() {
        let payload = EventPayload::SandboxCreated {
            sandbox_id: "sbx-001".to_string(),
            tier: "container".to_string(),
            config: serde_json::json!({
                "tier": "container",
                "allowed_paths": ["/workspace"],
                "allowed_commands": ["cargo"],
                "network_access": false,
                "max_memory_mb": 512,
                "max_cpu_seconds": 60,
            }),
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"type\":\"SandboxCreated\""));
        let back: EventPayload = serde_json::from_str(&json).unwrap();
        if let EventPayload::SandboxCreated {
            sandbox_id, tier, ..
        } = back
        {
            assert_eq!(sandbox_id, "sbx-001");
            assert_eq!(tier, "container");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn sandbox_executed_serde_roundtrip() {
        let payload = EventPayload::SandboxExecuted {
            sandbox_id: "sbx-001".to_string(),
            command: "cargo test".to_string(),
            exit_code: 0,
            duration_ms: 1234,
        };
        let json = serde_json::to_string(&payload).unwrap();
        let back: EventPayload = serde_json::from_str(&json).unwrap();
        if let EventPayload::SandboxExecuted {
            exit_code,
            duration_ms,
            ..
        } = back
        {
            assert_eq!(exit_code, 0);
            assert_eq!(duration_ms, 1234);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn sandbox_violation_serde_roundtrip() {
        let payload = EventPayload::SandboxViolation {
            sandbox_id: "sbx-001".to_string(),
            violation_type: "network_access".to_string(),
            details: "attempted outbound connection to 1.2.3.4:443".to_string(),
        };
        let json = serde_json::to_string(&payload).unwrap();
        let back: EventPayload = serde_json::from_str(&json).unwrap();
        if let EventPayload::SandboxViolation {
            violation_type,
            details,
            ..
        } = back
        {
            assert_eq!(violation_type, "network_access");
            assert!(details.contains("1.2.3.4"));
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn sandbox_destroyed_serde_roundtrip() {
        let payload = EventPayload::SandboxDestroyed {
            sandbox_id: "sbx-001".to_string(),
        };
        let json = serde_json::to_string(&payload).unwrap();
        let back: EventPayload = serde_json::from_str(&json).unwrap();
        if let EventPayload::SandboxDestroyed { sandbox_id } = back {
            assert_eq!(sandbox_id, "sbx-001");
        } else {
            panic!("wrong variant");
        }
    }

    // --- Forward compatibility tests

    #[test]
    fn unknown_variant_deserializes_as_custom() {
        let json = r#"{"type":"VisionResult","image_hash":"abc123","confidence":0.95}"#;
        let payload: EventPayload = serde_json::from_str(json).unwrap();
        if let EventPayload::Custom { event_type, data } = payload {
            assert_eq!(event_type, "VisionResult");
            assert_eq!(data["image_hash"], "abc123");
            assert_eq!(data["confidence"], 0.95);
        } else {
            panic!("unknown variant should deserialize as Custom");
        }
    }

    #[test]
    fn unknown_variant_with_nested_objects() {
        let json =
            r#"{"type":"FutureAgent","config":{"model":"x","params":[1,2,3]},"active":true}"#;
        let payload: EventPayload = serde_json::from_str(json).unwrap();
        if let EventPayload::Custom { event_type, data } = payload {
            assert_eq!(event_type, "FutureAgent");
            assert_eq!(data["config"]["model"], "x");
            assert_eq!(data["active"], true);
        } else {
            panic!("unknown variant should deserialize as Custom");
        }
    }

    #[test]
    fn unknown_variant_in_full_envelope() {
        let json = r#"{
            "event_id": "EVT999",
            "session_id": "SESS001",
            "branch_id": "main",
            "seq": 100,
            "timestamp": 1700000000000000,
            "payload": {"type":"NewFeature","value":42},
            "metadata": {}
        }"#;
        let envelope: EventEnvelope = serde_json::from_str(json).unwrap();
        assert_eq!(envelope.event_id.as_str(), "EVT999");
        assert_eq!(envelope.schema_version, 1); // default
        if let EventPayload::Custom { event_type, data } = &envelope.payload {
            assert_eq!(event_type, "NewFeature");
            assert_eq!(data["value"], 42);
        } else {
            panic!("unknown variant in envelope should deserialize as Custom");
        }
    }

    #[test]
    fn known_variants_still_deserialize_correctly() {
        // Verify the custom deserializer doesn't break normal operation
        let json = r#"{"type":"FileDelete","path":"/tmp/test"}"#;
        let payload: EventPayload = serde_json::from_str(json).unwrap();
        assert!(matches!(payload, EventPayload::FileDelete { .. }));

        let json = r#"{"type":"Message","role":"user","content":"hi"}"#;
        let payload: EventPayload = serde_json::from_str(json).unwrap();
        if let EventPayload::Message {
            role,
            content,
            model,
            token_usage,
        } = payload
        {
            assert_eq!(role, "user");
            assert_eq!(content, "hi");
            assert!(model.is_none()); // default for missing optional
            assert!(token_usage.is_none());
        } else {
            panic!("known variant should deserialize normally");
        }
    }

    #[test]
    fn schema_version_defaults_to_1() {
        let json = r#"{
            "event_id": "E1",
            "session_id": "S1",
            "branch_id": "main",
            "seq": 0,
            "timestamp": 100,
            "payload": {"type":"Error","error":"boom"},
            "metadata": {}
        }"#;
        let envelope: EventEnvelope = serde_json::from_str(json).unwrap();
        assert_eq!(envelope.schema_version, 1);
    }

    #[test]
    fn schema_version_roundtrips() {
        let envelope = make_test_envelope(EventPayload::ErrorRaised {
            message: "test".to_string(),
        });
        let json = serde_json::to_string(&envelope).unwrap();
        let back: EventEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schema_version, 1);
    }

    // --- Memory event tests

    #[test]
    fn memory_scope_serde_roundtrip() {
        for (scope, expected) in [
            (MemoryScope::Session, "\"session\""),
            (MemoryScope::User, "\"user\""),
            (MemoryScope::Agent, "\"agent\""),
            (MemoryScope::Org, "\"org\""),
        ] {
            let json = serde_json::to_string(&scope).unwrap();
            assert_eq!(json, expected);
            let back: MemoryScope = serde_json::from_str(&json).unwrap();
            assert_eq!(scope, back);
        }
    }

    #[test]
    fn memory_id_uniqueness() {
        let a = MemoryId::new();
        let b = MemoryId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn memory_id_serde_roundtrip() {
        let id = MemoryId::from_string("MEM001");
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"MEM001\"");
        let back: MemoryId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn observation_appended_serde_roundtrip() {
        let payload = EventPayload::ObservationAppended {
            scope: MemoryScope::Session,
            observation_ref: BlobHash::from_hex("abc123").into(),
            source_run_id: Some("run-1".to_string()),
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"type\":\"ObservationAppended\""));
        assert!(json.contains("\"scope\":\"session\""));
        let back: EventPayload = serde_json::from_str(&json).unwrap();
        if let EventPayload::ObservationAppended {
            scope,
            observation_ref,
            source_run_id,
        } = back
        {
            assert_eq!(scope, MemoryScope::Session);
            assert_eq!(observation_ref.as_str(), "abc123");
            assert_eq!(source_run_id.as_deref(), Some("run-1"));
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn reflection_compacted_serde_roundtrip() {
        let payload = EventPayload::ReflectionCompacted {
            scope: MemoryScope::User,
            summary_ref: BlobHash::from_hex("def456").into(),
            covers_through_seq: 42,
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"type\":\"ReflectionCompacted\""));
        let back: EventPayload = serde_json::from_str(&json).unwrap();
        if let EventPayload::ReflectionCompacted {
            scope,
            summary_ref,
            covers_through_seq,
        } = back
        {
            assert_eq!(scope, MemoryScope::User);
            assert_eq!(summary_ref.as_str(), "def456");
            assert_eq!(covers_through_seq, 42);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn memory_proposed_serde_roundtrip() {
        let payload = EventPayload::MemoryProposed {
            scope: MemoryScope::Agent,
            proposal_id: MemoryId::from_string("PROP001").into(),
            entries_ref: BlobHash::from_hex("789abc").into(),
            source_run_id: None,
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"type\":\"MemoryProposed\""));
        assert!(!json.contains("source_run_id")); // None fields are skipped
        let back: EventPayload = serde_json::from_str(&json).unwrap();
        if let EventPayload::MemoryProposed {
            scope,
            proposal_id,
            entries_ref,
            source_run_id,
        } = back
        {
            assert_eq!(scope, MemoryScope::Agent);
            assert_eq!(proposal_id.as_str(), "PROP001");
            assert_eq!(entries_ref.as_str(), "789abc");
            assert!(source_run_id.is_none());
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn memory_committed_serde_roundtrip() {
        let payload = EventPayload::MemoryCommitted {
            scope: MemoryScope::Org,
            memory_id: MemoryId::from_string("MEM001").into(),
            committed_ref: BlobHash::from_hex("deadbeef").into(),
            supersedes: Some(MemoryId::from_string("MEM000").into()),
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"type\":\"MemoryCommitted\""));
        let back: EventPayload = serde_json::from_str(&json).unwrap();
        if let EventPayload::MemoryCommitted {
            scope,
            memory_id,
            committed_ref,
            supersedes,
        } = back
        {
            assert_eq!(scope, MemoryScope::Org);
            assert_eq!(memory_id.as_str(), "MEM001");
            assert_eq!(committed_ref.as_str(), "deadbeef");
            assert_eq!(supersedes.unwrap().as_str(), "MEM000");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn memory_tombstoned_serde_roundtrip() {
        let payload = EventPayload::MemoryTombstoned {
            scope: MemoryScope::Session,
            memory_id: MemoryId::from_string("MEM001").into(),
            reason: "stale information".to_string(),
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"type\":\"MemoryTombstoned\""));
        let back: EventPayload = serde_json::from_str(&json).unwrap();
        if let EventPayload::MemoryTombstoned {
            scope,
            memory_id,
            reason,
        } = back
        {
            assert_eq!(scope, MemoryScope::Session);
            assert_eq!(memory_id.as_str(), "MEM001");
            assert_eq!(reason, "stale information");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn memory_event_full_envelope_roundtrip() {
        let envelope = make_test_envelope(EventPayload::ObservationAppended {
            scope: MemoryScope::User,
            observation_ref: BlobHash::from_hex("cafebabe").into(),
            source_run_id: Some("run-42".to_string()),
        });
        let json = serde_json::to_string(&envelope).unwrap();
        let back: EventEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.event_id.as_str(), "EVT001");
        assert_eq!(back.seq, 1);
        if let EventPayload::ObservationAppended {
            scope,
            observation_ref,
            ..
        } = &back.payload
        {
            assert_eq!(*scope, MemoryScope::User);
            assert_eq!(observation_ref.as_str(), "cafebabe");
        } else {
            panic!("wrong variant in envelope");
        }
    }

    #[test]
    fn memory_optional_fields_default_on_missing() {
        // Deserialize ObservationAppended without source_run_id
        let json = r#"{"type":"ObservationAppended","scope":"session","observation_ref":"abc"}"#;
        let payload: EventPayload = serde_json::from_str(json).unwrap();
        if let EventPayload::ObservationAppended { source_run_id, .. } = payload {
            assert!(source_run_id.is_none());
        } else {
            panic!("wrong variant");
        }

        // Deserialize MemoryCommitted without supersedes
        let json =
            r#"{"type":"MemoryCommitted","scope":"agent","memory_id":"M1","committed_ref":"aaa"}"#;
        let payload: EventPayload = serde_json::from_str(json).unwrap();
        if let EventPayload::MemoryCommitted { supersedes, .. } = payload {
            assert!(supersedes.is_none());
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn memory_scope_equality_and_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(MemoryScope::Session);
        set.insert(MemoryScope::User);
        set.insert(MemoryScope::Agent);
        set.insert(MemoryScope::Org);
        assert_eq!(set.len(), 4);
        assert!(set.contains(&MemoryScope::Session));
        // Inserting duplicate
        set.insert(MemoryScope::Session);
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn existing_variants_still_work_after_memory_addition() {
        // Verify sandbox variants still roundtrip
        let payload = EventPayload::SandboxCreated {
            sandbox_id: "sbx-1".to_string(),
            tier: "container".to_string(),
            config: serde_json::json!({
                "tier": "container",
                "allowed_paths": [],
                "allowed_commands": [],
                "network_access": false,
            }),
        };
        let json = serde_json::to_string(&payload).unwrap();
        let back: EventPayload = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, EventPayload::SandboxCreated { .. }));

        // Verify Message still works
        let payload = EventPayload::Message {
            role: "user".to_string(),
            content: "test".to_string(),
            model: None,
            token_usage: None,
        };
        let json = serde_json::to_string(&payload).unwrap();
        let back: EventPayload = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, EventPayload::Message { .. }));
    }

    #[test]
    fn unknown_memory_variant_falls_back_to_custom() {
        // A future memory event type unknown to this code version
        let json = r#"{"type":"MemoryMerged","scope":"user","source_ids":["M1","M2"]}"#;
        let payload: EventPayload = serde_json::from_str(json).unwrap();
        if let EventPayload::Custom { event_type, data } = payload {
            assert_eq!(event_type, "MemoryMerged");
            assert_eq!(data["scope"], "user");
        } else {
            panic!("unknown memory variant should deserialize as Custom");
        }
    }

    #[test]
    fn unknown_variant_preserves_all_fields() {
        // Verify zero data loss through the unknown variant path
        let json = r#"{"type":"X","a":1,"b":"two","c":[3],"d":{"e":true}}"#;
        let payload: EventPayload = serde_json::from_str(json).unwrap();
        if let EventPayload::Custom { event_type, data } = &payload {
            assert_eq!(event_type, "X");
            assert_eq!(data["a"], 1);
            assert_eq!(data["b"], "two");
            assert_eq!(data["c"][0], 3);
            assert_eq!(data["d"]["e"], true);

            // Re-serialize and verify the Custom event can be read back
            let re_json = serde_json::to_string(&payload).unwrap();
            let re_payload: EventPayload = serde_json::from_str(&re_json).unwrap();
            if let EventPayload::Custom {
                event_type: et2,
                data: d2,
            } = re_payload
            {
                assert_eq!(et2, "X");
                assert_eq!(d2["a"], 1);
            } else {
                panic!("re-deserialized should still be Custom");
            }
        } else {
            panic!("should be Custom");
        }
    }

    // Old Lago "Error" JSON now deserializes as Custom (canonical name is ErrorRaised)
    #[test]
    fn lago_error_variant_backward_compat() {
        let json = r#"{"type":"Error","error":"boom"}"#;
        let payload: EventPayload = serde_json::from_str(json).unwrap();
        assert!(matches!(payload, EventPayload::Custom { .. }));
    }

    // Canonical ErrorRaised roundtrip
    #[test]
    fn error_raised_roundtrip() {
        let payload = EventPayload::ErrorRaised {
            message: "boom".to_string(),
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"type\":\"ErrorRaised\""));
        let back: EventPayload = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, EventPayload::ErrorRaised { .. }));
    }

    // Old Lago "ToolInvoke" JSON now deserializes as Custom (canonical name is ToolCallRequested)
    #[test]
    fn lago_tool_invoke_backward_compat() {
        let json =
            r#"{"type":"ToolInvoke","call_id":"c1","tool_name":"exec","arguments":{"cmd":"ls"}}"#;
        let payload: EventPayload = serde_json::from_str(json).unwrap();
        assert!(matches!(payload, EventPayload::Custom { .. }));
    }

    // Canonical SnapshotCreated roundtrip
    #[test]
    fn lago_snapshot_roundtrip() {
        let payload = EventPayload::SnapshotCreated {
            snapshot_id: SnapshotId::from_string("SNAP001").into(),
            snapshot_type: SnapshotType::Full,
            covers_through_seq: 100,
            data_hash: BlobHash::from_hex("abc").into(),
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"type\":\"SnapshotCreated\""));
        let back: EventPayload = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, EventPayload::SnapshotCreated { .. }));
    }
}
