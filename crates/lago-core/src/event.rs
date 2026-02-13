use crate::id::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
}

impl EventEnvelope {
    pub fn now_micros() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64
    }
}

/// Discriminated union of all event types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EventPayload {
    // --- Session lifecycle
    SessionCreated {
        name: String,
        config: serde_json::Value,
    },
    SessionResumed {
        from_snapshot: Option<SnapshotId>,
    },

    // --- LLM I/O
    Message {
        role: String,
        content: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        model: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        token_usage: Option<TokenUsage>,
    },
    MessageDelta {
        role: String,
        delta: String,
        index: u32,
    },

    // --- File operations
    FileWrite {
        path: String,
        blob_hash: BlobHash,
        size_bytes: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        content_type: Option<String>,
    },
    FileDelete {
        path: String,
    },
    FileRename {
        old_path: String,
        new_path: String,
    },

    // --- Tool execution
    ToolInvoke {
        call_id: String,
        tool_name: String,
        arguments: serde_json::Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        category: Option<String>,
    },
    ToolResult {
        call_id: String,
        tool_name: String,
        result: serde_json::Value,
        duration_ms: u64,
        status: SpanStatus,
    },

    // --- Approval gate
    ApprovalRequested {
        approval_id: ApprovalId,
        call_id: String,
        tool_name: String,
        arguments: serde_json::Value,
        risk: RiskLevel,
    },
    ApprovalResolved {
        approval_id: ApprovalId,
        decision: ApprovalDecision,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },

    // --- Snapshots + branches
    Snapshot {
        snapshot_id: SnapshotId,
        snapshot_type: SnapshotType,
        covers_through_seq: SeqNo,
        data_hash: BlobHash,
    },
    BranchCreated {
        new_branch_id: BranchId,
        fork_point_seq: SeqNo,
        name: String,
    },
    BranchMerged {
        source_branch_id: BranchId,
        merge_seq: SeqNo,
    },

    // --- Policy
    PolicyEvaluated {
        tool_name: String,
        decision: PolicyDecisionKind,
        #[serde(skip_serializing_if = "Option::is_none")]
        rule_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        explanation: Option<String>,
    },

    // --- Extension
    Custom {
        event_type: String,
        data: serde_json::Value,
    },
}

// --- Supporting types

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanStatus {
    Ok,
    Error,
    Timeout,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approved,
    Denied,
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotType {
    Full,
    Incremental,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecisionKind {
    Allow,
    Deny,
    RequireApproval,
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
        let payload = EventPayload::MessageDelta {
            role: "assistant".to_string(),
            delta: "chunk".to_string(),
            index: 3,
        };
        let json = serde_json::to_string(&payload).unwrap();
        let back: EventPayload = serde_json::from_str(&json).unwrap();
        if let EventPayload::MessageDelta { delta, index, .. } = back {
            assert_eq!(delta, "chunk");
            assert_eq!(index, 3);
        } else {
            panic!("deserialized to wrong variant");
        }
    }

    #[test]
    fn file_write_serde_roundtrip() {
        let payload = EventPayload::FileWrite {
            path: "/src/main.rs".to_string(),
            blob_hash: BlobHash::from_hex("abcdef"),
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
        let invoke = EventPayload::ToolInvoke {
            call_id: "call-1".to_string(),
            tool_name: "read_file".to_string(),
            arguments: serde_json::json!({"path": "/etc/hosts"}),
            category: Some("fs".to_string()),
        };
        let result = EventPayload::ToolResult {
            call_id: "call-1".to_string(),
            tool_name: "read_file".to_string(),
            result: serde_json::json!({"content": "127.0.0.1 localhost"}),
            duration_ms: 42,
            status: SpanStatus::Ok,
        };
        let j1 = serde_json::to_string(&invoke).unwrap();
        let j2 = serde_json::to_string(&result).unwrap();
        assert!(j1.contains("\"type\":\"ToolInvoke\""));
        assert!(j2.contains("\"type\":\"ToolResult\""));

        let back: EventPayload = serde_json::from_str(&j2).unwrap();
        if let EventPayload::ToolResult { status, .. } = back {
            assert_eq!(status, SpanStatus::Ok);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn approval_serde_roundtrip() {
        let requested = EventPayload::ApprovalRequested {
            approval_id: ApprovalId::from_string("APR001"),
            call_id: "call-1".to_string(),
            tool_name: "rm".to_string(),
            arguments: serde_json::json!({"path": "/"}),
            risk: RiskLevel::Critical,
        };
        let json = serde_json::to_string(&requested).unwrap();
        assert!(json.contains("\"risk\":\"critical\""));

        let resolved = EventPayload::ApprovalResolved {
            approval_id: ApprovalId::from_string("APR001"),
            decision: ApprovalDecision::Denied,
            reason: Some("too dangerous".to_string()),
        };
        let j2 = serde_json::to_string(&resolved).unwrap();
        assert!(j2.contains("\"decision\":\"denied\""));
    }

    #[test]
    fn branch_events_serde_roundtrip() {
        let created = EventPayload::BranchCreated {
            new_branch_id: BranchId::from_string("feature-x"),
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
}
