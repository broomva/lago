use crate::event::SpanStatus;
use serde::{Deserialize, Serialize};

/// Represents a tool execution span (invoke -> result).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpan {
    pub call_id: String,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    pub category: Option<String>,
    pub status: Option<SpanStatus>,
    pub result: Option<serde_json::Value>,
    pub started_at: u64,
    pub ended_at: Option<u64>,
    pub duration_ms: Option<u64>,
}

impl ToolSpan {
    pub fn new(call_id: String, tool_name: String, arguments: serde_json::Value) -> Self {
        Self {
            call_id,
            tool_name,
            arguments,
            category: None,
            status: None,
            result: None,
            started_at: crate::event::EventEnvelope::now_micros(),
            ended_at: None,
            duration_ms: None,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.status.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::SpanStatus;

    #[test]
    fn new_span_is_incomplete() {
        let span = ToolSpan::new(
            "call-1".into(),
            "read_file".into(),
            serde_json::json!({"path": "/foo"}),
        );
        assert!(!span.is_complete());
        assert_eq!(span.call_id, "call-1");
        assert_eq!(span.tool_name, "read_file");
        assert!(span.started_at > 0);
        assert!(span.ended_at.is_none());
        assert!(span.result.is_none());
        assert!(span.category.is_none());
    }

    #[test]
    fn completed_span() {
        let mut span = ToolSpan::new("call-2".into(), "write".into(), serde_json::json!({}));
        span.status = Some(SpanStatus::Ok);
        span.result = Some(serde_json::json!({"written": true}));
        span.ended_at = Some(span.started_at + 100_000);
        span.duration_ms = Some(100);
        assert!(span.is_complete());
    }

    #[test]
    fn span_serde_roundtrip() {
        let span = ToolSpan::new(
            "call-3".into(),
            "exec".into(),
            serde_json::json!({"cmd": "ls"}),
        );
        let json = serde_json::to_string(&span).unwrap();
        let back: ToolSpan = serde_json::from_str(&json).unwrap();
        assert_eq!(back.call_id, "call-3");
        assert_eq!(back.tool_name, "exec");
    }
}
