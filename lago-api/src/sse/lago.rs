use lago_core::EventEnvelope;

use super::format::{SseFormat, SseFrame};

/// Native Lago SSE format. Events are sent as-is in their JSON envelope
/// representation, preserving the full event structure.
pub struct LagoFormat;

impl SseFormat for LagoFormat {
    fn format(&self, event: &EventEnvelope) -> Vec<SseFrame> {
        let data = match serde_json::to_string(event) {
            Ok(json) => json,
            Err(e) => {
                tracing::warn!(error = %e, "failed to serialize event envelope");
                return Vec::new();
            }
        };

        vec![SseFrame {
            event: Some("event".to_string()),
            data,
            id: Some(event.seq.to_string()),
        }]
    }

    fn done_frame(&self) -> Option<SseFrame> {
        Some(SseFrame {
            event: Some("done".to_string()),
            data: r#"{"type":"done"}"#.to_string(),
            id: None,
        })
    }

    fn extra_headers(&self) -> Vec<(String, String)> {
        Vec::new()
    }

    fn name(&self) -> &str {
        "lago"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lago_core::event::EventPayload;
    use lago_core::id::*;
    use std::collections::HashMap;

    fn make_envelope(payload: EventPayload, seq: u64) -> EventEnvelope {
        EventEnvelope {
            event_id: EventId::from_string("EVT001"),
            session_id: SessionId::from_string("SESS001"),
            branch_id: BranchId::from_string("main"),
            run_id: None,
            seq,
            timestamp: 1_700_000_000_000_000,
            parent_id: None,
            payload,
            metadata: HashMap::new(),
            schema_version: 1,
        }
    }

    #[test]
    fn lago_format_passes_through_all_events() {
        let fmt = LagoFormat;

        // Message events
        let event = make_envelope(
            EventPayload::Message {
                role: "user".into(),
                content: "hi".into(),
                model: None,
                token_usage: None,
            },
            1,
        );
        let frames = fmt.format(&event);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].event.as_deref(), Some("event"));
        assert_eq!(frames[0].id.as_deref(), Some("1"));

        // The data should be a valid JSON EventEnvelope
        let back: EventEnvelope = serde_json::from_str(&frames[0].data).unwrap();
        assert_eq!(back.event_id.as_str(), "EVT001");
    }

    #[test]
    fn lago_format_includes_file_events() {
        let fmt = LagoFormat;
        let event = make_envelope(
            EventPayload::FileDelete {
                path: "/tmp/x".into(),
            },
            5,
        );
        let frames = fmt.format(&event);
        assert_eq!(frames.len(), 1);
        // Verify the full envelope is in the data
        let back: EventEnvelope = serde_json::from_str(&frames[0].data).unwrap();
        if let EventPayload::FileDelete { path } = &back.payload {
            assert_eq!(path, "/tmp/x");
        } else {
            panic!("wrong payload");
        }
    }

    #[test]
    fn lago_done_frame() {
        let fmt = LagoFormat;
        let done = fmt.done_frame().unwrap();
        assert_eq!(done.event.as_deref(), Some("done"));
        assert_eq!(done.data, r#"{"type":"done"}"#);
    }

    #[test]
    fn lago_no_extra_headers() {
        assert!(LagoFormat.extra_headers().is_empty());
    }

    #[test]
    fn name_is_lago() {
        assert_eq!(LagoFormat.name(), "lago");
    }
}
