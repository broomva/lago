use lago_core::EventEnvelope;
use lago_core::event::EventPayload;
use serde_json::json;

use super::format::{SseFormat, SseFrame};

/// Vercel AI SDK compatible SSE format.
///
/// Formats events using the Vercel AI SDK data stream protocol with
/// `text-delta` and `finish-message` types. Adds the
/// `x-vercel-ai-data-stream: v1` header.
pub struct VercelFormat;

impl SseFormat for VercelFormat {
    fn format(&self, event: &EventEnvelope) -> Vec<SseFrame> {
        match &event.payload {
            EventPayload::Message { content, .. } => {
                let frame = json!({
                    "type": "text-delta",
                    "id": event.event_id.to_string(),
                    "delta": content,
                });

                vec![SseFrame {
                    event: None,
                    data: frame.to_string(),
                    id: Some(event.seq.to_string()),
                }]
            }

            EventPayload::MessageDelta { delta, .. } => {
                let frame = json!({
                    "type": "text-delta",
                    "id": event.event_id.to_string(),
                    "delta": delta,
                });

                vec![SseFrame {
                    event: None,
                    data: frame.to_string(),
                    id: Some(event.seq.to_string()),
                }]
            }

            // Non-message events are filtered out in Vercel format
            _ => Vec::new(),
        }
    }

    fn done_frame(&self) -> Option<SseFrame> {
        let done = json!({
            "type": "finish-message",
            "finishReason": "stop",
        });
        Some(SseFrame {
            event: None,
            data: done.to_string(),
            id: None,
        })
    }

    fn extra_headers(&self) -> Vec<(String, String)> {
        vec![("x-vercel-ai-data-stream".to_string(), "v1".to_string())]
    }

    fn name(&self) -> &str {
        "vercel"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        }
    }

    #[test]
    fn message_produces_text_delta_frame() {
        let fmt = VercelFormat;
        let event = make_envelope(
            EventPayload::Message {
                role: "assistant".into(),
                content: "Hello!".into(),
                model: None,
                token_usage: None,
            },
            3,
        );
        let frames = fmt.format(&event);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].event.is_none());
        assert_eq!(frames[0].id.as_deref(), Some("3"));

        let data: serde_json::Value = serde_json::from_str(&frames[0].data).unwrap();
        assert_eq!(data["type"], "text-delta");
        assert_eq!(data["delta"], "Hello!");
    }

    #[test]
    fn message_delta_produces_text_delta_frame() {
        let fmt = VercelFormat;
        let event = make_envelope(
            EventPayload::MessageDelta {
                role: "assistant".into(),
                delta: "chunk".into(),
                index: 0,
            },
            7,
        );
        let frames = fmt.format(&event);
        assert_eq!(frames.len(), 1);
        let data: serde_json::Value = serde_json::from_str(&frames[0].data).unwrap();
        assert_eq!(data["type"], "text-delta");
        assert_eq!(data["delta"], "chunk");
    }

    #[test]
    fn non_message_events_filtered() {
        let fmt = VercelFormat;
        let event = make_envelope(
            EventPayload::FileWrite {
                path: "/a".into(),
                blob_hash: BlobHash::from_hex("abc"),
                size_bytes: 10,
                content_type: None,
            },
            1,
        );
        assert!(fmt.format(&event).is_empty());
    }

    #[test]
    fn done_frame_is_finish_message() {
        let fmt = VercelFormat;
        let done = fmt.done_frame().unwrap();
        let data: serde_json::Value = serde_json::from_str(&done.data).unwrap();
        assert_eq!(data["type"], "finish-message");
        assert_eq!(data["finishReason"], "stop");
    }

    #[test]
    fn extra_headers_include_vercel_header() {
        let fmt = VercelFormat;
        let headers = fmt.extra_headers();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "x-vercel-ai-data-stream");
        assert_eq!(headers[0].1, "v1");
    }

    #[test]
    fn name_is_vercel() {
        assert_eq!(VercelFormat.name(), "vercel");
    }
}
