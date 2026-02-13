use lago_core::EventEnvelope;
use lago_core::event::EventPayload;
use serde_json::json;

use super::format::{SseFormat, SseFrame};

/// OpenAI-compatible SSE format.
///
/// Formats `Message` and `MessageDelta` events as chat completion chunk
/// objects matching the OpenAI streaming API shape.
pub struct OpenAiFormat;

impl SseFormat for OpenAiFormat {
    fn format(&self, event: &EventEnvelope) -> Vec<SseFrame> {
        match &event.payload {
            EventPayload::Message {
                role,
                content,
                model,
                ..
            } => {
                // Emit a single chunk with the full message content
                let chunk = json!({
                    "id": format!("chatcmpl-{}", event.event_id),
                    "object": "chat.completion.chunk",
                    "created": event.timestamp / 1_000_000, // micros -> seconds
                    "model": model.as_deref().unwrap_or("lago"),
                    "choices": [{
                        "index": 0,
                        "delta": {
                            "role": role,
                            "content": content,
                        },
                        "finish_reason": "stop",
                    }],
                });

                vec![SseFrame {
                    event: None,
                    data: chunk.to_string(),
                    id: Some(event.seq.to_string()),
                }]
            }

            EventPayload::MessageDelta { role, delta, index } => {
                let chunk = json!({
                    "id": format!("chatcmpl-{}", event.event_id),
                    "object": "chat.completion.chunk",
                    "created": event.timestamp / 1_000_000,
                    "model": "lago",
                    "choices": [{
                        "index": index,
                        "delta": {
                            "role": role,
                            "content": delta,
                        },
                        "finish_reason": null,
                    }],
                });

                vec![SseFrame {
                    event: None,
                    data: chunk.to_string(),
                    id: Some(event.seq.to_string()),
                }]
            }

            // Non-message events are filtered out in OpenAI format
            _ => Vec::new(),
        }
    }

    fn done_frame(&self) -> Option<SseFrame> {
        Some(SseFrame {
            event: None,
            data: "[DONE]".to_string(),
            id: None,
        })
    }

    fn extra_headers(&self) -> Vec<(String, String)> {
        Vec::new()
    }

    fn name(&self) -> &str {
        "openai"
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
    fn message_produces_one_frame() {
        let fmt = OpenAiFormat;
        let event = make_envelope(
            EventPayload::Message {
                role: "assistant".into(),
                content: "Hello!".into(),
                model: Some("gpt-4".into()),
                token_usage: None,
            },
            42,
        );
        let frames = fmt.format(&event);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].event.is_none()); // OpenAI uses bare data lines
        assert_eq!(frames[0].id.as_deref(), Some("42"));

        let data: serde_json::Value = serde_json::from_str(&frames[0].data).unwrap();
        assert_eq!(data["object"], "chat.completion.chunk");
        assert_eq!(data["choices"][0]["delta"]["content"], "Hello!");
        assert_eq!(data["choices"][0]["delta"]["role"], "assistant");
        assert_eq!(data["choices"][0]["finish_reason"], "stop");
        assert_eq!(data["model"], "gpt-4");
        assert!(data["id"].as_str().unwrap().starts_with("chatcmpl-"));
    }

    #[test]
    fn message_delta_produces_frame() {
        let fmt = OpenAiFormat;
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
        assert_eq!(data["choices"][0]["delta"]["content"], "chunk");
        assert!(data["choices"][0]["finish_reason"].is_null());
    }

    #[test]
    fn non_message_events_filtered_out() {
        let fmt = OpenAiFormat;
        let event = make_envelope(
            EventPayload::FileDelete {
                path: "/tmp/x".into(),
            },
            1,
        );
        let frames = fmt.format(&event);
        assert!(frames.is_empty());
    }

    #[test]
    fn done_frame() {
        let fmt = OpenAiFormat;
        let done = fmt.done_frame().unwrap();
        assert_eq!(done.data, "[DONE]");
        assert!(done.event.is_none());
    }

    #[test]
    fn no_extra_headers() {
        let fmt = OpenAiFormat;
        assert!(fmt.extra_headers().is_empty());
    }

    #[test]
    fn name_is_openai() {
        assert_eq!(OpenAiFormat.name(), "openai");
    }
}
