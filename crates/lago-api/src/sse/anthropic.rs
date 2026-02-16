use lago_core::EventEnvelope;
use lago_core::event::EventPayload;
use serde_json::json;

use super::format::{SseFormat, SseFrame};

/// Anthropic-compatible SSE format.
///
/// Formats events using Anthropic's streaming message API shape with
/// `content_block_delta` and `message_stop` event types.
pub struct AnthropicFormat;

impl SseFormat for AnthropicFormat {
    fn format(&self, event: &EventEnvelope) -> Vec<SseFrame> {
        match &event.payload {
            EventPayload::Message {
                role,
                content,
                model,
                token_usage,
            } => {
                let mut frames = Vec::new();

                // message_start
                let msg_start = json!({
                    "type": "message_start",
                    "message": {
                        "id": format!("msg_{}", event.event_id),
                        "type": "message",
                        "role": role,
                        "content": [],
                        "model": model.as_deref().unwrap_or("lago"),
                        "stop_reason": null,
                        "usage": {
                            "input_tokens": token_usage.as_ref().map(|u| u.prompt_tokens).unwrap_or(0),
                            "output_tokens": 0,
                        },
                    },
                });
                frames.push(SseFrame {
                    event: Some("message_start".to_string()),
                    data: msg_start.to_string(),
                    id: Some(event.seq.to_string()),
                });

                // content_block_start
                let block_start = json!({
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {
                        "type": "text",
                        "text": "",
                    },
                });
                frames.push(SseFrame {
                    event: Some("content_block_start".to_string()),
                    data: block_start.to_string(),
                    id: None,
                });

                // content_block_delta with the full content
                let block_delta = json!({
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {
                        "type": "text_delta",
                        "text": content,
                    },
                });
                frames.push(SseFrame {
                    event: Some("content_block_delta".to_string()),
                    data: block_delta.to_string(),
                    id: None,
                });

                // content_block_stop
                let block_stop = json!({
                    "type": "content_block_stop",
                    "index": 0,
                });
                frames.push(SseFrame {
                    event: Some("content_block_stop".to_string()),
                    data: block_stop.to_string(),
                    id: None,
                });

                // message_delta with stop reason
                let msg_delta = json!({
                    "type": "message_delta",
                    "delta": {
                        "stop_reason": "end_turn",
                    },
                    "usage": {
                        "output_tokens": token_usage.as_ref().map(|u| u.completion_tokens).unwrap_or(0),
                    },
                });
                frames.push(SseFrame {
                    event: Some("message_delta".to_string()),
                    data: msg_delta.to_string(),
                    id: None,
                });

                frames
            }

            EventPayload::TextDelta { delta, index } => {
                let block_delta = json!({
                    "type": "content_block_delta",
                    "index": index.unwrap_or(0),
                    "delta": {
                        "type": "text_delta",
                        "text": delta,
                    },
                });

                vec![SseFrame {
                    event: Some("content_block_delta".to_string()),
                    data: block_delta.to_string(),
                    id: Some(event.seq.to_string()),
                }]
            }

            // Non-message events are filtered out in Anthropic format
            _ => Vec::new(),
        }
    }

    fn done_frame(&self) -> Option<SseFrame> {
        let stop = json!({
            "type": "message_stop",
        });
        Some(SseFrame {
            event: Some("message_stop".to_string()),
            data: stop.to_string(),
            id: None,
        })
    }

    fn extra_headers(&self) -> Vec<(String, String)> {
        Vec::new()
    }

    fn name(&self) -> &str {
        "anthropic"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lago_core::event::TokenUsage;
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
    fn message_produces_five_frames() {
        let fmt = AnthropicFormat;
        let event = make_envelope(
            EventPayload::Message {
                role: "assistant".into(),
                content: "Hello!".into(),
                model: Some("claude-3".into()),
                token_usage: Some(TokenUsage {
                    prompt_tokens: 10,
                    completion_tokens: 5,
                    total_tokens: 15,
                }),
            },
            1,
        );
        let frames = fmt.format(&event);
        assert_eq!(frames.len(), 5);

        // message_start
        assert_eq!(frames[0].event.as_deref(), Some("message_start"));
        let d0: serde_json::Value = serde_json::from_str(&frames[0].data).unwrap();
        assert_eq!(d0["type"], "message_start");
        assert_eq!(d0["message"]["model"], "claude-3");
        assert_eq!(d0["message"]["usage"]["input_tokens"], 10);
        assert_eq!(frames[0].id.as_deref(), Some("1"));

        // content_block_start
        assert_eq!(frames[1].event.as_deref(), Some("content_block_start"));

        // content_block_delta
        assert_eq!(frames[2].event.as_deref(), Some("content_block_delta"));
        let d2: serde_json::Value = serde_json::from_str(&frames[2].data).unwrap();
        assert_eq!(d2["delta"]["text"], "Hello!");

        // content_block_stop
        assert_eq!(frames[3].event.as_deref(), Some("content_block_stop"));

        // message_delta
        assert_eq!(frames[4].event.as_deref(), Some("message_delta"));
        let d4: serde_json::Value = serde_json::from_str(&frames[4].data).unwrap();
        assert_eq!(d4["delta"]["stop_reason"], "end_turn");
        assert_eq!(d4["usage"]["output_tokens"], 5);
    }

    #[test]
    fn message_delta_produces_one_frame() {
        let fmt = AnthropicFormat;
        let event = make_envelope(
            EventPayload::TextDelta {
                delta: "token".into(),
                index: Some(2),
            },
            5,
        );
        let frames = fmt.format(&event);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].event.as_deref(), Some("content_block_delta"));
        let data: serde_json::Value = serde_json::from_str(&frames[0].data).unwrap();
        assert_eq!(data["index"], 2);
        assert_eq!(data["delta"]["text"], "token");
    }

    #[test]
    fn non_message_events_filtered() {
        let fmt = AnthropicFormat;
        let event = make_envelope(
            EventPayload::FileDelete {
                path: "/tmp".into(),
            },
            1,
        );
        assert!(fmt.format(&event).is_empty());
    }

    #[test]
    fn done_frame_is_message_stop() {
        let fmt = AnthropicFormat;
        let done = fmt.done_frame().unwrap();
        assert_eq!(done.event.as_deref(), Some("message_stop"));
        let data: serde_json::Value = serde_json::from_str(&done.data).unwrap();
        assert_eq!(data["type"], "message_stop");
    }

    #[test]
    fn name_is_anthropic() {
        assert_eq!(AnthropicFormat.name(), "anthropic");
    }
}
