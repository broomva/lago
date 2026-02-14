use lago_core::EventEnvelope;
use lago_core::event::EventPayload;
use serde_json::json;

use super::format::{SseFormat, SseFrame};

/// Vercel AI SDK compatible SSE format.
///
/// Formats events using the Vercel AI SDK UI message stream protocol with
/// lifecycle frames (`start-step`, `text-start`, `text-delta`, `text-end`,
/// `finish-step`) and tool streaming. Adds the
/// `x-vercel-ai-ui-message-stream: v1` header.
pub struct VercelFormat;

impl SseFormat for VercelFormat {
    fn format(&self, event: &EventEnvelope) -> Vec<SseFrame> {
        let id = Some(event.seq.to_string());

        match &event.payload {
            EventPayload::Message { content, .. } => {
                // Full message: emit lifecycle frames
                vec![
                    make_frame("start-step", json!({}), &id),
                    make_frame("text-start", json!({}), &id),
                    make_frame(
                        "text-delta",
                        json!({
                            "id": event.event_id.to_string(),
                            "delta": content,
                        }),
                        &id,
                    ),
                    make_frame("text-end", json!({}), &id),
                    make_frame("finish-step", json!({}), &id),
                ]
            }

            EventPayload::MessageDelta { delta, .. } => {
                vec![make_frame(
                    "text-delta",
                    json!({
                        "id": event.event_id.to_string(),
                        "delta": delta,
                    }),
                    &id,
                )]
            }

            EventPayload::ToolInvoke {
                call_id,
                tool_name,
                arguments,
                ..
            } => {
                let args_str = arguments.to_string();
                vec![
                    make_frame(
                        "tool-input-start",
                        json!({
                            "toolCallId": call_id,
                            "toolName": tool_name,
                        }),
                        &id,
                    ),
                    make_frame(
                        "tool-input-delta",
                        json!({
                            "toolCallId": call_id,
                            "delta": args_str,
                        }),
                        &id,
                    ),
                    make_frame(
                        "tool-input-available",
                        json!({
                            "toolCallId": call_id,
                            "toolName": tool_name,
                            "input": arguments,
                        }),
                        &id,
                    ),
                ]
            }

            EventPayload::ToolResult {
                call_id,
                tool_name,
                result,
                ..
            } => {
                vec![make_frame(
                    "tool-output-available",
                    json!({
                        "toolCallId": call_id,
                        "toolName": tool_name,
                        "output": result,
                    }),
                    &id,
                )]
            }

            // Non-message/tool events are filtered out in Vercel format
            _ => Vec::new(),
        }
    }

    fn done_frame(&self) -> Option<SseFrame> {
        let done = json!({
            "type": "finish",
            "finishReason": "stop",
        });
        Some(SseFrame {
            event: None,
            data: done.to_string(),
            id: None,
        })
    }

    fn extra_headers(&self) -> Vec<(String, String)> {
        vec![(
            "x-vercel-ai-ui-message-stream".to_string(),
            "v1".to_string(),
        )]
    }

    fn name(&self) -> &str {
        "vercel"
    }
}

/// Helper to create a typed SSE frame.
fn make_frame(frame_type: &str, mut data: serde_json::Value, id: &Option<String>) -> SseFrame {
    data["type"] = json!(frame_type);
    SseFrame {
        event: None,
        data: data.to_string(),
        id: id.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lago_core::event::SpanStatus;
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

    fn parse_frame(frame: &SseFrame) -> serde_json::Value {
        serde_json::from_str(&frame.data).unwrap()
    }

    #[test]
    fn message_produces_lifecycle_frames() {
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
        assert_eq!(frames.len(), 5);

        assert_eq!(parse_frame(&frames[0])["type"], "start-step");
        assert_eq!(parse_frame(&frames[1])["type"], "text-start");
        assert_eq!(parse_frame(&frames[2])["type"], "text-delta");
        assert_eq!(parse_frame(&frames[2])["delta"], "Hello!");
        assert_eq!(parse_frame(&frames[3])["type"], "text-end");
        assert_eq!(parse_frame(&frames[4])["type"], "finish-step");

        // All frames share the same id
        for frame in &frames {
            assert_eq!(frame.id.as_deref(), Some("3"));
        }
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
        let data = parse_frame(&frames[0]);
        assert_eq!(data["type"], "text-delta");
        assert_eq!(data["delta"], "chunk");
    }

    #[test]
    fn tool_invoke_produces_tool_input_frames() {
        let fmt = VercelFormat;
        let event = make_envelope(
            EventPayload::ToolInvoke {
                call_id: "call-1".into(),
                tool_name: "read_file".into(),
                arguments: serde_json::json!({"path": "/etc/hosts"}),
                category: None,
            },
            10,
        );
        let frames = fmt.format(&event);
        assert_eq!(frames.len(), 3);

        let f0 = parse_frame(&frames[0]);
        assert_eq!(f0["type"], "tool-input-start");
        assert_eq!(f0["toolCallId"], "call-1");
        assert_eq!(f0["toolName"], "read_file");

        let f1 = parse_frame(&frames[1]);
        assert_eq!(f1["type"], "tool-input-delta");
        assert_eq!(f1["toolCallId"], "call-1");
        assert!(f1["delta"].as_str().unwrap().contains("/etc/hosts"));

        let f2 = parse_frame(&frames[2]);
        assert_eq!(f2["type"], "tool-input-available");
        assert_eq!(f2["toolCallId"], "call-1");
        assert_eq!(f2["input"]["path"], "/etc/hosts");
    }

    #[test]
    fn tool_result_produces_tool_output_frame() {
        let fmt = VercelFormat;
        let event = make_envelope(
            EventPayload::ToolResult {
                call_id: "call-1".into(),
                tool_name: "read_file".into(),
                result: serde_json::json!({"content": "data"}),
                duration_ms: 42,
                status: SpanStatus::Ok,
            },
            11,
        );
        let frames = fmt.format(&event);
        assert_eq!(frames.len(), 1);

        let data = parse_frame(&frames[0]);
        assert_eq!(data["type"], "tool-output-available");
        assert_eq!(data["toolCallId"], "call-1");
        assert_eq!(data["output"]["content"], "data");
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
    fn done_frame_is_finish() {
        let fmt = VercelFormat;
        let done = fmt.done_frame().unwrap();
        let data = parse_frame(&done);
        assert_eq!(data["type"], "finish");
        assert_eq!(data["finishReason"], "stop");
    }

    #[test]
    fn extra_headers_include_ui_message_stream_header() {
        let fmt = VercelFormat;
        let headers = fmt.extra_headers();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "x-vercel-ai-ui-message-stream");
        assert_eq!(headers[0].1, "v1");
    }

    #[test]
    fn name_is_vercel() {
        assert_eq!(VercelFormat.name(), "vercel");
    }

    #[test]
    fn sandbox_events_filtered() {
        let fmt = VercelFormat;
        let event = make_envelope(
            EventPayload::SandboxCreated {
                sandbox_id: "sbx-001".into(),
                tier: lago_core::sandbox::SandboxTier::Container,
                config: lago_core::sandbox::SandboxConfig {
                    tier: lago_core::sandbox::SandboxTier::Container,
                    allowed_paths: vec![],
                    allowed_commands: vec![],
                    network_access: false,
                    max_memory_mb: None,
                    max_cpu_seconds: None,
                },
            },
            20,
        );
        assert!(fmt.format(&event).is_empty());
    }
}
