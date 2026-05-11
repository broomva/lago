//! `lago replay --tree` — reconstruct the agent-spawn recursion tree
//! from a session's `ergon.stream` events.
//!
//! Closes acceptance criterion §9.4 of the authored-agents
//! architecture spec
//! (`core/life/docs/superpowers/specs/2026-05-09-bro-1006-authored-agents-architecture.md`).
//!
//! ## How the tree is reconstructed
//!
//! The ergon framework's `LagoSink` writes every `StreamEvent` to the
//! journal as `EventPayload::Custom { event_type: "ergon.stream",
//! data: <serialized StreamEvent JSON> }`. We read those events for
//! the requested session and reconstruct the recursion tree from the
//! `ToolUseStart` / `ToolUseEnd` bracketing of `spawn_agent` tool
//! calls:
//!
//! - A `ToolUseStart` whose `name == "spawn_agent"` opens a new
//!   child frame on the depth stack.
//! - Subsequent `ToolUseInputDelta` events accumulate the JSON args
//!   for that frame. Once the bracketed `ToolUseEnd` arrives, we
//!   parse the accumulated args to extract the spawned agent's
//!   `name` (the `name` field of `SpawnArgs`).
//! - A matching `ToolUseEnd` closes the frame (pops the stack).
//!
//! Other `StreamEvent` variants (`Usage`, `TextStart/Delta/End`,
//! `ToolUseStart` for non-spawn tools, …) annotate the current frame:
//! token usage accumulates per-frame, tool calls become children of
//! the frame, and so on.
//!
//! ## Why this approach over a separate event type
//!
//! Ideally `dispatch_spawn_agent` would emit a dedicated
//! `Custom { event_type: "ergon.agent_spawned", … }` event with
//! parent-child correlation IDs. That's the spec-recommended path —
//! see the follow-up note in this PR's description. For now, the
//! `ToolUseStart(spawn_agent)` bracket signal is already in the
//! journal of every authored-agent run, so this MVP shipping a
//! reader works against existing data without requiring an emit-side
//! change first.
//!
//! ## Limitations (documented, not blockers)
//!
//! 1. **No cross-tick threading.** Each kernel tick's events form
//!    one tree. Spawns across ticks are not linked.
//! 2. **Args-parse heuristic for agent name.** If
//!    `ToolUseInputDelta` chunks arrive out of order or the JSON is
//!    truncated, we fall back to `<unknown>`. The `spawn_agent` tool
//!    output (in `ToolUseEnd`'s call result, not the args) would be
//!    a more reliable source if the framework emits it — current
//!    `ToolUseEnd` only carries ok/denied/error.
//! 3. **No timing/duration computation.** We surface event seq
//!    numbers and timestamps; computing per-frame wall clock is a
//!    follow-up.

use std::collections::HashMap;
use std::path::Path;

use lago_core::event::EventPayload;
use lago_core::{BranchId, EventEnvelope, EventQuery, Journal, SessionId};
use serde::Deserialize;

use crate::db::open_journal;

/// Stable event_type constant the ergon `LagoSink` writes. Matching
/// `crates/ergon/ergon-life-sinks/src/lago.rs::ERGON_STREAM_EVENT_TYPE`.
const ERGON_STREAM_EVENT_TYPE: &str = "ergon.stream";

/// Stable tool name the ergon framework synthesizes for sub-agent
/// invocations. Matching `crates/ergon/ergon/src/builtin_tools.rs::SPAWN_AGENT_TOOL`.
const SPAWN_AGENT_TOOL: &str = "spawn_agent";

/// CLI options for `lago replay --tree`.
#[derive(Debug, Clone)]
pub struct ReplayOptions {
    pub session_id: String,
    pub branch: String,
    pub limit: usize,
    /// When true, print as an indented ASCII tree (the default mode
    /// for this command — currently the only mode).
    pub tree: bool,
}

/// One frame of the recursion tree.
#[derive(Debug, Clone)]
struct Frame {
    /// Index into the flat `frames` Vec of the parent frame; `None`
    /// for the root.
    parent: Option<usize>,
    /// Depth in the tree (0 == root).
    depth: usize,
    /// Agent name. `<root>` for the workflow tick's outermost frame;
    /// `<unknown>` if the spawn args couldn't be parsed.
    agent_name: String,
    /// `spawn_agent` tool_use id that opened this frame. `None` for
    /// the root. Carried on the frame for debugging / future
    /// renderers (`--show-tool-use-ids`); the tree builder uses
    /// `spawn_frame_of` for lookup, not this field.
    #[allow(dead_code)]
    spawn_tool_use_id: Option<String>,
    /// First event seq# in this frame.
    started_seq: u64,
    /// Last event seq# in this frame (set when the bracketing
    /// `ToolUseEnd` arrives).
    finished_seq: Option<u64>,
    /// Sum of `Usage.input` tokens across all `Usage` events in this
    /// frame (including descendants — descendant counts also bubble
    /// up via `Usage` events nested in the bracket).
    input_tokens: u64,
    /// Sum of `Usage.output` tokens.
    output_tokens: u64,
    /// Non-spawn tool calls observed in this frame (e.g.
    /// `record_answer`). One entry per `ToolUseStart`.
    inline_tool_calls: Vec<String>,
}

impl Frame {
    fn root(started_seq: u64) -> Self {
        Self {
            parent: None,
            depth: 0,
            agent_name: "<root>".to_owned(),
            spawn_tool_use_id: None,
            started_seq,
            finished_seq: None,
            input_tokens: 0,
            output_tokens: 0,
            inline_tool_calls: Vec::new(),
        }
    }

    fn child(
        parent_idx: usize,
        parent_depth: usize,
        started_seq: u64,
        tool_use_id: String,
    ) -> Self {
        Self {
            parent: Some(parent_idx),
            depth: parent_depth + 1,
            agent_name: "<unknown>".to_owned(),
            spawn_tool_use_id: Some(tool_use_id),
            started_seq,
            finished_seq: None,
            input_tokens: 0,
            output_tokens: 0,
            inline_tool_calls: Vec::new(),
        }
    }
}

/// Execute `lago replay --tree`.
pub async fn run(data_dir: &Path, opts: ReplayOptions) -> Result<(), Box<dyn std::error::Error>> {
    let journal = open_journal(data_dir)?;

    let session_id = SessionId::from_string(&opts.session_id);
    let branch_id = BranchId::from_string(&opts.branch);

    let query = EventQuery::new()
        .session(session_id)
        .branch(branch_id)
        .limit(opts.limit);

    let events = journal.read(query).await?;

    if events.is_empty() {
        println!(
            "No events found for session {} branch {}.",
            opts.session_id, opts.branch
        );
        return Ok(());
    }

    let frames = build_tree(&events);

    if opts.tree {
        render_tree(&frames, &opts);
    } else {
        // Reserved for future modes; only `--tree` ships in this PR.
        render_tree(&frames, &opts);
    }

    Ok(())
}

/// Reconstruct the recursion tree from a session's events.
///
/// Returns a flat `Vec<Frame>` where each frame holds a `parent`
/// index back into the same Vec. The 0-th entry is always the root.
fn build_tree(events: &[EventEnvelope]) -> Vec<Frame> {
    let first_seq = events.first().map(|e| e.seq).unwrap_or(0);
    let mut frames: Vec<Frame> = vec![Frame::root(first_seq)];
    // Stack of frame indices currently on the spawn chain. The top of
    // the stack is the deepest open frame; events accrue there.
    let mut stack: Vec<usize> = vec![0];
    // tool_use_id → accumulated partial_args JSON. Tracks every
    // open `spawn_agent` tool_use so we can parse the agent name out
    // of the args once the bracket closes (or before, if all chunks
    // arrived).
    let mut spawn_args: HashMap<String, String> = HashMap::new();
    // tool_use_id → frame index. Tracks which frame each `spawn_agent`
    // call opened, so the matching `ToolUseEnd` knows which to close.
    let mut spawn_frame_of: HashMap<String, usize> = HashMap::new();

    for event in events {
        let data = match &event.payload {
            EventPayload::Custom { event_type, data } if event_type == ERGON_STREAM_EVENT_TYPE => {
                data
            }
            _ => continue,
        };

        let stream_event: StreamEventTag = match serde_json::from_value(data.clone()) {
            Ok(s) => s,
            Err(_) => continue, // forward-compat: skip unrecognised shapes
        };

        let cur_idx = *stack.last().expect("stack always non-empty (root)");

        match stream_event {
            StreamEventTag::ToolUseStart { id, name } if name == SPAWN_AGENT_TOOL => {
                let parent_idx = cur_idx;
                let parent_depth = frames[parent_idx].depth;
                let child = Frame::child(parent_idx, parent_depth, event.seq, id.clone());
                let child_idx = frames.len();
                frames.push(child);
                stack.push(child_idx);
                spawn_args.insert(id.clone(), String::new());
                spawn_frame_of.insert(id, child_idx);
            }
            StreamEventTag::ToolUseStart { id: _, name } => {
                // Non-spawn tool call — annotate the current frame.
                frames[cur_idx].inline_tool_calls.push(name);
            }
            StreamEventTag::ToolUseInputDelta { id, partial_args } => {
                if let Some(buf) = spawn_args.get_mut(&id) {
                    buf.push_str(&partial_args);
                }
            }
            StreamEventTag::ToolUseEnd { id, .. } => {
                // If this id matches an open spawn frame, finalize and pop.
                if let Some(frame_idx) = spawn_frame_of.remove(&id) {
                    // Parse the accumulated args to extract the agent name.
                    if let Some(args_str) = spawn_args.remove(&id) {
                        let trimmed = args_str.trim();
                        if !trimmed.is_empty()
                            && let Ok(args_json) = serde_json::from_str::<SpawnArgsView>(trimmed)
                        {
                            frames[frame_idx].agent_name = args_json.name;
                        }
                    }
                    frames[frame_idx].finished_seq = Some(event.seq);
                    // Pop until we've removed this frame from the stack
                    // (handles malformed traces where Ends came in
                    // out-of-order — we close everything down to it).
                    while let Some(&top) = stack.last() {
                        stack.pop();
                        if top == frame_idx {
                            break;
                        }
                    }
                    if stack.is_empty() {
                        // Defensive: never leave the stack fully empty
                        // — root must always be present so subsequent
                        // events still accrue somewhere.
                        stack.push(0);
                    }
                }
            }
            StreamEventTag::Usage { input, output, .. } => {
                frames[cur_idx].input_tokens += u64::from(input);
                frames[cur_idx].output_tokens += u64::from(output);
            }
            // Everything else (TextStart/Delta/End, ReasoningStart/Delta/End,
            // StructuredStart/Delta/End, Citation, Source, Done, Error,
            // SessionStart, VendorEvent) is annotation — we don't yet
            // surface it in the tree. The `inline_tool_calls` list above
            // captures the tool-call vocabulary; richer rendering is a
            // follow-up.
            _ => {}
        }
    }

    // Set finished_seq on any frames that never closed (truncated
    // session, dropped events) so the renderer can still produce
    // output.
    let last_seq = events.last().map(|e| e.seq).unwrap_or(first_seq);
    for f in &mut frames {
        if f.finished_seq.is_none() {
            f.finished_seq = Some(last_seq);
        }
    }

    frames
}

/// Render the tree as indented ASCII to stdout.
fn render_tree(frames: &[Frame], opts: &ReplayOptions) {
    println!(
        "Recursion tree for session={} branch={}:",
        opts.session_id, opts.branch
    );
    println!();

    // Compute children-of relation by parent index.
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); frames.len()];
    for (idx, frame) in frames.iter().enumerate() {
        if let Some(p) = frame.parent {
            children[p].push(idx);
        }
    }

    // DFS render from the root (index 0).
    let mut prefix_stack: Vec<bool> = Vec::new();
    render_frame(0, frames, &children, &mut prefix_stack);

    // Summary footer.
    let total_spawns = frames.len().saturating_sub(1);
    let total_input: u64 = frames.iter().map(|f| f.input_tokens).sum();
    let total_output: u64 = frames.iter().map(|f| f.output_tokens).sum();
    println!();
    println!(
        "--- {total_spawns} spawn(s), {total_input} input + {total_output} output tokens total ---"
    );
}

fn render_frame(
    idx: usize,
    frames: &[Frame],
    children: &[Vec<usize>],
    prefix_stack: &mut Vec<bool>, // true → "is last sibling at this depth"
) {
    let frame = &frames[idx];

    // Build the indent prefix from the stack.
    let mut prefix = String::new();
    for (depth, &is_last) in prefix_stack.iter().enumerate() {
        if depth + 1 == prefix_stack.len() {
            prefix.push_str(if is_last { "└─ " } else { "├─ " });
        } else {
            prefix.push_str(if is_last { "   " } else { "│  " });
        }
    }

    let kids = &children[idx];
    let tool_summary = if frame.inline_tool_calls.is_empty() {
        String::new()
    } else {
        format!(" [tools: {}]", frame.inline_tool_calls.join(", "))
    };
    let token_summary = if frame.input_tokens > 0 || frame.output_tokens > 0 {
        format!(" ({} in / {} out)", frame.input_tokens, frame.output_tokens)
    } else {
        String::new()
    };
    let seq_summary = match frame.finished_seq {
        Some(end) => format!(" seq {}..{}", frame.started_seq, end),
        None => format!(" seq {}..", frame.started_seq),
    };

    println!(
        "{prefix}{}{seq_summary}{token_summary}{tool_summary}",
        frame.agent_name,
    );

    // Recurse into children, tracking is-last for box-drawing.
    for (i, &child_idx) in kids.iter().enumerate() {
        let is_last_child = i + 1 == kids.len();
        prefix_stack.push(is_last_child);
        render_frame(child_idx, frames, children, prefix_stack);
        prefix_stack.pop();
    }
}

// ─── StreamEvent deserialization shims ──────────────────────────────────
//
// We don't depend on the `ergon` crate from `lago-cli` (lago is below
// ergon in the dependency graph), so we reconstruct the minimum
// vocabulary needed to walk `ergon::StreamEvent` JSON. The
// serde-tagged shape is documented as stable in
// `crates/ergon/ergon/src/stream.rs` ("variants are append-only after
// v1.0") so this private shim is safe to maintain here.

/// The minimum vocabulary needed to walk `ergon::StreamEvent` JSON.
///
/// Several fields exist solely so the serde tag accepts the wire
/// shape — they aren't read by `build_tree`. Marking the enum
/// `#[allow(dead_code)]` (rather than prefixing each field with `_`)
/// keeps the declared shape readable as a wire spec.
#[derive(Debug, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
#[allow(dead_code)]
enum StreamEventTag {
    ToolUseStart {
        id: String,
        name: String,
    },
    ToolUseInputDelta {
        id: String,
        partial_args: String,
    },
    ToolUseEnd {
        id: String,
        #[serde(default)]
        ok: bool,
        #[serde(default)]
        denied: bool,
        #[serde(default)]
        error: Option<String>,
    },
    Usage {
        input: u32,
        output: u32,
        #[serde(default)]
        cached_input: Option<u32>,
        #[serde(default)]
        reasoning: Option<u32>,
    },
    /// Forward-compat catch-all for any variant we don't model
    /// (TextStart/Delta/End, ReasoningStart/Delta/End, etc.). The
    /// `#[non_exhaustive]` discipline on `ergon::StreamEvent` means
    /// new variants land in any minor version; this lets us absorb
    /// them without breaking the reader.
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize)]
struct SpawnArgsView {
    name: String,
    // We don't need `input` here — only the spawned agent's name.
}

#[cfg(test)]
mod tests {
    use super::*;
    use lago_core::EventId;

    fn make_envelope(seq: u64, payload: EventPayload) -> EventEnvelope {
        EventEnvelope {
            event_id: EventId::new(),
            session_id: SessionId::from_string("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
            branch_id: BranchId::from_string("main"),
            run_id: None,
            seq,
            timestamp: EventEnvelope::now_micros(),
            parent_id: None,
            payload,
            metadata: std::collections::HashMap::new(),
            schema_version: 1,
        }
    }

    fn ergon_stream(seq: u64, payload_json: serde_json::Value) -> EventEnvelope {
        make_envelope(
            seq,
            EventPayload::Custom {
                event_type: ERGON_STREAM_EVENT_TYPE.to_owned(),
                data: payload_json,
            },
        )
    }

    #[test]
    fn build_tree_no_spawns_returns_just_root() {
        let events = vec![
            ergon_stream(1, serde_json::json!({"event": "text_start", "id": "t1"})),
            ergon_stream(
                2,
                serde_json::json!({"event": "text_delta", "id": "t1", "delta": "hi"}),
            ),
            ergon_stream(3, serde_json::json!({"event": "text_end", "id": "t1"})),
            ergon_stream(
                4,
                serde_json::json!({"event": "usage", "input": 100, "output": 50}),
            ),
        ];

        let frames = build_tree(&events);

        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].agent_name, "<root>");
        assert_eq!(frames[0].depth, 0);
        assert!(frames[0].parent.is_none());
        assert_eq!(frames[0].input_tokens, 100);
        assert_eq!(frames[0].output_tokens, 50);
    }

    #[test]
    fn build_tree_single_spawn_opens_child_frame() {
        // ToolUseStart(spawn_agent) → ToolUseInputDelta(args) → ToolUseEnd
        let events = vec![
            ergon_stream(
                1,
                serde_json::json!({
                    "event": "tool_use_start",
                    "id": "tu-1",
                    "name": "spawn_agent"
                }),
            ),
            ergon_stream(
                2,
                serde_json::json!({
                    "event": "tool_use_input_delta",
                    "id": "tu-1",
                    "partial_args": r#"{"name":"goal-pursuer","input":{"goal":"test"}}"#
                }),
            ),
            // Sub-agent emits a usage event while running (inside the bracket).
            ergon_stream(
                3,
                serde_json::json!({"event": "usage", "input": 200, "output": 150}),
            ),
            ergon_stream(
                4,
                serde_json::json!({
                    "event": "tool_use_end",
                    "id": "tu-1",
                    "ok": true,
                    "denied": false
                }),
            ),
        ];

        let frames = build_tree(&events);

        assert_eq!(frames.len(), 2, "root + one spawned child");
        assert_eq!(frames[0].agent_name, "<root>");
        assert_eq!(frames[1].agent_name, "goal-pursuer");
        assert_eq!(frames[1].depth, 1);
        assert_eq!(frames[1].parent, Some(0));
        assert_eq!(frames[1].spawn_tool_use_id.as_deref(), Some("tu-1"));
        assert_eq!(frames[1].started_seq, 1);
        assert_eq!(frames[1].finished_seq, Some(4));
        // Token usage accrued to the child (events arrived inside its
        // bracket).
        assert_eq!(frames[1].input_tokens, 200);
        assert_eq!(frames[1].output_tokens, 150);
    }

    #[test]
    fn build_tree_two_level_recursion() {
        // orchestrator → relayer → echo-1 (the spawn_dispatch.rs
        // integration test's two-level recursion case).
        let events = vec![
            // outer spawn: spawn_agent("relayer")
            ergon_stream(
                1,
                serde_json::json!({
                    "event": "tool_use_start", "id": "tu-1", "name": "spawn_agent"
                }),
            ),
            ergon_stream(
                2,
                serde_json::json!({
                    "event": "tool_use_input_delta", "id": "tu-1",
                    "partial_args": r#"{"name":"relayer","input":{}}"#
                }),
            ),
            // inner spawn (inside relayer's frame): spawn_agent("echo-1")
            ergon_stream(
                3,
                serde_json::json!({
                    "event": "tool_use_start", "id": "tu-2", "name": "spawn_agent"
                }),
            ),
            ergon_stream(
                4,
                serde_json::json!({
                    "event": "tool_use_input_delta", "id": "tu-2",
                    "partial_args": r#"{"name":"echo-1","input":{}}"#
                }),
            ),
            // echo-1 emits a non-spawn tool call (record_answer).
            ergon_stream(
                5,
                serde_json::json!({
                    "event": "tool_use_start", "id": "tu-3", "name": "record_answer"
                }),
            ),
            ergon_stream(
                6,
                serde_json::json!({"event": "tool_use_end", "id": "tu-3", "ok": true, "denied": false}),
            ),
            // inner spawn finishes.
            ergon_stream(
                7,
                serde_json::json!({"event": "tool_use_end", "id": "tu-2", "ok": true, "denied": false}),
            ),
            // outer spawn finishes.
            ergon_stream(
                8,
                serde_json::json!({"event": "tool_use_end", "id": "tu-1", "ok": true, "denied": false}),
            ),
        ];

        let frames = build_tree(&events);

        assert_eq!(frames.len(), 3, "root + relayer + echo-1");
        assert_eq!(frames[0].agent_name, "<root>");
        assert_eq!(frames[1].agent_name, "relayer");
        assert_eq!(frames[1].depth, 1);
        assert_eq!(frames[1].parent, Some(0));
        assert_eq!(frames[2].agent_name, "echo-1");
        assert_eq!(frames[2].depth, 2);
        assert_eq!(frames[2].parent, Some(1));
        // The record_answer tool call should be annotated on the echo-1
        // (deepest) frame, since it happened inside echo-1's bracket.
        assert_eq!(frames[2].inline_tool_calls, vec!["record_answer"]);
    }

    #[test]
    fn build_tree_malformed_spawn_args_falls_back_to_unknown() {
        // ToolUseStart(spawn_agent) but the partial_args never arrive
        // or are malformed JSON. The frame still opens; the agent
        // name falls back to `<unknown>`.
        let events = vec![
            ergon_stream(
                1,
                serde_json::json!({
                    "event": "tool_use_start", "id": "tu-1", "name": "spawn_agent"
                }),
            ),
            ergon_stream(
                2,
                serde_json::json!({
                    "event": "tool_use_input_delta", "id": "tu-1",
                    "partial_args": "this is not json"
                }),
            ),
            ergon_stream(
                3,
                serde_json::json!({"event": "tool_use_end", "id": "tu-1", "ok": true, "denied": false}),
            ),
        ];

        let frames = build_tree(&events);

        assert_eq!(frames.len(), 2);
        assert_eq!(frames[1].agent_name, "<unknown>");
        assert_eq!(frames[1].finished_seq, Some(3));
    }

    #[test]
    fn build_tree_ignores_non_ergon_events() {
        // A foreign Custom event_type and a non-Custom event are both
        // ignored — we don't crash, and they don't accrue to the
        // root.
        let events = vec![
            make_envelope(
                1,
                EventPayload::Custom {
                    event_type: "some.other.event".to_owned(),
                    data: serde_json::json!({"x": 1}),
                },
            ),
            make_envelope(
                2,
                EventPayload::Message {
                    role: "user".to_owned(),
                    content: "hi".to_owned(),
                    model: None,
                    token_usage: None,
                },
            ),
            ergon_stream(
                3,
                serde_json::json!({"event": "usage", "input": 10, "output": 5}),
            ),
        ];

        let frames = build_tree(&events);

        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].input_tokens, 10);
        assert_eq!(frames[0].output_tokens, 5);
    }

    #[test]
    fn build_tree_handles_unrecognised_stream_event_variant() {
        // Forward-compat: a hypothetical future StreamEvent variant
        // with `"event": "some_future_kind"` should be silently
        // absorbed (the deserializer's `#[serde(other)]` rule
        // accepts it).
        let events = vec![
            ergon_stream(
                1,
                serde_json::json!({"event": "some_future_kind", "id": "x"}),
            ),
            ergon_stream(
                2,
                serde_json::json!({"event": "usage", "input": 7, "output": 3}),
            ),
        ];

        let frames = build_tree(&events);

        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].input_tokens, 7);
        assert_eq!(frames[0].output_tokens, 3);
    }
}
