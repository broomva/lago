use std::path::Path;

use lago_core::event::EventPayload;
use lago_core::{BranchId, EventEnvelope, EventQuery, Journal, SessionId};

use crate::db::open_journal;

/// Options for the `lago log` command.
#[derive(Debug, Clone)]
pub struct LogOptions {
    pub session_id: String,
    pub branch: String,
    pub limit: usize,
    pub after_seq: Option<u64>,
}

/// Execute the `lago log` command.
///
/// Reads events from the journal matching the given session and branch,
/// then prints them in a human-readable format.
pub async fn run(data_dir: &Path, opts: LogOptions) -> Result<(), Box<dyn std::error::Error>> {
    let journal = open_journal(data_dir)?;

    let session_id = SessionId::from_string(&opts.session_id);
    let branch_id = BranchId::from_string(&opts.branch);

    let mut query = EventQuery::new()
        .session(session_id)
        .branch(branch_id)
        .limit(opts.limit);

    if let Some(after) = opts.after_seq {
        query = query.after(after);
    }

    let events = journal.read(query).await?;

    if events.is_empty() {
        println!("No events found.");
        return Ok(());
    }

    for event in &events {
        print_event(event);
        println!();
    }

    println!("--- {} event(s) ---", events.len());
    Ok(())
}

/// Print a single event in a concise, readable format.
fn print_event(event: &EventEnvelope) {
    let ts = format_timestamp(event.timestamp);
    let seq = event.seq;
    let eid = &event.event_id;

    println!("seq {seq}  {eid}  [{ts}]");
    println!("  branch: {}", event.branch_id);

    if let Some(ref run_id) = event.run_id {
        println!("  run:    {run_id}");
    }

    match &event.payload {
        EventPayload::SessionCreated { name, .. } => {
            println!("  type:   SessionCreated");
            println!("  name:   {name}");
        }
        EventPayload::SessionResumed { from_snapshot } => {
            println!("  type:   SessionResumed");
            if let Some(snap) = from_snapshot {
                println!("  from:   {snap}");
            }
        }
        EventPayload::Message {
            role,
            content,
            model,
            token_usage,
        } => {
            println!("  type:   Message");
            println!("  role:   {role}");
            if let Some(m) = model {
                println!("  model:  {m}");
            }
            if let Some(usage) = token_usage {
                println!(
                    "  tokens: {} prompt + {} completion = {} total",
                    usage.prompt_tokens, usage.completion_tokens, usage.total_tokens
                );
            }
            // Truncate long messages for display
            let preview = if content.len() > 200 {
                format!("{}...", &content[..200])
            } else {
                content.clone()
            };
            println!("  content: {preview}");
        }
        EventPayload::MessageDelta { role, delta, index } => {
            println!("  type:   MessageDelta (index={index})");
            println!("  role:   {role}");
            let preview = if delta.len() > 100 {
                format!("{}...", &delta[..100])
            } else {
                delta.clone()
            };
            println!("  delta:  {preview}");
        }
        EventPayload::FileWrite {
            path,
            blob_hash,
            size_bytes,
            ..
        } => {
            println!("  type:   FileWrite");
            println!("  path:   {path}");
            println!("  hash:   {blob_hash}");
            println!("  size:   {size_bytes} bytes");
        }
        EventPayload::FileDelete { path } => {
            println!("  type:   FileDelete");
            println!("  path:   {path}");
        }
        EventPayload::FileRename { old_path, new_path } => {
            println!("  type:   FileRename");
            println!("  from:   {old_path}");
            println!("  to:     {new_path}");
        }
        EventPayload::ToolInvoke {
            call_id,
            tool_name,
            arguments,
            category,
        } => {
            println!("  type:   ToolInvoke");
            println!("  tool:   {tool_name}");
            println!("  call:   {call_id}");
            if let Some(cat) = category {
                println!("  cat:    {cat}");
            }
            let args_str = serde_json::to_string(arguments).unwrap_or_default();
            let preview = if args_str.len() > 200 {
                format!("{}...", &args_str[..200])
            } else {
                args_str
            };
            println!("  args:   {preview}");
        }
        EventPayload::ToolResult {
            call_id,
            tool_name,
            duration_ms,
            status,
            ..
        } => {
            println!("  type:   ToolResult");
            println!("  tool:   {tool_name}");
            println!("  call:   {call_id}");
            println!("  status: {status:?}");
            println!("  dur:    {duration_ms}ms");
        }
        EventPayload::ApprovalRequested {
            approval_id,
            tool_name,
            risk,
            ..
        } => {
            println!("  type:   ApprovalRequested");
            println!("  tool:   {tool_name}");
            println!("  id:     {approval_id}");
            println!("  risk:   {risk:?}");
        }
        EventPayload::ApprovalResolved {
            approval_id,
            decision,
            reason,
        } => {
            println!("  type:   ApprovalResolved");
            println!("  id:     {approval_id}");
            println!("  decision: {decision:?}");
            if let Some(r) = reason {
                println!("  reason: {r}");
            }
        }
        EventPayload::Snapshot {
            snapshot_id,
            snapshot_type,
            covers_through_seq,
            ..
        } => {
            println!("  type:   Snapshot");
            println!("  id:     {snapshot_id}");
            println!("  kind:   {snapshot_type:?}");
            println!("  covers: seq {covers_through_seq}");
        }
        EventPayload::BranchCreated {
            new_branch_id,
            fork_point_seq,
            name,
        } => {
            println!("  type:   BranchCreated");
            println!("  branch: {new_branch_id}");
            println!("  name:   {name}");
            println!("  fork:   seq {fork_point_seq}");
        }
        EventPayload::BranchMerged {
            source_branch_id,
            merge_seq,
        } => {
            println!("  type:   BranchMerged");
            println!("  source: {source_branch_id}");
            println!("  merge:  seq {merge_seq}");
        }
        EventPayload::PolicyEvaluated {
            tool_name,
            decision,
            rule_id,
            explanation,
        } => {
            println!("  type:   PolicyEvaluated");
            println!("  tool:   {tool_name}");
            println!("  decision: {decision:?}");
            if let Some(id) = rule_id {
                println!("  rule:   {id}");
            }
            if let Some(exp) = explanation {
                println!("  reason: {exp}");
            }
        }
        EventPayload::Custom { event_type, data } => {
            println!("  type:   Custom({event_type})");
            let json = serde_json::to_string_pretty(data).unwrap_or_default();
            let preview = if json.len() > 200 {
                format!("{}...", &json[..200])
            } else {
                json
            };
            println!("  data:   {preview}");
        }
    }
}

/// Format a microsecond timestamp to a compact human-readable string.
fn format_timestamp(micros: u64) -> String {
    let secs = micros / 1_000_000;
    let frac = (micros % 1_000_000) / 1000; // milliseconds
    format!("{secs}.{frac:03}")
}
