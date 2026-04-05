# AI-Native Design

Lago is designed from the ground up as infrastructure for AI agents, not adapted from human-centric tools. Every design decision prioritizes the unique requirements of long-running, tool-using, branching agent workflows.

## Core Philosophy

### The Agent State Problem

AI agents today scatter their state across logs, databases, files, and memory stores. This creates fundamental problems:

- **No audit trail**: What did the agent do? In what order? Why?
- **No replay**: Can we reproduce a past agent run exactly?
- **No branching**: Can we explore alternative strategies without losing progress?
- **No governance**: Can we control what tools the agent uses?
- **No interoperability**: Every provider has a different streaming format

Lago solves all five by treating **every agent side-effect as an immutable event** in an append-only journal.

### Event Sourcing for Agents

Traditional databases store "current state" — you know what exists now but not how it got there. Event sourcing stores "what happened" — the full history of changes. For AI agents, this is transformative:

| Capability | Traditional DB | Event-Sourced (Lago) |
|-----------|---------------|---------------------|
| Audit trail | Manual logging | Automatic — every action is an event |
| Replay | Not possible | Replay events 0..N to reconstruct any state |
| Branching | Complex migrations | Fork at sequence N, write to new branch |
| Time travel | Snapshots only | Read events up to any point |
| Debugging | Parse logs | Query structured events by type, tool, time |
| Multi-view | One schema | Same events → multiple projections |

## Agent Workflow Patterns

### Tool Span Lifecycle

Every tool execution is captured as a structured span with begin/end events:

```
ToolInvoke { call_id: "call-1", tool_name: "file_write", arguments: {...} }
    |
    v
  [tool executes]
    |
    v
ToolResult { call_id: "call-1", tool_name: "file_write", result: {...}, duration_ms: 45, status: Ok }
```

The `call_id` links invoke and result events, enabling:
- Duration tracking per tool execution
- Error analysis (which tools fail most?)
- Cost attribution (which tools take longest?)
- Approval gates (pause between invoke and result)

### Approval Gates

For high-risk operations, Lago supports human-in-the-loop approval:

```
Agent wants to execute: exec_shell("rm -rf /tmp")
    |
    v
PolicyEngine evaluates → RequireApproval
    |
    v
ApprovalRequested { approval_id, tool_name: "exec_shell", risk: Critical }
    |
    v
  [human reviews and decides]
    |
    v
ApprovalResolved { approval_id, decision: Approved/Denied, reason: "..." }
    |
    v
ToolInvoke / (or blocked if denied)
```

This creates a complete audit trail of what was requested, who approved it, and why.

### Branching and Exploration

Agents can explore multiple strategies by branching:

```
Session: "research-agent"
Branch: "main"
  seq 0: SessionCreated
  seq 1: Message { role: "user", content: "Research X" }
  seq 2: ToolInvoke { tool: "web_search", args: "X" }
  seq 3: ToolResult { result: {...} }
  seq 4: Message { role: "assistant", content: "Found two approaches..." }
         |
         +-- Fork at seq 4 → Branch "approach-a"
         |     seq 5: ToolInvoke { tool: "analyze", args: "approach A" }
         |     seq 6: ToolResult { ... }
         |
         +-- Fork at seq 4 → Branch "approach-b"
               seq 5: ToolInvoke { tool: "analyze", args: "approach B" }
               seq 6: ToolResult { ... }
```

Branching is copy-on-write at the event level — no data is duplicated. The same events 0..4 are implicitly shared by all branches. Each branch tracks its own head sequence independently.

The manifest projection (`ManifestProjection`) builds the correct filesystem state for each branch by replaying only the relevant events.

### Multi-Format Streaming

Different agent frameworks expect different streaming formats. Lago's `SseFormat` trait adapts the same event stream:

```
Same EventEnvelope
    |
    +-- OpenAI format:    chat.completion.chunk + [DONE]
    +-- Anthropic format: content_block_delta + message_stop
    +-- Vercel format:    text-delta + finish-message
    +-- Lago native:      Full EventEnvelope JSON (all event types)
```

This means a single Lago instance can serve:
- OpenAI-compatible frontends (ChatGPT UI clones)
- Anthropic-compatible clients (Claude integrations)
- Vercel AI SDK applications (Next.js apps)
- Custom dashboards (using the native format with full event data)

### Session Lifecycle

```
1. SessionCreated { name: "agent-run-42", config: {...} }
   Creates session + "main" branch

2. Events accumulate on main branch
   Messages, ToolInvokes, ToolResults, FileWrites...

3. Optional: Branch for exploration
   BranchCreated { fork_point_seq: N, name: "experiment" }

4. Optional: Snapshot for fast replay
   Snapshot { covers_through_seq: 1000, type: Full }

5. Optional: Merge results back
   BranchMerged { source_branch_id, merge_seq }
```

## Virtual Filesystem

The filesystem manifest is a **projection** — derived state computed by replaying events:

```rust
impl Projection for ManifestProjection {
    fn on_event(&mut self, event: &EventEnvelope) -> LagoResult<()> {
        match &event.payload {
            FileWrite { path, blob_hash, .. } => self.manifest.apply_write(...),
            FileDelete { path } => self.manifest.apply_delete(path),
            FileRename { old_path, new_path } => self.manifest.apply_rename(...),
            BranchCreated { .. } => self.branch_manager.create_branch_with_id(...),
            _ => {} // Ignore other event types
        }
    }
}
```

This means:
- **No separate file database**: File state is always consistent with the event journal
- **Branch-aware**: Each branch has its own manifest state
- **Time-travel**: Build the manifest at any point in time by replaying events up to that sequence
- **Diffable**: Compare manifests between branches or points in time

Parent directories are implicitly created (like `mkdir -p`) when writing files, with `content_type: "inode/directory"` sentinel entries.

## Policy as Code

The policy engine runs inline with every tool invocation, not as an afterthought:

```
Agent calls tool
    → PolicyEngine evaluates rules (priority-ordered)
    → RBAC checks session permissions
    → Hooks fire (pre/post)
    → PolicyEvaluated event recorded in journal
```

Policy decisions are themselves events in the journal, creating a complete governance audit trail. Rules are configured in TOML for version-controlled, reviewable policy definitions.

## Design Decisions for AI Workloads

### Why redb (not PostgreSQL, Redis, or SQLite)?

| Requirement | redb | PostgreSQL | Redis | SQLite |
|------------|------|-----------|-------|--------|
| Embedded (no server) | Yes | No | No | Yes |
| Pure Rust (no FFI) | Yes | No | No | No |
| ACID transactions | Yes | Yes | No | Yes |
| Append-optimized | Yes | Tunable | Yes | Tunable |
| Single-file storage | Yes | No | No | Yes |
| Zero configuration | Yes | No | No | Mostly |

AI agents run locally, in containers, or as sidecars. An embedded database eliminates deployment complexity. Pure Rust eliminates cross-compilation headaches.

### Why JSON in Storage (not Protobuf)?

Events are stored as JSON in redb despite protobuf being used on the wire:

1. **Debuggability**: Events can be inspected with standard tools (`jq`, text editors)
2. **Schema evolution**: New event variants are automatically handled by serde's tagged enum
3. **No codegen dependency**: Storage layer doesn't depend on protobuf toolchain
4. **Reasonable performance**: JSON parsing overhead is acceptable for storage reads (not a hot path)

### Why ULID (not UUID v4 or nanoid)?

| Property | ULID | UUID v4 | nanoid |
|----------|------|---------|--------|
| Time-sortable | Yes | No | No |
| Monotonic ordering | Yes | No | No |
| Unique | Yes | Yes | Yes |
| Compact (26 chars) | Yes | No (36) | Configurable |
| Standard | Yes | Yes | No |

Time-sortability means events naturally sort by creation order when sorted by ID, useful for debugging and indexing.

### Why Compound Keys (not Auto-Increment)?

The 60-byte compound key (`session_id + branch_id + seq`) was chosen over simple auto-increment because:

1. **Locality**: All events for a session+branch are physically contiguous in the B-tree
2. **Multi-tenancy**: No global sequence counter bottleneck across sessions
3. **Range scans**: "Give me events 100-200 for session X, branch Y" is a single range query
4. **No coordination**: Each branch has its own sequence space

### Why BoxFuture (not async fn in trait)?

The `Journal` trait uses `BoxFuture` instead of Rust's `async fn in trait` because:

```rust
// This is dyn-compatible:
fn append(&self, event: EventEnvelope) -> BoxFuture<'_, LagoResult<SeqNo>>;

// This is NOT dyn-compatible:
async fn append(&self, event: EventEnvelope) -> LagoResult<SeqNo>;
```

Lago stores the journal as `Arc<dyn Journal>` for runtime polymorphism (different backends, testing, layering). `async fn in trait` methods produce anonymous `impl Future` types that cannot be used with trait objects.
