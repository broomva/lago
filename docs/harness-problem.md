# The Harness Problem

How Arcan + Lago addresses the agent harness problem — the challenge of giving AI agents proper filesystem access, tool execution, sandboxing, and a robust agent loop while maintaining complete auditability.

## Background

The **harness** is the entire interface layer between a language model's output and the actual changes made to a developer's workspace. It encompasses tool schemas, edit formats, error messages, state management, and every mechanism that translates model decisions into file modifications.

The **harness problem** (coined by [Can Boluk](https://blog.can.ac/2026/02/12/the-harness-problem/)) is the observation that this interface layer is a critically under-optimized, fragmented, and often model-specific component that dramatically affects agent performance — sometimes more than the choice of model itself. A different edit format alone can swing a model's benchmark score by 5-14 percentage points and cut output tokens by ~20%.

### Industry Approaches

| System | Approach | Key Insight |
|--------|----------|-------------|
| [Vercel bash-tool](https://vercel.com/blog/how-to-build-agents-with-filesystems-and-bash) | Filesystem-as-context + sandboxed bash. Removed 80% of tools (15->2), improved success 80%->100%, speed 275s->77s. | Models explore better with Unix primitives than bespoke retrieval tools. |
| [Can Boluk / hashline](https://blog.can.ac/2026/02/12/the-harness-problem/) | Content-addressed line identification. Lines tagged with short hashes instead of requiring exact string reproduction. | Edit format is the bottleneck. `str_replace` fails on whitespace; `apply_patch` has ~50% failure rates. Hashline improves all 16 tested models. |
| [OpenClaw](https://docs.openclaw.ai/concepts/agent-loop) | Three-stream event model (lifecycle/assistant/tool). Session serialization, compaction, hook-based extensibility. | The agent loop needs explicit lifecycle events, session-level concurrency control, and extension points at every boundary. |
| [Vercel AI SDK](https://ai-sdk.dev/docs/ai-sdk-ui/stream-protocol) | Structured SSE with `start/delta/end` triples, step abstraction, tool input streaming. | Streaming protocols need explicit step markers for agentic loop visibility and incremental tool input rendering. |

## How Arcan + Lago Addresses Each Dimension

### 1. Edit Format and Tool Output

**The problem:** `str_replace` requires exact character-level matching, including whitespace. `apply_patch` has ~50% failure rates across models. Retry loops burn massive output tokens attempting to re-specify the same edit.

**Current state:** Arcan provides standard tools — `read_file`, `write_file`, `edit` (str_replace style), `glob`, `grep`, `bash`. Lago records all tool invocations and results in the journal with full fidelity. Content-addressed blob storage (SHA-256) provides immutable snapshots of every file version.

**Architectural advantage:** Lago's blob store already uses content-addressing for files. Boluk's hashline concept (content-addressed line identification) is architecturally compatible — both systems derive deterministic identifiers from content rather than relying on positional references.

**Hashline integration opportunity:** Add a `hashline` mode to the `read_file` tool output format, where lines are tagged with content hashes:

```
11:a3|function hello() {
22:f1|  return "world";
33:0e|}
```

The `edit` tool then references lines by hash rather than exact string match:

```json
{
  "tool": "edit",
  "path": "src/main.rs",
  "after_hash": "a3",
  "before_hash": "0e",
  "new_content": "  return \"hello world\";\n"
}
```

This eliminates the "String to replace not found" failure class, reduces output tokens ~20%, breaks retry loops, and works across all models.

### 2. Filesystem as Context (Lazy Loading)

**Vercel's insight:** Replace bespoke retrieval tools with a filesystem metaphor. Organize domain knowledge as files. Let the model explore with `ls`, `grep`, `cat`. This dropped their agent from 15 tools to 2, improved accuracy to 100%, and cut cost from ~$1.00 to ~$0.25 per call.

**Arcan+Lago's approach:**
- Arcan provides `glob`, `grep`, `read_file` — the same primitives Vercel advocates
- Lago-fs provides a **virtual filesystem manifest** derived from events:
  - `ManifestEntry` with path, blob_hash, size, content_type
  - Implicit directory creation (like `mkdir -p`)
  - BTreeMap ordering for efficient range queries
- **Branching** enables exploring alternatives without losing work
- **Time travel** via diff between any two points in history or across branches

**Beyond Vercel:** Lago's filesystem is **event-sourced**. Every file write/delete/rename is an immutable event. You can reconstruct the filesystem at any point in history. Vercel's approach is stateless (files exist or don't); Lago's is fully temporal.

```
Event replay:
  FileWrite { path: "src/main.rs", blob_hash: "abc...", seq: 10 }
  FileWrite { path: "src/lib.rs",  blob_hash: "def...", seq: 11 }
  FileDelete { path: "src/old.rs",                      seq: 12 }
  FileRename { old: "src/lib.rs", new: "src/core.rs",   seq: 13 }

Manifest at seq 13:
  src/main.rs  -> blob "abc..."
  src/core.rs  -> blob "def..."

Manifest at seq 11:
  src/main.rs  -> blob "abc..."
  src/lib.rs   -> blob "def..."
  src/old.rs   -> blob "..."
```

### 3. Sandboxing and Safety

**Vercel's approach:** Three-tier sandboxing — `just-bash` (in-memory TypeScript interpreter, no disk/network access by default), `@vercel/sandbox` (full VM isolation), custom backends.

**Arcan+Lago's approach — governance-first:**

Lago has a **policy engine** that evaluates every tool call before execution:

```
Agent requests tool
  |
  v
Pre-hooks run (logging, metrics)
  |
  v
PolicyEngine::evaluate(PolicyContext { tool_name, arguments, risk, role, ... })
  |
  v
Rules evaluated in priority order (first match wins):
  1. deny-shell (priority 1): tool_name == "exec_shell" -> Deny
  2. approve-destructive (priority 10): risk >= High -> RequireApproval
  3. allow-filesystem (priority 100): category == "filesystem" -> Allow
  |
  v
PolicyDecision: Allow | Deny | RequireApproval
  |
  v
PolicyEvaluated event recorded in journal
  |
  v
If RequireApproval:
  ApprovalRequested event -> human reviews -> ApprovalResolved event
```

**Key mechanisms:**

| Layer | Mechanism |
|-------|-----------|
| **Rule evaluation** | Priority-ordered rules with `MatchCondition` predicates (tool name, category, risk level, boolean combinators) |
| **RBAC** | Role-based permissions per session. Deny always wins over Allow. |
| **Approval gates** | Human-in-the-loop for high-risk operations. `ApprovalRequested`/`ApprovalResolved` events recorded in journal. |
| **Hooks** | Pre/post tool call hooks for logging, metrics, notifications. All matching hooks run (unlike rules which stop at first match). |
| **TOML config** | Rules, roles, and hooks defined in version-controlled TOML files. |
| **Audit trail** | Every policy evaluation recorded as an immutable event. |

**Comparison:**

| Dimension | Vercel | Arcan+Lago |
|-----------|--------|------------|
| Execution isolation | Strong (in-memory FS, no network) | Gap — needs process-level sandboxing |
| Governance | CLI allow-lists | Strong — policy engine, RBAC, approvals |
| Audit trail | None | Full — every decision in the journal |
| Configuration | Code-level | TOML files (version-controlled) |
| Human-in-the-loop | None | Approval gates with events |

### 4. Agent Loop Architecture

**OpenClaw's model:** `intake -> context assembly -> model inference -> tool execution -> streaming -> persistence`. Three event streams (lifecycle, assistant, tool). Session serialization, compaction, hooks.

**Arcan+Lago's model:**

```
Arcan (agent brain)                   Lago (persistence spine)
-----------------------               -----------------------
1. Build context (history, tools)     journal.read() -> event history
2. Call LLM (Anthropic, OpenAI)       -
3. Parse response                     -
4. Dispatch tool calls                PolicyEngine.evaluate()
5. Collect results                    blob_store.put() for file content
6. Append all events                  journal.append_batch() [atomic]
7. Stream to clients                  SseFormat adapters
8. Check termination                  -
9. Repeat or finish                   Snapshot if threshold reached
```

**Event types covering the full lifecycle:**

| Category | Event Types |
|----------|-------------|
| Session | `SessionCreated`, `SessionResumed` |
| LLM I/O | `Message`, `MessageDelta` |
| Tools | `ToolInvoke`, `ToolResult` |
| Files | `FileWrite`, `FileDelete`, `FileRename` |
| Policy | `PolicyEvaluated`, `ApprovalRequested`, `ApprovalResolved` |
| Branching | `BranchCreated`, `BranchMerged` |
| Snapshots | `Snapshot` (Full or Incremental) |
| Extensibility | `Custom { event_type, data }` |

**Alignment with OpenClaw patterns:**

| OpenClaw Pattern | Arcan+Lago Equivalent |
|---|---|
| Three event streams (lifecycle/assistant/tool) | Discriminated `EventPayload` union in single journal |
| Session serialization (per-session lanes) | Compound key (session + branch + seq) with redb write serialization |
| Compaction (context window management) | Snapshot events + replay from snapshot |
| `tool_result_persist` hook | `ToolResult` event with full result in journal |
| Timeout/abort handling | `RunErrored` custom event type |
| `before_tool_call`/`after_tool_call` hooks | Pre/post hooks in policy engine |

**Unique to Arcan+Lago:**
- **Branching** at the event level — no other system provides this
- **Snapshots** for fast replay of long sessions (threshold: 1000 events)
- **Content-addressed blobs** — file content deduplicated and immutable
- **Policy decisions as events** — governance is part of the audit trail
- **Multiple SSE format adapters** — same events stream as OpenAI, Anthropic, Vercel, or native format

### 5. Streaming Protocol

**Vercel AI SDK evolved to** a structured SSE protocol (UI Message Stream v1):
- `start/delta/end` triples for all content types (text, reasoning, tool input)
- `start-step/finish-step` markers for agentic loop visibility
- Tool input streaming (`tool-input-start/delta/available`)
- `x-vercel-ai-ui-message-stream: v1` header

**Lago's SSE implementation** uses the `SseFormat` trait to adapt events to multiple wire formats:

```rust
pub trait SseFormat: Send + Sync {
    fn format(&self, event: &EventEnvelope) -> Vec<SseFrame>;
    fn done_frame(&self) -> Option<SseFrame>;
    fn extra_headers(&self) -> Vec<(String, String)>;
    fn name(&self) -> &str;
}
```

**Four format adapters:**

| Format | Wire Shape | Key Features |
|--------|-----------|--------------|
| **OpenAI** | `chat.completion.chunk` JSON | `choices[].delta`, `[DONE]` sentinel |
| **Anthropic** | Multi-frame sequence | `message_start`, `content_block_delta`, `message_stop` |
| **Vercel** | `text-delta` / `finish-message` | `x-vercel-ai-data-stream: v1` header |
| **Native Lago** | Full `EventEnvelope` JSON | All event types visible (tools, files, policy, branches) |

**Gap:** The Vercel adapter currently targets the older Data Stream protocol (`x-vercel-ai-data-stream: v1`). The upstream SDK has evolved to the richer UI Message Stream protocol with step markers, text block lifecycle, and tool input streaming.

## Comparative Architecture Matrix

| Capability | Vercel bash-tool | OpenClaw | Arcan+Lago |
|---|---|---|---|
| **Agent loop** | External (AI SDK) | Built-in | Built-in (Arcan) |
| **Filesystem** | Virtual (just-bash) | Workspace-based | Event-sourced manifest |
| **Branching** | None | None | First-class (copy-on-write events) |
| **Time travel** | None | None | Full (event replay to any seq) |
| **Edit format** | Full rewrite | str_replace | str_replace (hashline opportunity) |
| **Sandboxing** | 3-tier (bash/VM/custom) | Workspace isolation | Policy engine + RBAC |
| **Persistence** | None (stateless) | Session transcript | ACID journal (redb) |
| **Streaming** | AI SDK protocol | 3-stream SSE | 4-format SSE + gRPC ingest |
| **Governance** | CLI allow-lists | Plugin hooks | Policy engine + approval gates |
| **Content addressing** | None | None | SHA-256 + zstd blobs |
| **Audit trail** | None | Session logs | Immutable event journal |
| **Deduplication** | None | None | Automatic (same hash = same blob) |

## Unique Differentiators

### Event-Sourced Filesystem

Every other system treats the filesystem as mutable state. Lago treats it as a **projection of immutable events**. This means:

- **Complete history**: See every version of every file, when it changed, and why
- **Branching**: Fork the filesystem at any point, explore alternatives independently
- **Diffing**: Compare any two states (different times, different branches)
- **Crash recovery**: Incomplete writes are simply absent from the journal
- **Debugging**: Query structured events to understand what happened

### Content-Addressed Deduplication

When an agent writes the same file content to multiple paths, or reverts a file to a previous version, the blob store stores the content only once. This is transparent — the journal records `FileWrite` events with different paths but the same `blob_hash`.

### Governance as Events

Policy decisions are not side-effects — they are first-class events in the journal:

```json
{
  "payload": {
    "type": "PolicyEvaluated",
    "tool_name": "bash",
    "decision": "Deny",
    "rule_id": "deny-shell",
    "explanation": "Shell access not permitted for this session"
  }
}
```

This means you can query "which tool calls were denied and why?" the same way you query "which files were written?" — it is all in the same journal.

### Multi-Format Streaming

The same event stream can be consumed by:
- An OpenAI-compatible client (ChatGPT-style UI)
- An Anthropic-compatible client (Claude-style UI)
- A Vercel AI SDK frontend (Next.js app)
- A native Lago client (full event visibility including tools, files, policy)

No other system provides this level of protocol compatibility from a single event source.

## Roadmap

### Phase 1: Hashline Edit Format

Solve the core harness problem — edit format failures.

1. Add `hashline` module to `lago-core` — line-level content hashing
2. Add hashline-aware `read_file` output — annotate lines with content hashes
3. Add hashline-aware `edit` tool — reference lines by hash instead of exact string
4. Benchmark edit success rates before/after across models

**Expected impact:** Eliminate the "String to replace not found" failure class. ~20% reduction in output tokens. Improved success rates across all models.

### Phase 2: Execution Sandboxing

Match Vercel's three-tier containment model with Lago's governance.

| Tier | Scope | Mechanism |
|------|-------|-----------|
| **1 (default)** | Path validation, size limits, command filtering | Already partial — formalize and complete |
| **2 (enhanced)** | Process isolation | `bubblewrap`/`nsjail` (Linux), `sandbox-exec` (macOS) |
| **3 (full)** | Container isolation | Docker/Firecracker for untrusted workloads |

Record sandbox tier and violations as events in the journal (`SandboxCreated`, `SandboxViolation`).

### Phase 3: Vercel Stream Protocol Update

Update `crates/lago-api/src/sse/vercel.rs` to support the UI Message Stream protocol:

- Add message lifecycle (`start`/`finish`)
- Add step markers (`start-step`/`finish-step`)
- Add text block markers (`text-start`/`text-end`)
- Stream tool inputs incrementally (`tool-input-start`/`tool-input-delta`/`tool-input-available`)
- Update header to `x-vercel-ai-ui-message-stream: v1`

### Phase 4: Bridge Crate Completion (arcan-lago)

Complete the integration documented in the [Integration Guide](integration.md):

1. Finish `LagoSessionRepository` implementation
2. Complete bidirectional event mapping (all AgentEvent variants)
3. Build `agentd` unified binary
4. Add blob middleware for file content storage
5. Wire policy bridge middleware

### Phase 5: Agent Skills and Context Organization

Apply Vercel's "filesystem as context" insight systematically:

1. Formalize skills framework — `SKILL.md` files discoverable by agents, backed by event-sourced skill manifests
2. Define guidelines for structuring agent knowledge as files — hierarchical layout matching domain semantics, lazy loading via `glob`/`grep`/`read_file` instead of prompt stuffing

## References

- [How to build agents with filesystems and bash](https://vercel.com/blog/how-to-build-agents-with-filesystems-and-bash) — Vercel
- [The Harness Problem](https://blog.can.ac/2026/02/12/the-harness-problem/) — Can Boluk
- [OpenClaw Agent Loop](https://docs.openclaw.ai/concepts/agent-loop) — OpenClaw
- [AI SDK Stream Protocol](https://ai-sdk.dev/docs/ai-sdk-ui/stream-protocol) — Vercel AI SDK
- [We removed 80% of our agent's tools](https://vercel.com/blog/we-removed-80-percent-of-our-agents-tools) — Vercel
- [Testing if "bash is all you need"](https://vercel.com/blog/testing-if-bash-is-all-you-need) — Vercel
