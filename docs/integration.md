# Integration Guide

Lago is designed to serve as the persistence substrate beneath agent runtimes. This guide explains how to integrate Lago into an external system, using the [Arcan](https://github.com/broomva/arcan) agent runtime as a concrete example.

## Architecture

An agent runtime typically has:
- An **orchestrator** that runs the agent loop (prompt -> model -> tool -> repeat)
- A **persistence layer** that stores session history for replay
- **Tool execution** with policy/governance hooks

Lago replaces the persistence layer with an event-sourced journal, content-addressed blob store, and policy engine:

```
Your Agent Runtime                    Lago
-----------------                    ----
Orchestrator / Agent Loop            RedbJournal (ACID event storage)
LLM Provider (Anthropic, OpenAI)     BlobStore (SHA-256 + zstd files)
Tool Registry                        PolicyEngine (RBAC + rules)
Middleware Stack                      SSE adapters (OpenAI/Anthropic/Vercel)
         |                                   |
         +---------- bridge crate -----------+
                 (event mapping layer)
```

## Integration Pattern

### 1. Implement Your Repository Trait

Most agent runtimes define a repository interface for session persistence. You bridge this to Lago's `Journal` trait.

**Example**: Arcan defines `SessionRepository`:

```rust
pub trait SessionRepository: Send + Sync {
    fn append(&self, request: AppendEvent) -> Result<EventRecord, StoreError>;
    fn load_session(&self, session_id: &str) -> Result<Vec<EventRecord>, StoreError>;
    fn load_children(&self, parent_id: &str) -> Result<Vec<EventRecord>, StoreError>;
    fn head(&self, session_id: &str) -> Result<Option<EventRecord>, StoreError>;
}
```

The bridge implementation wraps `Arc<dyn Journal>`:

```rust
pub struct LagoSessionRepository {
    journal: Arc<dyn Journal>,
    default_branch: BranchId,
}

impl LagoSessionRepository {
    pub fn new(journal: Arc<dyn Journal>) -> Self {
        Self {
            journal,
            default_branch: BranchId::from("main"),
        }
    }
}
```

### 2. Map Events Bidirectionally

Define a mapping between your runtime's event types and Lago's `EventPayload`. The mapping should be lossless for common event types and use `EventPayload::Custom` as a catch-all.

**Example mapping** (Arcan `AgentEvent` <-> Lago `EventPayload`):

| Runtime Event | Lago Payload | Notes |
|--------------|-------------|-------|
| `TextDelta { delta, iteration }` | `MessageDelta { role: "assistant", delta, index }` | Streaming text chunks |
| `ToolCallRequested { call }` | `ToolInvoke { call_id, tool_name, arguments }` | Tool execution start |
| `ToolCallCompleted { result }` | `ToolResult { ..., status: Ok }` | Successful tool result |
| `ToolCallFailed { error }` | `ToolResult { ..., status: Error }` | Failed tool result |
| `RunFinished { final_answer: Some(text) }` | `Message { role: "assistant", content }` | Final agent response |
| `RunStarted`, `ModelOutput`, etc. | `Custom { event_type, data }` | Serialized via serde_json |

The reverse mapping reconstructs runtime events from Lago payloads for session replay.

```rust
// Forward: runtime event -> Lago envelope
pub fn runtime_to_lago(
    session_id: &SessionId,
    branch_id: &BranchId,
    seq: SeqNo,
    event: &YourEvent,
) -> EventEnvelope {
    let payload = match event {
        YourEvent::TextChunk { text, .. } => EventPayload::MessageDelta {
            role: "assistant".to_string(),
            delta: text.clone(),
            index: 0,
        },
        // ... map other variants
        other => EventPayload::Custom {
            event_type: other.type_name().to_string(),
            data: serde_json::to_value(other).unwrap_or_default(),
        },
    };
    EventEnvelope { payload, ..build_envelope(session_id, branch_id, seq) }
}

// Reverse: Lago envelope -> runtime event
pub fn lago_to_runtime(envelope: &EventEnvelope) -> Option<YourEvent> {
    match &envelope.payload {
        EventPayload::MessageDelta { delta, .. } => {
            Some(YourEvent::TextChunk { text: delta.clone(), .. })
        }
        EventPayload::Custom { data, .. } => {
            serde_json::from_value(data.clone()).ok()
        }
        _ => None,
    }
}
```

### 3. Handle the Sync/Async Boundary

Lago's `Journal` trait is async (returns `BoxFuture`). If your runtime's repository interface is synchronous (common for agent loops that run on blocking threads), bridge with `Handle::current().block_on()`:

```rust
impl SessionRepository for LagoSessionRepository {
    fn append(&self, request: AppendEvent) -> Result<EventRecord, StoreError> {
        // Safe because the agent loop runs inside spawn_blocking
        let handle = tokio::runtime::Handle::current();
        let seq = handle.block_on(self.journal.head_seq(&session_id, &branch_id))?;
        let envelope = runtime_to_lago(&session_id, &branch_id, seq + 1, &request.event);
        handle.block_on(self.journal.append(envelope))?;
        Ok(event_record)
    }
}
```

This is safe when the calling code runs inside `tokio::task::spawn_blocking`, which is the standard pattern for agent orchestrators that need to call synchronous provider APIs.

### 4. Handle ID Mapping

Your runtime likely uses different ID types than Lago's ULIDs. Store the mapping in event metadata:

```rust
// Generate a Lago ULID for journal storage
let lago_event_id = EventId::new();

// Preserve the runtime's ID in metadata
let mut metadata = HashMap::new();
metadata.insert("runtime_event_id".to_string(), runtime_uuid.to_string());
```

On read, extract the runtime ID from metadata:

```rust
let runtime_id = envelope.metadata
    .get("runtime_event_id")
    .cloned()
    .unwrap_or_else(|| envelope.event_id.to_string());
```

### 5. Wire It Up

In your binary's `main()`, replace the old persistence backend with Lago:

```rust
use lago_journal::RedbJournal;
use lago_store::BlobStore;

// Open Lago storage
let journal = RedbJournal::open("data/journal.redb")?;
let blob_store = BlobStore::open("data/blobs")?;

// Create the bridge repository
let session_repo = Arc::new(LagoSessionRepository::new(Arc::new(journal)));

// Pass to your agent loop (same interface, new backend)
let agent_loop = AgentLoop::new(session_repo, orchestrator);
```

## Integrating the Policy Engine

Lago's policy engine can be bridged into your runtime's middleware stack to govern tool execution:

```rust
use lago_policy::PolicyEngine;
use lago_core::{PolicyContext, PolicyDecision};

pub struct LagoPolicyMiddleware {
    engine: PolicyEngine,
    tool_annotations: HashMap<String, ToolAnnotations>,
}

impl Middleware for LagoPolicyMiddleware {
    fn pre_tool_call(&self, call: &ToolCall, ctx: &ToolContext) -> Result<(), Error> {
        let risk = self.tool_annotations.get(&call.tool_name)
            .map(|ann| if ann.destructive { RiskLevel::High } else { RiskLevel::Low })
            .unwrap_or(RiskLevel::Low);

        let policy_ctx = PolicyContext {
            tool_name: call.tool_name.clone(),
            arguments: call.input.clone(),
            category: None,
            risk: Some(risk),
            session_id: ctx.session_id.clone(),
            role: None,
        };

        match self.engine.evaluate(&policy_ctx).decision {
            PolicyDecisionKind::Allow => Ok(()),
            PolicyDecisionKind::Deny => Err(Error::new("denied by policy")),
            PolicyDecisionKind::RequireApproval => Err(Error::new("approval required")),
        }
    }
}
```

Configure rules via TOML:

```toml
[[rules]]
id = "deny-destructive"
name = "Block destructive tools"
priority = 1
decision = "deny"
[rules.condition]
type = "RiskLevel"
value = "critical"
```

## Integrating the Blob Store

Intercept file-writing tool results to store content in the blob store and emit `FileWrite` events:

```rust
impl Middleware for LagoBlobMiddleware {
    fn post_tool_call(&self, call: &ToolCall, result: &Value, ctx: &ToolContext) -> Result<()> {
        if call.tool_name == "write_file" {
            let content = read_file_from_disk(&call.input["path"])?;
            let hash = self.blob_store.put(&content)?;

            let event = EventEnvelope {
                payload: EventPayload::FileWrite {
                    path: call.input["path"].as_str().unwrap().to_string(),
                    blob_hash: hash,
                    size_bytes: content.len() as u64,
                    content_type: None,
                },
                ..build_envelope(&ctx.session_id, &ctx.branch_id, next_seq)
            };
            self.journal.append(event).await?;
        }
        Ok(())
    }
}
```

## Complete Example: Arcan + Lago

The [`arcan-lago`](https://github.com/broomva/arcan) bridge crate demonstrates a full integration:

### Crate Structure

```
crates/arcan-lago/
  src/
    lib.rs           # Module exports
    event_map.rs     # AgentEvent <-> EventPayload bidirectional mapping
    repository.rs    # LagoSessionRepository implementing SessionRepository
```

### Event Mapping (event_map.rs)

Two functions handle the bidirectional conversion:

```rust
/// Runtime event -> Lago envelope
pub fn arcan_to_lago(
    session_id: &SessionId,
    branch_id: &BranchId,
    seq: SeqNo,
    run_id: &str,
    event: &AgentEvent,
    arcan_event_id: &str,
) -> EventEnvelope;

/// Lago envelope -> Runtime event (None for non-agent events)
pub fn lago_to_arcan(envelope: &EventEnvelope) -> Option<AgentEvent>;
```

All 10 `AgentEvent` variants are mapped. Common events use semantic Lago payloads (`MessageDelta`, `ToolInvoke`, `ToolResult`, `Message`). Less common events use `Custom` with full serde serialization for lossless round-tripping.

### Repository (repository.rs)

```rust
impl SessionRepository for LagoSessionRepository {
    fn append(&self, request: AppendEvent) -> Result<EventRecord, StoreError> {
        let seq = self.block_on(self.journal.head_seq(&sid, &bid))? + 1;
        let envelope = arcan_to_lago(&sid, &bid, seq, &run_id, &request.event, &uuid);
        self.block_on(self.journal.append(envelope))?;
        Ok(record)
    }

    fn load_session(&self, session_id: &str) -> Result<Vec<EventRecord>, StoreError> {
        let envelopes = self.block_on(self.journal.read(query))?;
        envelopes.iter()
            .filter_map(|env| lago_to_arcan(env).map(|event| EventRecord { event, .. }))
            .collect()
    }
}
```

### Unified Binary (agentd)

The `agentd` binary wires everything together:

```rust
// Lago persistence
let journal = RedbJournal::open(&data_dir.join("journal.redb"))?;
let blob_store = BlobStore::open(&data_dir.join("blobs"))?;
let session_repo = Arc::new(LagoSessionRepository::new(Arc::new(journal)));

// Arcan agent runtime
let provider = Arc::new(AnthropicProvider::new(config));
let orchestrator = Arc::new(Orchestrator::new(provider, tools, middlewares, config));
let agent_loop = Arc::new(AgentLoop::new(session_repo, orchestrator));

// HTTP server
let router = create_router(agent_loop).await;
axum::serve(listener, router).await?;
```

## Design Considerations

### Why a Bridge Crate?

Keeping the mapping layer in a separate crate:
- Avoids coupling either project to the other's types
- Allows independent versioning
- Makes it easy to swap out either side
- Keeps both projects publishable to crates.io independently

### Round-Trip Fidelity

Events that use `Custom` payloads serialize the full runtime event as JSON. This means:
- Zero information loss for round-tripping
- Schema changes in the runtime event type are automatically handled
- No proto/schema migration needed when adding new event variants

### Performance

- **Append path**: One redb write transaction per event (~100us on SSD)
- **Read path**: Range scan over compound keys, O(n) in result set
- **Sync/async bridge**: `block_on` adds ~1us overhead per call
- **JSON round-trip**: Microseconds for typical event sizes (< 10KB)

For high-throughput scenarios, use `journal.append_batch()` to write multiple events in a single transaction.
