# API Reference

Lago exposes two transport layers: a **gRPC** bidirectional streaming interface for high-throughput event ingestion, and an **HTTP/REST** API with SSE for queries and real-time streaming.

## HTTP REST API (lago-api)

Base URL: `http://localhost:8080`

### Health

```
GET /health
Response: { "status": "ok" }
```

### Sessions

#### Create Session
```
POST /v1/sessions
Content-Type: application/json

{
  "name": "my-agent-session",
  "model": "claude-sonnet-4-5-20250929",        // optional
  "params": { "key": "value" }   // optional
}

Response (201):
{
  "session_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "branch_id": "01BSR3NDEKTSV4RRFFQ69G5FAW"
}
```

Creates a new session with a "main" branch and emits a `SessionCreated` event.

#### List Sessions
```
GET /v1/sessions

Response (200):
[
  {
    "session_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
    "name": "my-agent-session",
    "model": "claude-sonnet-4-5-20250929",
    "created_at": 1700000000000000,
    "branches": ["01BSR3NDEKTSV4RRFFQ69G5FAW"]
  }
]
```

#### Get Session
```
GET /v1/sessions/{session_id}

Response (200): SessionResponse (same shape as list item)
Response (404): { "error": "session_not_found", "message": "..." }
```

### Event Streaming (SSE)

```
GET /v1/sessions/{session_id}/events?format=openai&branch=main&after_seq=0
Headers:
  Last-Event-ID: 42    (optional, overrides after_seq for reconnection)

Response: text/event-stream
```

#### Query Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `format` | `lago` | SSE format: `openai`, `anthropic`, `vercel`, `lago` |
| `branch` | `main` | Branch to stream from |
| `after_seq` | `0` | Start after this sequence number |

#### SSE Frame Structure

Each SSE frame has:
- `event:` — Event type (format-dependent)
- `data:` — JSON payload
- `id:` — Sequence number (for reconnection)

Keep-alive pings sent every 15 seconds.

### Branches

#### Create Branch
```
POST /v1/sessions/{session_id}/branches
Content-Type: application/json

{
  "name": "experiment-a",
  "fork_point_seq": 1000    // optional, defaults to head
}

Response (201):
{
  "branch_id": "01CSU3NDEKTSV4RRFFQ69G5FAW",
  "name": "experiment-a",
  "fork_point_seq": 1000
}
```

#### List Branches
```
GET /v1/sessions/{session_id}/branches

Response (200):
[
  { "branch_id": "...", "name": "main", "fork_point_seq": 0 },
  { "branch_id": "...", "name": "experiment-a", "fork_point_seq": 1000 }
]
```

### Files (Virtual Filesystem)

#### Read File
```
GET /v1/sessions/{session_id}/files/{path}

Response (200): Raw binary data
Headers:
  content-type: text/plain (or detected type)
  x-blob-hash: abcdef0123456789...
```

#### Write File
```
PUT /v1/sessions/{session_id}/files/{path}
Content-Type: application/octet-stream
Body: Raw binary file content

Response (201):
{
  "path": "/src/main.rs",
  "blob_hash": "abcdef0123456789...",
  "size_bytes": 1234
}
```

Stores the blob and emits a `FileWrite` event.

#### Delete File
```
DELETE /v1/sessions/{session_id}/files/{path}

Response (204): No content
```

Emits a `FileDelete` event. The blob itself is not deleted (immutable).

#### Get Manifest
```
GET /v1/sessions/{session_id}/manifest

Response (200):
{
  "session_id": "...",
  "entries": [
    {
      "path": "/src/main.rs",
      "blob_hash": "abcdef...",
      "size_bytes": 1234,
      "content_type": "text/x-rust",
      "updated_at": 1700000000000000
    }
  ]
}
```

### Blobs (Direct Access)

#### Get Blob
```
GET /v1/blobs/{hash}

Response (200): Raw binary data
Headers:
  content-type: application/octet-stream
  x-blob-hash: abcdef...
```

#### Put Blob
```
PUT /v1/blobs/{hash}
Body: Raw binary data

Response (201):
{
  "hash": "abcdef...",
  "size_bytes": 1234
}

Response (400): Hash mismatch if computed hash != path hash
```

### Error Responses

All errors return JSON:
```json
{
  "error": "error_type",
  "message": "Human-readable description"
}
```

| LagoError | HTTP Status |
|-----------|-------------|
| `SessionNotFound` | 404 |
| `BranchNotFound` | 404 |
| `EventNotFound` | 404 |
| `BlobNotFound` | 404 |
| `FileNotFound` | 404 |
| `InvalidArgument` | 400 |
| `Serialization` | 400 |
| `SequenceConflict` | 409 |
| `PolicyDenied` | 403 |
| Other | 500 |

### Middleware

- **CORS**: Permissive (any origin, methods, headers) — suitable for development
- **Tracing**: Request-level tracing via `tower-http`

---

## SSE Format Adapters

Lago adapts the same event stream to four wire formats via the `SseFormat` trait.

### OpenAI Compatible

Matches the [OpenAI Streaming API](https://platform.openai.com/docs/api-reference/streaming) format:

```
data: {"id":"chatcmpl-01ARZ3...","object":"chat.completion.chunk","created":1700000000,"model":"claude-sonnet-4-5-20250929","choices":[{"index":0,"delta":{"role":"assistant","content":"Hello"},"finish_reason":"stop"}]}

data: [DONE]
```

- Only `Message` and `MessageDelta` events are emitted; other event types are filtered
- `finish_reason` is `"stop"` for complete messages, `null` for deltas
- Done signal: `data: [DONE]`

### Anthropic Compatible

Matches the [Anthropic Messages Streaming API](https://docs.anthropic.com/en/api/messages-streaming) format:

```
event: message_start
data: {"type":"message_start","message":{"id":"msg_01ARZ3...","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-5-20250929"},"usage":{"input_tokens":0,"output_tokens":0}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}

event: message_stop
data: {"type":"message_stop"}
```

- Complete messages emit 5 frames (start → block_start → delta → block_stop → message_delta)
- Streaming deltas emit 1 frame (content_block_delta)
- Done signal: `event: message_stop`

### Vercel AI SDK Compatible

Matches the [Vercel AI SDK Data Stream Protocol](https://sdk.vercel.ai/docs/ai-sdk-ui/stream-protocol):

```
data: {"type":"text-delta","id":"01ARZ3...","delta":"Hello"}

data: {"type":"finish-message","finishReason":"stop"}
```

- Extra header: `x-vercel-ai-data-stream: v1`
- Messages and deltas both produce `text-delta` frames
- Done signal: `finish-message` with `finishReason`

### Lago Native

Passes through all events unchanged as full `EventEnvelope` JSON:

```
event: event
data: {"event_id":"01ARZ3...","session_id":"...","branch_id":"...","seq":1,"timestamp":1700000000000000,"payload":{"type":"FileWrite","path":"/src/main.rs","blob_hash":"abcdef...","size_bytes":1234},"metadata":{}}

event: done
data: {"type":"done"}
```

- Every event type is included (not just messages)
- Full envelope with all metadata
- Suitable for building custom UIs or replaying events

---

## gRPC API (lago-ingest)

### Service Definition

```protobuf
service IngestService {
  rpc Ingest(stream IngestRequest) returns (stream IngestResponse);
  rpc CreateSession(CreateSessionRequest) returns (CreateSessionResponse);
  rpc GetSession(GetSessionRequest) returns (GetSessionResponse);
}
```

Default port: `50051`

### Bidirectional Streaming: `Ingest`

The primary ingestion path. Clients stream events, server responds with acks:

**Client → Server (IngestRequest)**:
```protobuf
message IngestRequest {
  oneof message {
    EventEnvelope event = 1;    // Event to persist
    Heartbeat heartbeat = 2;    // Keep-alive
  }
}
```

**Server → Client (IngestResponse)**:
```protobuf
message IngestResponse {
  oneof message {
    Ack ack = 1;                        // Event acknowledgment
    Heartbeat heartbeat = 2;            // Keep-alive response
    BackpressureSignal backpressure = 3; // Flow control
  }
}
```

**Wire Format for Events**:
```protobuf
message EventEnvelope {
  string event_id = 1;
  string session_id = 2;
  string branch_id = 3;
  optional string run_id = 4;
  uint64 seq = 5;
  uint64 timestamp = 6;
  optional string parent_id = 7;
  string payload_json = 8;     // EventPayload serialized as JSON
  map<string, string> metadata = 9;
}
```

The `payload_json` field carries the `EventPayload` as a JSON string rather than a nested protobuf message. This avoids tight proto coupling with the event type system — new event variants can be added without proto schema changes.

**Acknowledgment**:
```protobuf
message Ack {
  string event_id = 1;
  uint64 seq = 2;
  bool success = 3;
  optional string error = 4;
}
```

### Unary RPCs

```protobuf
message CreateSessionRequest {
  string session_id = 1;
  SessionConfig config = 2;
}

message CreateSessionResponse {
  string session_id = 1;
  bool created = 2;
}

message GetSessionRequest {
  string session_id = 1;
}

message GetSessionResponse {
  string session_id = 1;
  SessionConfig config = 2;
  uint64 event_count = 3;
}
```

### Client SDK

```rust
let mut client = IngestClient::connect("http://localhost:50051").await?;
client.create_session("sess-01", "my-agent").await?;

let (sender, mut receiver) = client.open_stream().await?;

// Send events
sender.send_event(&event).await?;
sender.send_heartbeat().await?;

// Receive acks
while let Some(resp) = receiver.recv().await {
    // Handle ack or heartbeat
}
```

### Codec Layer

The codec converts between protobuf wire types and core Rust types:

```rust
pub fn event_to_proto(event: &EventEnvelope) -> proto::EventEnvelope
pub fn event_from_proto(proto: proto::EventEnvelope) -> Result<EventEnvelope, serde_json::Error>
pub fn make_ack(event_id: &str, seq: u64, success: bool, error: Option<String>) -> proto::Ack
pub fn make_heartbeat() -> proto::Heartbeat
```
