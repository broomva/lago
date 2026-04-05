# Architecture Rules

## Event Sourcing

- All state is derived from the append-only event journal. Never mutate state directly.
- Events are immutable once written. Use compensating events to "undo".
- Compound key format: `session_id(26B) + branch_id(26B) + seq(8B BE)` = 60 bytes.

## Async & Blocking I/O

- redb is synchronous; always wrap operations in `tokio::task::spawn_blocking`.
- gRPC and HTTP handlers are fully async (tonic/axum).
- Use `BoxFuture` for trait methods that need dyn-compatibility (`Arc<dyn Journal>`).

## Serialization

- **Wire format (gRPC)**: Protobuf via prost. Proto files in `proto/lago/v1/`.
- **Storage format (redb)**: JSON via serde_json.
- **HTTP API**: JSON request/response, SSE for streaming.

## SSE Compatibility

- The `SseFormat` trait adapts events to multiple wire formats.
- Supported: OpenAI, Anthropic, Vercel AI SDK, native Lago format.
- New formats implement `SseFormat` in `lago-api/src/sse/`.
