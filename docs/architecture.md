# Architecture

## Design Philosophy

Lago treats the **event journal as the single source of truth**. All state — filesystem manifests, session metadata, policy decisions — is derived by replaying events. This event-sourcing approach provides:

- **Complete auditability**: Every agent action is recorded with causal ordering
- **Time travel**: Replay to any point in history by replaying events up to sequence N
- **Branching**: Fork agent state by reading events up to a fork point, then writing to a new branch
- **Multi-format streaming**: Same event stream adapted to OpenAI, Anthropic, Vercel, or native wire formats

## Core Principles

### Append-Only Immutability

Events are never modified or deleted after write. "Undoing" an action means emitting a compensating event (e.g., `FileDelete` reverses a `FileWrite`). This guarantees:

- Crash recovery: incomplete writes are simply absent
- Concurrent readers: no locks needed for read operations
- Audit trail: every action is permanently recorded

### Content Addressing

File contents are stored in a separate blob store indexed by SHA-256 hash. Events reference blobs by hash, enabling:

- **Deduplication**: identical files stored once
- **Integrity verification**: hash is the identity
- **Decoupled storage**: events are small (metadata), blobs are large (content)

### Separation of Wire and Storage Formats

- **Wire format (gRPC)**: Protocol Buffers — compact binary, schema-evolving
- **Storage format (redb)**: JSON — human-readable, debuggable with standard tools
- **API format (HTTP)**: JSON request/response, SSE for streaming

This separation allows each layer to optimize independently. The gRPC ingest layer handles high-throughput agent streams, while the storage layer prioritizes inspectability.

## Workspace Structure

The project is organized as a Cargo workspace with 9 crates following a strict dependency hierarchy:

```
lago-core        (zero deps — foundation types, traits, errors)
  |
  +-- lago-store       (content-addressed blob storage)
  +-- lago-journal     (event journal over redb)
  +-- lago-fs          (virtual filesystem + branching)
  +-- lago-policy      (RBAC + rule-based governance)
  |
  +-- lago-ingest      (gRPC streaming ingest)
  |     depends on: core, journal
  |
  +-- lago-api         (HTTP REST + SSE streaming)
  |     depends on: core, journal, store, fs, policy
  |
  +-- lago-cli         (CLI binary)
  |     depends on: api, journal, store
  |
  +-- lagod            (daemon binary — composes all subsystems)
```

### Crate Responsibilities

| Crate | Role | Key Trait/Type |
|-------|------|----------------|
| `lago-core` | Foundation types shared by all crates | `Journal`, `Projection`, `EventEnvelope` |
| `lago-journal` | Persistent event storage via redb | `RedbJournal` |
| `lago-store` | Content-addressed blob storage | `BlobStore` |
| `lago-fs` | Virtual filesystem derived from events | `Manifest`, `ManifestProjection` |
| `lago-policy` | Security rules and access control | `PolicyEngine`, `RbacManager` |
| `lago-ingest` | gRPC bidirectional streaming | `IngestServer`, `IngestClient` |
| `lago-api` | HTTP/REST + SSE endpoints | `AppState`, `SseFormat` |
| `lago-cli` | Command-line interface | `lago init/serve/session/log/cat` |
| `lagod` | Daemon process | Composes journal + store + gRPC + HTTP |

### Dependency Rules

1. **lago-core is dependency-free**: Only `std`, `serde`, `ulid`, and `thiserror` allowed
2. **Library crates use `thiserror`** for typed errors; binary crates may use `anyhow`
3. **All shared deps** declared in root `Cargo.toml` `[workspace.dependencies]` and inherited via `{ workspace = true }`
4. **Proto files** live in `proto/lago/v1/`, compiled by `lago-ingest/build.rs`

## Async & Blocking Boundaries

The system has a clear boundary between async and synchronous code:

```
Async Layer (tokio)           Blocking Layer (spawn_blocking)
+------------------------+    +------------------------+
| axum HTTP handlers     |    |                        |
| tonic gRPC handlers    |--->| redb read/write txns   |
| SSE stream adapters    |    | Blob filesystem I/O    |
| Journal trait (BoxFuture)|  |                        |
+------------------------+    +------------------------+
```

- **redb** is synchronous — all database operations run on `tokio::task::spawn_blocking` threads
- **gRPC and HTTP** handlers are fully async (tonic/axum)
- The **Journal trait** uses `BoxFuture` (not `async fn in trait`) for dyn-compatibility with `Arc<dyn Journal>`

## Data Flow

### Event Ingestion (gRPC)

```
Agent SDK --> IngestClient --> gRPC stream --> IngestServer
                                                  |
                                                  v
                                         codec::event_from_proto()
                                                  |
                                                  v
                                         journal.append(event)
                                                  |
                                                  v
                                        redb write transaction
                                        (EVENTS + EVENT_INDEX +
                                         BRANCH_HEADS tables)
                                                  |
                                                  v
                                        broadcast notification
                                                  |
                                                  v
                                              Ack response
```

### Event Consumption (SSE)

```
HTTP Client --> GET /v1/sessions/{id}/events?format=openai
                          |
                          v
                journal.stream(session, branch, after_seq)
                          |
                          v
                   EventTailStream
                   (broadcast receiver)
                          |
                          v
               SseFormat::format(event) --> Vec<SseFrame>
                          |
                          v
                   axum SSE response
                   (with 15s keep-alive)
```

### File Operations

```
PUT /v1/sessions/{id}/files/src/main.rs
          |
          v
   blob_store.put(body) --> BlobHash (SHA-256)
          |
          v
   journal.append(FileWrite { path, blob_hash, size })
          |
          v
   Response: { path, blob_hash, size_bytes }

GET /v1/sessions/{id}/files/src/main.rs
          |
          v
   journal.read(session) --> events
          |
          v
   ManifestProjection::on_event() for each event
          |
          v
   manifest.get("/src/main.rs") --> ManifestEntry { blob_hash }
          |
          v
   blob_store.get(blob_hash) --> raw bytes
```

## Concurrency Model

- **Single writer**: redb enforces single-writer semantics (ACID transactions)
- **Multiple readers**: redb supports concurrent read transactions via MVCC
- **Event notifications**: `tokio::sync::broadcast` (capacity 4096) notifies SSE streams of new events
- **Backpressure**: gRPC ingest uses mpsc channel (buffer 256) for flow control
