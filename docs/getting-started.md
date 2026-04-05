# Getting Started

## Installation

### From crates.io (recommended)

```bash
cargo install lago
```

This installs the `lago` CLI binary, which includes both the client commands and the embedded daemon.

### From GitHub releases

```bash
curl -fsSL https://github.com/broomva/lago/raw/main/install.sh | bash
```

The script detects your OS and architecture, downloads the appropriate binary, and installs it to `~/.local/bin/lago`.

### From source

```bash
git clone https://github.com/broomva/lago.git
cd lago
cargo install --path crates/lago-cli
```

## Quick Start

### 1. Initialize a project

```bash
lago init .
```

This creates:
- `.lago/journal.redb` -- the event journal (ACID embedded database)
- `.lago/blobs/` -- content-addressed blob storage
- `lago.toml` -- daemon configuration

### 2. Start the daemon

```bash
lago serve
```

Starts two servers:
- **gRPC** on port `50051` (high-throughput event ingestion)
- **HTTP/REST** on port `8080` (queries, SSE streaming, file operations)

Override ports with flags:

```bash
lago serve --grpc-port 50051 --http-port 3000
```

### 3. Create a session

```bash
lago session create --name "my-agent"
```

Output:
```
Session created: 01JMK8N3XFVQ7R9T2Y5P6W4H0G
Branch: main (01JMK8N3XGWQ8S0U3Z6Q7X5I1H)
```

### 4. List sessions

```bash
lago session list
```

Output:
```
ID                          Name        Branches  Created
01JMK8N3XFVQ7R9T2Y5P6W4H0G  my-agent    1         2025-01-15 10:30:00
```

### 5. View the event log

```bash
lago log --session 01JMK8N3XFVQ7R9T2Y5P6W4H0G
```

Displays formatted events with type-specific fields. Use `--limit` and `--after` for pagination:

```bash
lago log --session <id> --limit 20 --after 100
```

### 6. Create a branch

Branches let agents explore alternative strategies without losing progress:

```bash
lago branch create --session <id> --name "experiment-a"
```

Fork from a specific point in history:

```bash
lago branch create --session <id> --name "rollback" --fork-at 50
```

### 7. List branches

```bash
lago branch list --session <id>
```

### 8. Read a file from the virtual filesystem

```bash
lago cat /src/main.rs --session <id>
```

## Using the HTTP API

### Create a session

```bash
curl -X POST http://localhost:8080/v1/sessions \
  -H "Content-Type: application/json" \
  -d '{"name": "my-agent", "model": "claude-sonnet-4-5-20250929"}'
```

### Stream events (SSE)

```bash
curl -N http://localhost:8080/v1/sessions/<id>/events?format=openai
```

Supported formats: `openai`, `anthropic`, `vercel`, `lago`

### Write a file

```bash
curl -X PUT http://localhost:8080/v1/sessions/<id>/files/src/main.rs \
  -H "Content-Type: application/octet-stream" \
  --data-binary @src/main.rs
```

### Read a file

```bash
curl http://localhost:8080/v1/sessions/<id>/files/src/main.rs
```

### Get the filesystem manifest

```bash
curl http://localhost:8080/v1/sessions/<id>/manifest
```

## Using the gRPC API

For high-throughput event ingestion from agent SDKs:

```rust
use lago_ingest::IngestClient;

let mut client = IngestClient::connect("http://localhost:50051").await?;
client.create_session("sess-01", "my-agent").await?;

let (sender, mut receiver) = client.open_stream().await?;

// Send events
sender.send_event(&event).await?;

// Receive acknowledgments
while let Some(resp) = receiver.recv().await {
    // handle ack
}
```

## Using Lago as a Library

Lago crates can be used directly without the daemon:

```rust
use lago_core::{EventEnvelope, EventPayload, Journal, SessionId, BranchId, EventId};
use lago_journal::RedbJournal;
use lago_store::BlobStore;

// Open the journal and blob store
let journal = RedbJournal::open("data/journal.redb")?;
let blobs = BlobStore::open("data/blobs")?;

// Create a session
let session_id = SessionId::new();
let branch_id = BranchId::from("main");

// Store a blob
let hash = blobs.put(b"file contents here")?;

// Append an event
let event = EventEnvelope {
    event_id: EventId::new(),
    session_id: session_id.clone(),
    branch_id: branch_id.clone(),
    run_id: None,
    seq: 1,
    timestamp: EventEnvelope::now_micros(),
    parent_id: None,
    payload: EventPayload::FileWrite {
        path: "/src/main.rs".to_string(),
        blob_hash: hash,
        size_bytes: 18,
        content_type: Some("text/x-rust".to_string()),
    },
    metadata: Default::default(),
};

journal.append(event).await?;
```

## Project Structure

After `lago init`, your project looks like:

```
my-project/
  .lago/
    journal.redb    # Event journal (redb database)
    blobs/          # Content-addressed blob storage
      ab/
        cdef01...zst  # Compressed file blobs
  lago.toml         # Configuration
```

## Configuration

`lago.toml`:

```toml
[daemon]
grpc_port = 50051
http_port = 8080
data_dir = ".lago"

[wal]
flush_interval_ms = 100
flush_threshold = 1000

[snapshot]
interval = 10000
```

CLI flags always override configuration file values.

## Next Steps

- [Architecture](architecture.md) -- understand the design philosophy and crate structure
- [Type System](type-system.md) -- learn about events, IDs, and core traits
- [API Reference](api-reference.md) -- full HTTP REST, SSE, and gRPC documentation
- [Integration Guide](integration.md) -- use Lago as a persistence substrate for your agent runtime
- [Filesystem & Branching](filesystem.md) -- virtual filesystem, branching, and diffing
