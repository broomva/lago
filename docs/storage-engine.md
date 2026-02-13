# Storage Engine

Lago uses two complementary storage systems: an **event journal** (redb) for structured event data and a **blob store** (filesystem) for content-addressed binary data.

## Event Journal (lago-journal)

### Storage Backend: redb

[redb](https://github.com/cberner/redb) is a pure-Rust, embedded, ACID-compliant key-value store. It was chosen over alternatives for:

| Property | redb | sled | SQLite |
|----------|------|------|--------|
| Pure Rust | Yes | Yes | No (C FFI) |
| ACID | Yes | Partial | Yes |
| File format stability | Stable v2 | Beta | Stable |
| MVCC | Yes | Yes | WAL mode |
| Supply chain risk | Minimal | Minimal | C dependency |

### Table Schema

The journal uses five redb tables:

#### `events` — Primary Event Store
```
Key:   [u8; 60]  = session_id(26B) + branch_id(26B) + seq(8B BE)
Value: &str       = JSON-serialized EventEnvelope
```

Events are stored as JSON strings for debuggability. The compound key ensures:
- All events for a session+branch are contiguous in the B-tree
- Lexicographic ordering matches logical ordering (session → branch → sequence)
- Range scans are efficient (no secondary index needed for primary access pattern)

#### `event_index` — Event ID Lookup
```
Key:   &str    = event_id (ULID string)
Value: [u8; 60] = compound key bytes
```

Enables O(1) lookup of any event by its ID, without scanning.

#### `branch_heads` — Sequence Tracking
```
Key:   [u8; 52] = session_id(26B) + branch_id(26B)
Value: u64      = current head sequence number
```

Tracks the monotonic sequence counter per session+branch. Updated atomically with event writes.

#### `sessions` — Session Metadata
```
Key:   &str = session_id (ULID string)
Value: &str = JSON-serialized Session
```

Stores session configuration and metadata.

#### `snapshots` — State Checkpoints
```
Key:   &str    = snapshot_id (ULID string)
Value: [u8]    = serialized snapshot data
```

Stores compressed state snapshots for faster replay.

### Compound Key Encoding

Keys use fixed-width encoding for deterministic byte ordering:

```
Offset  Length  Content
0       26      session_id (right-padded with spaces)
26      26      branch_id (right-padded with spaces)
52      8       seq (big-endian u64)
```

Big-endian encoding ensures numeric ordering matches byte ordering. Both ID fields are right-padded to exactly 26 bytes (ULID width) for fixed-width keys.

```rust
pub fn encode_event_key(session_id: &str, branch_id: &str, seq: u64) -> Vec<u8>
pub fn decode_event_key(bytes: &[u8]) -> (String, String, u64)
pub fn encode_branch_key(session_id: &str, branch_id: &str) -> Vec<u8>
pub fn decode_branch_key(bytes: &[u8]) -> (String, String)
```

### RedbJournal Implementation

`RedbJournal` implements the `Journal` trait with full ACID semantics:

```rust
pub struct RedbJournal {
    db: Arc<Database>,
    notify_tx: broadcast::Sender<EventNotification>,
}
```

**Key behaviors:**

- **All redb operations** run on `tokio::task::spawn_blocking` threads because redb is synchronous
- **Append**: single write transaction inserts into `EVENTS`, `EVENT_INDEX`, and `BRANCH_HEADS` atomically
- **Batch append**: multiple events in one transaction for throughput
- **Read**: supports range scans (session+branch+seq bounds), prefix scans (session only), or full scans
- **Stream**: returns an `EventTailStream` that receives `broadcast` notifications on new events
- **Notification channel**: capacity 4096, broadcasts `EventNotification { session_id, branch_id, seq }` on every append

### Query Execution

The `read_blocking` function handles three query patterns:

1. **Session + Branch specified**: Direct range scan using compound key prefix + seq bounds
2. **Session only**: Prefix scan across all branches, with in-memory filtering
3. **No filters**: Full table scan with in-memory filtering

All patterns apply `after_seq`, `before_seq`, and `limit` filters.

### Snapshots

```rust
pub const SNAPSHOT_THRESHOLD: u64 = 1000;

pub async fn create_snapshot(journal, session_id, branch_id) -> (Vec<u8>, SeqNo)
pub fn load_snapshot(data: &[u8]) -> Vec<EventEnvelope>
pub fn should_snapshot(head_seq: SeqNo) -> bool
```

Snapshots serialize all events for a session+branch as a JSON array. The `should_snapshot` check triggers at 1000+ events per branch.

## Blob Store (lago-store)

### Content-Addressed Storage

The blob store provides content-addressed storage with automatic deduplication:

```rust
pub struct BlobStore {
    root: PathBuf,
}
```

### Storage Layout

Blobs are stored in a git-like sharded directory structure:

```
{root}/
  ab/
    cdef0123456789...rest_of_hash.zst
  e3/
    b0c44298fc1c14...rest_of_hash.zst
```

The first two hex characters of the SHA-256 hash form the shard directory, preventing single directories from accumulating millions of files.

### Operations

#### Put
```rust
pub fn put(&self, data: &[u8]) -> LagoResult<BlobHash>
```
1. Compute SHA-256 hash of raw data
2. Check if blob already exists (content dedup)
3. If not: compress with zstd (level 3), write via temp file + atomic rename
4. Return `BlobHash` (hex string, 64 chars)

#### Get
```rust
pub fn get(&self, hash: &BlobHash) -> LagoResult<Vec<u8>>
```
1. Locate blob file by hash
2. Read compressed data from disk
3. Decompress with zstd
4. Return original bytes

#### Exists / Delete
```rust
pub fn exists(&self, hash: &BlobHash) -> bool
pub fn delete(&self, hash: &BlobHash) -> LagoResult<()>
```

### Hashing

```rust
pub fn hash_bytes(data: &[u8]) -> BlobHash     // SHA-256 hex digest
pub fn verify_hash(data: &[u8], expected: &BlobHash) -> bool
```

Known test vectors:
- `SHA-256("")` = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- `SHA-256("hello world")` = `b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9`

### Compression

```rust
pub const COMPRESSION_LEVEL: i32 = 3;  // zstd level (speed/ratio balance)
pub fn compress(data: &[u8]) -> LagoResult<Vec<u8>>
pub fn decompress(data: &[u8]) -> LagoResult<Vec<u8>>
```

### Design Properties

| Property | Guarantee |
|----------|-----------|
| Deduplication | Same content → same hash → stored once |
| Immutability | Content hash is identity; no overwrite |
| Crash safety | Atomic writes via temp file + rename |
| Compression | zstd level 3 on disk (~3-5x for text) |
| Scalability | Sharded directories (256 shards) |
| Integrity | SHA-256 verification on read |
