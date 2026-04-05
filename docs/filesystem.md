# Filesystem & Branching

Lago provides a virtual filesystem (`lago-fs`) that derives file state entirely from the event journal. Files are never stored directly -- instead, `FileWrite`, `FileDelete`, and `FileRename` events in the journal are replayed to reconstruct the current filesystem state at any point in time or on any branch.

## Manifest

The `Manifest` is a sorted map (`BTreeMap<String, ManifestEntry>`) that tracks every file in the virtual filesystem.

### ManifestEntry

Each file is represented by a `ManifestEntry`:

```rust
pub struct ManifestEntry {
    pub path: String,           // Absolute path (e.g., "/src/main.rs")
    pub blob_hash: BlobHash,    // SHA-256 hash of the file content
    pub size_bytes: u64,        // Original (uncompressed) size
    pub content_type: Option<String>,  // MIME type (e.g., "text/x-rust")
    pub updated_at: u64,        // Timestamp in microseconds since epoch
}
```

The actual file content lives in the blob store (`lago-store`), referenced by `blob_hash`. This decouples metadata from content, enabling deduplication and efficient diffing.

### Operations

```rust
let mut manifest = Manifest::new();

// Write a file (creates parent directories automatically)
manifest.apply_write(
    "/src/main.rs".to_string(),
    blob_hash,
    1024,
    Some("text/x-rust".to_string()),
    timestamp,
);

// Delete a file
manifest.apply_delete("/src/main.rs");

// Rename a file
manifest.apply_rename("/old.rs", "/new.rs".to_string());

// Query
manifest.get("/src/main.rs");       // Option<&ManifestEntry>
manifest.exists("/src/main.rs");     // bool
manifest.list("/src/");              // Vec<&ManifestEntry> (prefix match)
manifest.len();                      // number of entries
```

### Implicit Parent Directories

When a file is written at a deep path like `/a/b/c.txt`, all parent directories (`/a`, `/a/b`) are automatically created as sentinel entries with `content_type: "inode/directory"` and `size_bytes: 0`. This mirrors `mkdir -p` behavior.

## Tree Operations

The `tree` module provides directory-level traversal over the flat manifest.

### list_directory

Lists the immediate children (files and subdirectories) of a directory:

```rust
use lago_fs::list_directory;

let entries = list_directory(&manifest, "/src");
// Returns: [Directory("util"), File("main.rs"), File("lib.rs")]
```

Returns `TreeEntry` values:

```rust
pub enum TreeEntry {
    File { name: String, entry: ManifestEntry },
    Directory { name: String },
}
```

Directories are detected by collapsing deeper paths to their first component. Directory sentinel entries (those with `content_type: "inode/directory"`) are reported as `Directory`, not `File`.

### walk

Recursively lists all files under a path, excluding directory sentinels:

```rust
use lago_fs::walk;

let files = walk(&manifest, "/src");
// Returns all ManifestEntry references under /src (recursive)
```

### parent_dirs

Extracts all parent directory paths for a given file path:

```rust
use lago_fs::parent_dirs;

parent_dirs("/a/b/c.txt");  // ["/a", "/a/b"]
parent_dirs("/file.txt");    // []
```

## Branching

Branches enable copy-on-write exploration of alternative agent strategies. Branching is done at the event level -- no data is duplicated.

### BranchInfo

```rust
pub struct BranchInfo {
    pub branch_id: BranchId,
    pub name: String,
    pub fork_point_seq: SeqNo,        // Sequence number where the branch forked
    pub head_seq: SeqNo,              // Current head sequence
    pub parent_branch: Option<BranchId>,
}
```

### BranchManager

```rust
let mut bm = BranchManager::new();

// Create the main branch
let main_id = bm.create_branch("main".to_string(), 0, None);

// Fork a feature branch at sequence 100
let feature_id = bm.create_branch(
    "experiment".to_string(),
    100,
    Some(main_id.clone()),
);

// Look up a branch
let info = bm.get_branch(&feature_id).unwrap();
assert_eq!(info.fork_point_seq, 100);

// List all branches
let branches = bm.list_branches();
```

### How Branching Works

Events 0..N on the parent branch are implicitly shared by all child branches. When a branch is created at `fork_point_seq = 100`, reading that branch's state means:

1. Read events 0..100 from the parent branch
2. Read events 101..head from the new branch

Each branch tracks its own head sequence independently via the `BRANCH_HEADS` table in the journal.

```
Session: "research-agent"
Branch: "main"
  seq 0: SessionCreated
  seq 1: Message { "Research X" }
  seq 2: ToolInvoke { web_search }
  seq 3: ToolResult { ... }
  seq 4: Message { "Found two approaches..." }
         |
         +-- Fork at seq 4 --> Branch "approach-a"
         |     seq 5: ToolInvoke { analyze, "approach A" }
         |     seq 6: ToolResult { ... }
         |
         +-- Fork at seq 4 --> Branch "approach-b"
               seq 5: ToolInvoke { analyze, "approach B" }
               seq 6: ToolResult { ... }
```

## Diffing

The `diff` function computes the difference between two manifest states:

```rust
use lago_fs::diff;

let changes = diff(&old_manifest, &new_manifest);

for change in &changes {
    match change {
        DiffEntry::Added { path, entry } => {
            println!("+ {path} ({} bytes)", entry.size_bytes);
        }
        DiffEntry::Removed { path, .. } => {
            println!("- {path}");
        }
        DiffEntry::Modified { path, old, new } => {
            println!("~ {path}: {} -> {}", old.blob_hash, new.blob_hash);
        }
    }
}
```

### DiffEntry

```rust
pub enum DiffEntry {
    Added { path: String, entry: ManifestEntry },
    Removed { path: String, entry: ManifestEntry },
    Modified { path: String, old: ManifestEntry, new: ManifestEntry },
}
```

The diff algorithm exploits the `BTreeMap` ordering: both manifests are iterated in lockstep, making the comparison O(n) in the total number of entries. Modification is detected by comparing `blob_hash` values -- if the hash is the same, the file is unchanged regardless of timestamp.

### Use Cases

- **Branch comparison**: Diff the manifest at branch fork point vs. current branch head
- **Audit**: What files changed between sequence 100 and 200?
- **Merge preview**: Before merging a branch, see what would change

## ManifestProjection

The `ManifestProjection` implements the `Projection` trait to build filesystem state from events:

```rust
use lago_fs::ManifestProjection;
use lago_core::Projection;

let mut proj = ManifestProjection::new();

// Replay events
for event in events {
    proj.on_event(&event)?;
}

// Access the resulting manifest
let manifest = proj.manifest();
let branches = proj.branch_manager();
```

### Events Handled

| Event | Action |
|-------|--------|
| `FileWrite` | Inserts/updates the file entry in the manifest |
| `FileDelete` | Removes the file entry from the manifest |
| `FileRename` | Moves the entry from old path to new path |
| `BranchCreated` | Registers the new branch in the branch manager |
| `BranchMerged` | Updates the source branch's head sequence |
| All others | Ignored (no-op) |

### Building a Manifest at Any Point in Time

To see the filesystem state at sequence N, replay only events 0..N:

```rust
let mut proj = ManifestProjection::new();
let query = EventQuery::new()
    .session(session_id)
    .branch(branch_id)
    .before(n + 1);  // exclusive upper bound

let events = journal.read(query).await?;
for event in &events {
    proj.on_event(event)?;
}

// proj.manifest() now reflects the filesystem at sequence N
```

### Branch-Specific Manifests

To see the filesystem on a specific branch, include the parent branch's events up to the fork point, then the branch's own events:

```rust
// 1. Events from parent branch up to fork point
let parent_events = journal.read(
    EventQuery::new()
        .session(session_id)
        .branch(parent_branch_id)
        .before(fork_point_seq + 1)
).await?;

// 2. Events on the feature branch after the fork
let branch_events = journal.read(
    EventQuery::new()
        .session(session_id)
        .branch(feature_branch_id)
).await?;

let mut proj = ManifestProjection::new();
for event in parent_events.iter().chain(branch_events.iter()) {
    proj.on_event(event)?;
}
```
