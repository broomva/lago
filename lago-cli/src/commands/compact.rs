use std::collections::HashSet;
use std::path::{Path, PathBuf};

use lago_core::event::{EventPayload, SnapshotType};
use lago_core::id::*;
use lago_core::{EventEnvelope, EventQuery, Journal, Projection};
use lago_fs::ManifestProjection;
use lago_store::BlobStore;

use crate::db::open_journal;

/// Options for the `lago compact` command.
#[derive(Debug, Clone)]
pub struct CompactOptions {
    pub session_id: String,
    pub branch: String,
    pub quarantine_dir: Option<PathBuf>,
    pub dry_run: bool,
}

/// Execute the `lago compact` command.
///
/// Performs blob garbage collection by:
/// 1. Creating a snapshot at the current HEAD (recovery point)
/// 2. Building the current manifest to find active blob hashes
/// 3. Scanning the blob store for all blobs on disk
/// 4. Moving unreferenced blobs to a quarantine directory (soft delete)
pub async fn run(data_dir: &Path, opts: CompactOptions) -> Result<(), Box<dyn std::error::Error>> {
    let journal = open_journal(data_dir)?;
    let blob_store = BlobStore::open(data_dir.join("blobs"))?;

    let session_id = SessionId::from_string(&opts.session_id);
    let branch_id = BranchId::from_string(&opts.branch);

    // --- Step 1: Read all events for this session+branch
    let query = EventQuery::new()
        .session(session_id.clone())
        .branch(branch_id.clone());
    let events = journal.read(query).await?;
    let event_count = events.len();

    if events.is_empty() {
        println!(
            "No events found for session '{}' on branch '{}'.",
            opts.session_id, opts.branch
        );
        return Ok(());
    }

    // --- Step 2: Get current head seq
    let head_seq = journal.head_seq(&session_id, &branch_id).await?;

    println!("Compaction target:");
    println!("  session:  {}", opts.session_id);
    println!("  branch:   {}", opts.branch);
    println!("  head seq: {head_seq}");
    println!("  events:   {event_count}");
    println!();

    // --- Step 3: Build the current manifest (active blob hashes)
    let mut projection = ManifestProjection::new();
    for event in &events {
        projection.on_event(event)?;
    }

    let manifest = projection.manifest();
    let active_hashes: HashSet<String> = manifest
        .entries()
        .values()
        .filter(|entry| !entry.blob_hash.as_str().is_empty())
        .map(|entry| entry.blob_hash.as_str().to_string())
        .collect();

    // Also collect blob hashes referenced by snapshot events (data_hash)
    let mut referenced_hashes = active_hashes.clone();
    for event in &events {
        if let EventPayload::SnapshotCreated { data_hash, .. } = &event.payload {
            let hash_str = data_hash.as_str();
            if !hash_str.is_empty()
                && hash_str != "0000000000000000000000000000000000000000000000000000000000000000"
            {
                referenced_hashes.insert(hash_str.to_string());
            }
        }
        // Also collect blob hashes from observation/reflection/memory events
        if let EventPayload::ObservationAppended {
            observation_ref, ..
        } = &event.payload
        {
            referenced_hashes.insert(observation_ref.as_str().to_string());
        }
        if let EventPayload::ReflectionCompacted { summary_ref, .. } = &event.payload {
            referenced_hashes.insert(summary_ref.as_str().to_string());
        }
        if let EventPayload::MemoryProposed { entries_ref, .. } = &event.payload {
            referenced_hashes.insert(entries_ref.as_str().to_string());
        }
        if let EventPayload::MemoryCommitted { committed_ref, .. } = &event.payload {
            referenced_hashes.insert(committed_ref.as_str().to_string());
        }
    }

    println!("Manifest:");
    println!("  entries:         {}", manifest.len());
    println!("  active blobs:    {}", active_hashes.len());
    println!("  referenced blobs (total): {}", referenced_hashes.len());
    println!();

    // --- Step 4: Walk the blob store directory to find all blob hashes on disk
    let all_disk_hashes = walk_blob_store(blob_store.root())?;
    println!("Blob store:");
    println!("  blobs on disk:   {}", all_disk_hashes.len());

    // --- Step 5: Identify unreferenced blobs
    let unreferenced: Vec<&String> = all_disk_hashes
        .iter()
        .filter(|hash| !referenced_hashes.contains(*hash))
        .collect();

    println!("  unreferenced:    {}", unreferenced.len());
    println!();

    if unreferenced.is_empty() {
        println!("No unreferenced blobs found. Nothing to quarantine.");

        // Still create the snapshot as a compaction marker
        if !opts.dry_run {
            create_compaction_snapshot(&journal, &session_id, &branch_id, head_seq).await?;
            println!("Snapshot created at seq {head_seq}.");
        }

        return Ok(());
    }

    // --- Step 6: Quarantine unreferenced blobs
    let quarantine_base = opts
        .quarantine_dir
        .unwrap_or_else(|| data_dir.join("quarantine"));
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let quarantine_path = quarantine_base.join(timestamp.to_string());

    if opts.dry_run {
        println!(
            "[dry-run] Would quarantine {} blob(s) to:",
            unreferenced.len()
        );
        println!("  {}", quarantine_path.display());
        println!();
        for hash in &unreferenced {
            let blob_file = blob_path_from_hash(blob_store.root(), hash);
            println!("  [dry-run] {} -> quarantine", blob_file.display());
        }
        println!();
        println!("[dry-run] Would create snapshot at seq {head_seq}.");
    } else {
        std::fs::create_dir_all(&quarantine_path)?;

        let mut quarantined_count = 0u64;
        for hash in &unreferenced {
            let src = blob_path_from_hash(blob_store.root(), hash);
            if src.exists() {
                // Preserve the shard directory structure in quarantine
                let (prefix, rest) = hash.split_at(2);
                let dest_dir = quarantine_path.join(prefix);
                std::fs::create_dir_all(&dest_dir)?;
                let dest = dest_dir.join(format!("{rest}.zst"));

                std::fs::rename(&src, &dest)?;
                quarantined_count += 1;

                // Try to remove empty shard directory (best-effort)
                if let Some(parent) = src.parent() {
                    let _ = std::fs::remove_dir(parent);
                }
            }
        }

        println!("Quarantined {quarantined_count} blob(s) to:");
        println!("  {}", quarantine_path.display());

        // Create the recovery snapshot
        create_compaction_snapshot(&journal, &session_id, &branch_id, head_seq).await?;
        println!("Snapshot created at seq {head_seq}.");
    }

    println!();
    println!("Compaction complete.");

    Ok(())
}

/// Walk the blob store directory to collect all blob hashes on disk.
///
/// Blob layout: `{root}/{hash[0..2]}/{hash[2..]}.zst`
fn walk_blob_store(root: &Path) -> Result<HashSet<String>, Box<dyn std::error::Error>> {
    let mut hashes = HashSet::new();

    if !root.exists() {
        return Ok(hashes);
    }

    // Iterate over shard directories (2-char hex prefixes)
    let shard_entries = std::fs::read_dir(root)?;
    for shard_entry in shard_entries.flatten() {
        let shard_path = shard_entry.path();
        if !shard_path.is_dir() {
            continue;
        }

        let shard_name = shard_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        // Skip non-hex shard names (e.g. tmp files)
        if shard_name.len() != 2 || !shard_name.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }

        // Iterate over blob files within the shard
        let blob_entries = std::fs::read_dir(&shard_path)?;
        for blob_entry in blob_entries.flatten() {
            let blob_path = blob_entry.path();
            if !blob_path.is_file() {
                continue;
            }

            let file_name = blob_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            // Expected format: {hash_rest}.zst
            if let Some(rest) = file_name.strip_suffix(".zst") {
                let full_hash = format!("{shard_name}{rest}");
                hashes.insert(full_hash);
            }
        }
    }

    Ok(hashes)
}

/// Compute the on-disk path for a blob hash (mirrors BlobStore::blob_path).
fn blob_path_from_hash(root: &Path, hash: &str) -> PathBuf {
    let (prefix, rest) = hash.split_at(2);
    root.join(prefix).join(format!("{rest}.zst"))
}

/// Create a SnapshotCreated event as a compaction recovery point.
async fn create_compaction_snapshot(
    journal: &lago_journal::RedbJournal,
    session_id: &SessionId,
    branch_id: &BranchId,
    head_seq: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = EventEnvelope::now_micros();
    let snapshot_name = format!("compact-{}", now / 1_000_000);

    let envelope = EventEnvelope {
        event_id: EventId::default(),
        session_id: session_id.clone(),
        branch_id: branch_id.clone(),
        run_id: None,
        seq: 0, // Journal assigns real seq
        timestamp: now,
        parent_id: None,
        payload: EventPayload::SnapshotCreated {
            snapshot_id: SnapshotId::from_string(&snapshot_name).into(),
            snapshot_type: SnapshotType::Full,
            covers_through_seq: head_seq,
            data_hash: BlobHash::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
            .into(),
        },
        metadata: Default::default(),
        schema_version: 1,
    };

    journal.append(envelope).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walk_blob_store_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let hashes = walk_blob_store(dir.path()).unwrap();
        assert!(hashes.is_empty());
    }

    #[test]
    fn walk_blob_store_nonexistent_dir() {
        let hashes = walk_blob_store(Path::new("/nonexistent/path")).unwrap();
        assert!(hashes.is_empty());
    }

    #[test]
    fn walk_blob_store_finds_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Create shard directory and a blob file
        let shard = root.join("ab");
        std::fs::create_dir_all(&shard).unwrap();
        std::fs::write(shard.join("cdef0123456789.zst"), b"data").unwrap();

        // Create another shard
        let shard2 = root.join("ff");
        std::fs::create_dir_all(&shard2).unwrap();
        std::fs::write(shard2.join("0011223344.zst"), b"data2").unwrap();

        let hashes = walk_blob_store(root).unwrap();
        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains("abcdef0123456789"));
        assert!(hashes.contains("ff0011223344"));
    }

    #[test]
    fn walk_blob_store_ignores_non_zst() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let shard = root.join("ab");
        std::fs::create_dir_all(&shard).unwrap();
        std::fs::write(shard.join("cdef.zst"), b"valid").unwrap();
        std::fs::write(shard.join("cdef.tmp"), b"ignored").unwrap();

        let hashes = walk_blob_store(root).unwrap();
        assert_eq!(hashes.len(), 1);
        assert!(hashes.contains("abcdef"));
    }

    #[test]
    fn walk_blob_store_ignores_non_hex_shards() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Valid shard
        let shard = root.join("ab");
        std::fs::create_dir_all(&shard).unwrap();
        std::fs::write(shard.join("cd.zst"), b"data").unwrap();

        // Invalid shard name (not hex)
        let bad_shard = root.join("zz");
        std::fs::create_dir_all(&bad_shard).unwrap();
        std::fs::write(bad_shard.join("00.zst"), b"ignored").unwrap();

        // Shard name too long
        let long_shard = root.join("abc");
        std::fs::create_dir_all(&long_shard).unwrap();
        std::fs::write(long_shard.join("00.zst"), b"ignored").unwrap();

        let hashes = walk_blob_store(root).unwrap();
        assert_eq!(hashes.len(), 1);
        assert!(hashes.contains("abcd"));
    }

    #[test]
    fn blob_path_from_hash_layout() {
        let root = Path::new("/data/blobs");
        let path = blob_path_from_hash(root, "abcdef0123456789");
        assert_eq!(path, PathBuf::from("/data/blobs/ab/cdef0123456789.zst"));
    }
}
