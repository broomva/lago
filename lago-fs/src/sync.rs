use std::fs;
use std::path::PathBuf;

use lago_core::event::{EventEnvelope, EventPayload};
use lago_core::{BranchId, LagoResult, Projection};
use lago_store::BlobStore;
use tracing::{debug, warn};

/// A projection that synchronizes a Lago manifest state to a real local filesystem.
///
/// `LakeFsSync` binds to a specific `BranchId`. When file operations occur
/// on that branch, it fetches the content from the `BlobStore` and writes it
/// to the corresponding `target_dir` on disk.
///
/// This implements the "Lakebase" architecture pattern where the virtual
/// event-sourced state is perfectly mirrored onto a local POSIX filesystem
/// for raw tool execution and app routing.
pub struct LakeFsSync {
    target_dir: PathBuf,
    blob_store: BlobStore,
    target_branch: BranchId,
}

impl LakeFsSync {
    /// Create a new filesystem synchronizer bound to a specific directory and branch.
    pub fn new(target_dir: PathBuf, blob_store: BlobStore, target_branch: BranchId) -> Self {
        Self {
            target_dir,
            blob_store,
            target_branch,
        }
    }

    /// Resolve a virtual manifest path to a local absolute path.
    fn resolve_path(&self, virtual_path: &str) -> PathBuf {
        let relative = virtual_path.trim_start_matches('/');
        self.target_dir.join(relative)
    }
}

impl Projection for LakeFsSync {
    fn on_event(&mut self, event: &EventEnvelope) -> LagoResult<()> {
        // We only actively sync events that belong to our checked-out branch.
        if event.branch_id != self.target_branch {
            return Ok(());
        }

        match &event.payload {
            EventPayload::FileWrite {
                path, blob_hash, ..
            } => {
                let fs_path = self.resolve_path(path);
                if let Some(parent) = fs_path.parent() {
                    let _ = fs::create_dir_all(parent);
                }

                let lago_hash = lago_core::BlobHash::from_hex(blob_hash.as_str());
                match self.blob_store.get(&lago_hash) {
                    Ok(data) => {
                        // In a robust implementation we might only write if the file
                        // differs or doesn't exist. For now, we overwrite.
                        let _ = fs::write(&fs_path, &data);
                        debug!(path = %path, "synced file write to disk");
                    }
                    Err(e) => {
                        warn!(path = %path, error = %e, "failed to get blob for sync");
                    }
                }
            }
            EventPayload::FileDelete { path } => {
                let fs_path = self.resolve_path(path);
                let _ = fs::remove_file(&fs_path);
                debug!(path = %path, "synced file delete to disk");
            }
            EventPayload::FileRename { old_path, new_path } => {
                let old_fs_path = self.resolve_path(old_path);
                let new_fs_path = self.resolve_path(new_path);
                if let Some(parent) = new_fs_path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                let _ = fs::rename(&old_fs_path, &new_fs_path);
                debug!(old = %old_path, new = %new_path, "synced file rename to disk");
            }
            _ => {}
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "lake_fs_sync"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lago_core::id::{EventId, SeqNo, SessionId};
    use std::collections::HashMap;

    fn make_envelope(seq: SeqNo, payload: EventPayload, branch: &BranchId) -> EventEnvelope {
        EventEnvelope {
            event_id: EventId::new(),
            session_id: SessionId::new(),
            branch_id: branch.clone(),
            run_id: None,
            seq,
            timestamp: 1000 + seq,
            parent_id: None,
            payload,
            metadata: HashMap::new(),
            schema_version: 1,
        }
    }

    #[test]
    fn syncs_writes_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let blobs_dir = dir.path().join("blobs");
        let target_dir = dir.path().join("workspace");
        fs::create_dir_all(&target_dir).unwrap();

        let blob_store = BlobStore::open(&blobs_dir).unwrap();
        let data = b"hello sync";
        let hash = blob_store.put(data).unwrap();

        let target_branch = BranchId::from_string("main");
        let mut sync = LakeFsSync::new(target_dir.clone(), blob_store, target_branch.clone());

        let event = make_envelope(
            1,
            EventPayload::FileWrite {
                path: "/docs/readme.txt".to_string(),
                blob_hash: hash.to_string().into(),
                size_bytes: data.len() as u64,
                content_type: None,
            },
            &target_branch,
        );

        sync.on_event(&event).unwrap();

        let expected_path = target_dir.join("docs/readme.txt");
        assert!(expected_path.exists());
        assert_eq!(fs::read(&expected_path).unwrap(), b"hello sync");
    }

    #[test]
    fn ignores_other_branches() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::open(dir.path().join("blobs")).unwrap();

        // Setup sync on "main"
        let branch_main = BranchId::from_string("main");
        let mut sync = LakeFsSync::new(dir.path().join("ws"), blob_store, branch_main);

        let branch_feature = BranchId::from_string("feature");
        let event = make_envelope(
            1,
            EventPayload::FileDelete {
                path: "/some.txt".to_string(),
            },
            &branch_feature, // <-- Different branch
        );

        // Should ignore and not crash/error
        sync.on_event(&event).unwrap();
    }
}
