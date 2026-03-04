//! Inline filesystem change tracker for O(1) write notifications.
//!
//! [`FsTracker`] wraps a [`Manifest`] and a [`BlobStore`] to produce
//! event payloads on every write or delete — without scanning the workspace.
//! The [`reconcile`] method provides an O(n) safety-net path for catching
//! changes made outside of tracked writes (e.g. shell commands).

use std::path::Path;
use std::sync::{Arc, Mutex};

use lago_core::LagoResult;
use lago_core::event::EventPayload;
use lago_store::BlobStore;

use crate::diff::{self, DiffEntry};
use crate::manifest::Manifest;
use crate::snapshot;

/// Inline filesystem tracker producing event payloads on writes/deletes.
///
/// Thread-safe: the internal manifest is behind a `Mutex`.
pub struct FsTracker {
    manifest: Mutex<Manifest>,
    blob_store: Arc<BlobStore>,
}

impl FsTracker {
    /// Create a new tracker seeded with an existing manifest state.
    pub fn new(manifest: Manifest, blob_store: Arc<BlobStore>) -> Self {
        Self {
            manifest: Mutex::new(manifest),
            blob_store,
        }
    }

    /// O(1) track a file write. Stores the content in the blob store,
    /// updates the manifest, and returns a `FileWrite` event payload.
    pub fn track_write(
        &self,
        rel_path: &str,
        content: &[u8],
        content_type: Option<String>,
    ) -> LagoResult<EventPayload> {
        let blob_hash = self.blob_store.put(content)?;
        let size_bytes = content.len() as u64;
        let timestamp = now_micros();

        let mut manifest = self.manifest.lock().unwrap();
        manifest.apply_write(
            rel_path.to_string(),
            blob_hash.clone(),
            size_bytes,
            content_type.clone(),
            timestamp,
        );

        Ok(EventPayload::FileWrite {
            path: rel_path.to_string(),
            blob_hash: blob_hash.into(),
            size_bytes,
            content_type,
        })
    }

    /// O(1) track a file deletion. Updates the manifest and returns
    /// a `FileDelete` event payload.
    pub fn track_delete(&self, rel_path: &str) -> LagoResult<EventPayload> {
        let mut manifest = self.manifest.lock().unwrap();
        manifest.apply_delete(rel_path);

        Ok(EventPayload::FileDelete {
            path: rel_path.to_string(),
        })
    }

    /// O(n) reconciliation: snapshot the workspace, diff against the
    /// tracked manifest, update the manifest, and return event payloads
    /// for every detected change. This is the safety-net path for catching
    /// changes made outside of tracked writes.
    pub fn reconcile(&self, workspace_root: &Path) -> LagoResult<Vec<EventPayload>> {
        let mut manifest = self.manifest.lock().unwrap();
        let new_manifest = snapshot::snapshot(workspace_root, &manifest, &self.blob_store)?;
        let diffs = diff::diff(&manifest, &new_manifest);

        // Replace manifest with the fresh snapshot.
        *manifest = new_manifest;

        let payloads = diffs
            .into_iter()
            .map(|d| match d {
                DiffEntry::Added { path, entry }
                | DiffEntry::Modified {
                    path, new: entry, ..
                } => EventPayload::FileWrite {
                    path,
                    blob_hash: entry.blob_hash.into(),
                    size_bytes: entry.size_bytes,
                    content_type: entry.content_type,
                },
                DiffEntry::Removed { path, .. } => EventPayload::FileDelete { path },
            })
            .collect();

        Ok(payloads)
    }

    /// Clone the current manifest snapshot.
    pub fn manifest(&self) -> Manifest {
        self.manifest.lock().unwrap().clone()
    }
}

fn now_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use lago_core::BlobHash;
    use std::fs;

    fn setup() -> (tempfile::TempDir, Arc<BlobStore>, FsTracker) {
        let tmp = tempfile::tempdir().unwrap();
        let blob_store = Arc::new(BlobStore::open(tmp.path().join("blobs")).unwrap());
        let tracker = FsTracker::new(Manifest::new(), blob_store.clone());
        (tmp, blob_store, tracker)
    }

    #[test]
    fn track_write_produces_correct_event() {
        let (_tmp, blob_store, tracker) = setup();
        let payload = tracker
            .track_write("/src/main.rs", b"fn main() {}", Some("text/x-rust".into()))
            .unwrap();

        match &payload {
            EventPayload::FileWrite {
                path,
                blob_hash,
                size_bytes,
                content_type,
            } => {
                assert_eq!(path, "/src/main.rs");
                assert_eq!(*size_bytes, 12);
                assert_eq!(content_type.as_deref(), Some("text/x-rust"));
                // Verify blob was stored
                assert!(blob_store.exists(&BlobHash::from_hex(blob_hash.as_str())));
            }
            _ => panic!("expected FileWrite, got {payload:?}"),
        }
    }

    #[test]
    fn track_write_updates_manifest() {
        let (_tmp, _blob, tracker) = setup();
        tracker.track_write("/a.txt", b"hello", None).unwrap();

        let manifest = tracker.manifest();
        assert!(manifest.exists("/a.txt"));
        assert_eq!(manifest.get("/a.txt").unwrap().size_bytes, 5);
    }

    #[test]
    fn track_delete_produces_correct_event() {
        let (_tmp, _blob, tracker) = setup();
        // Write first, then delete
        tracker.track_write("/x.txt", b"data", None).unwrap();
        let payload = tracker.track_delete("/x.txt").unwrap();

        match &payload {
            EventPayload::FileDelete { path } => {
                assert_eq!(path, "/x.txt");
            }
            _ => panic!("expected FileDelete, got {payload:?}"),
        }

        // Manifest should no longer contain the entry
        assert!(!tracker.manifest().exists("/x.txt"));
    }

    #[test]
    fn reconcile_detects_additions() {
        let (tmp, blob_store, _) = setup();
        let ws = tmp.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        fs::write(ws.join("new.txt"), "content").unwrap();

        let tracker = FsTracker::new(Manifest::new(), blob_store);
        let payloads = tracker.reconcile(&ws).unwrap();

        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| matches!(
            p,
            EventPayload::FileWrite { path, .. } if path == "/new.txt"
        )));
    }

    #[test]
    fn reconcile_detects_deletions() {
        let (tmp, blob_store, _) = setup();
        let ws = tmp.path().join("ws");
        fs::create_dir_all(&ws).unwrap();

        // Seed the manifest with a file that doesn't exist on disk
        let mut manifest = Manifest::new();
        manifest.apply_write(
            "/gone.txt".into(),
            BlobHash::from_hex("dead"),
            4,
            None,
            1000,
        );

        let tracker = FsTracker::new(manifest, blob_store);
        let payloads = tracker.reconcile(&ws).unwrap();

        assert!(payloads.iter().any(|p| matches!(
            p,
            EventPayload::FileDelete { path } if path == "/gone.txt"
        )));
    }

    #[test]
    fn reconcile_detects_modifications() {
        let (tmp, blob_store, _) = setup();
        let ws = tmp.path().join("ws");
        fs::create_dir_all(&ws).unwrap();

        // Write a file, snapshot it, then change it.
        // Use different-length content so the snapshot's size-based fast path doesn't skip the hash.
        fs::write(ws.join("mod.txt"), "original").unwrap();
        let initial = crate::snapshot::snapshot(&ws, &Manifest::new(), &blob_store).unwrap();

        fs::write(
            ws.join("mod.txt"),
            "this content is much longer than original",
        )
        .unwrap();
        let tracker = FsTracker::new(initial, blob_store);
        let payloads = tracker.reconcile(&ws).unwrap();

        assert!(payloads.iter().any(|p| matches!(
            p,
            EventPayload::FileWrite { path, .. } if path == "/mod.txt"
        )));
    }

    #[test]
    fn empty_reconcile_returns_empty_vec() {
        let (tmp, blob_store, _) = setup();
        let ws = tmp.path().join("ws");
        fs::create_dir_all(&ws).unwrap();

        let tracker = FsTracker::new(Manifest::new(), blob_store);
        let payloads = tracker.reconcile(&ws).unwrap();
        assert!(payloads.is_empty());
    }

    #[test]
    fn concurrent_writes_do_not_panic() {
        let (_tmp, _blob, tracker) = setup();
        let tracker = Arc::new(tracker);

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let t = tracker.clone();
                std::thread::spawn(move || {
                    let path = format!("/file_{i}.txt");
                    let content = format!("content {i}");
                    t.track_write(&path, content.as_bytes(), None).unwrap();
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(tracker.manifest().len(), 10);
    }
}
