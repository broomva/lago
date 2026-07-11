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
use lago_store::BlobBackend;

use crate::diff::{self, DiffEntry};
use crate::manifest::Manifest;
use crate::snapshot::{self, SnapshotLimits};

/// `content_type` marker for implicit parent-directory sentinel entries.
///
/// `Manifest::apply_write` materializes a zero-size sentinel for every parent
/// directory of a written path. The snapshot walk only ever yields regular
/// files, so these sentinels can only appear in a diff as orphans (e.g. the
/// last file in a subdir is deleted, leaving the dir sentinel `Removed`).
/// They must never be mapped to `FileWrite`/`FileDelete` payloads — a path
/// that was never a file must not produce a file event.
const DIRECTORY_SENTINEL: &str = "inode/directory";

/// True if a manifest entry is an implicit directory sentinel (not a real file).
fn is_directory_sentinel(entry: &lago_core::ManifestEntry) -> bool {
    entry.content_type.as_deref() == Some(DIRECTORY_SENTINEL)
}

/// Inline filesystem tracker producing event payloads on writes/deletes.
///
/// Thread-safe: the internal manifest is behind a `Mutex`.
///
/// Blob content is stored through a [`BlobBackend`] — `LocalBlobBackend` for
/// on-disk storage, or a remote backend (e.g. `arcan_lago::RemoteBlobBackend`)
/// when running against a remote Lago daemon — so file content stays durable
/// wherever the journal lives.
pub struct FsTracker {
    manifest: Mutex<Manifest>,
    blob_store: Arc<dyn BlobBackend>,
}

impl FsTracker {
    /// Create a new tracker seeded with an existing manifest state.
    pub fn new(manifest: Manifest, blob_store: Arc<dyn BlobBackend>) -> Self {
        Self {
            manifest: Mutex::new(manifest),
            blob_store,
        }
    }

    /// Create a tracker whose initial manifest is a *baseline snapshot* of
    /// `workspace_root`, taken WITHOUT emitting any events.
    ///
    /// This is the correct constructor when the tracker is attached to a live,
    /// already-populated workspace (e.g. `arcan serve` over the current
    /// directory). Seeding with an empty [`Manifest::new`] instead would make
    /// the first [`reconcile_bounded`](Self::reconcile_bounded) diff the entire
    /// workspace against nothing — emitting a spurious `FileWrite` for every
    /// pre-existing file. Baselining records that prior state up front, so
    /// reconcile only ever reports genuine post-baseline changes.
    ///
    /// The baseline uses the SAME bounded walk + prune rules as reconcile (via
    /// `snapshot_bounded` with the supplied `limits`). This is load-bearing:
    /// if the baseline saw a different file set than reconcile (e.g. a smaller
    /// `max_files`, or different pruning), the first reconcile would re-discover
    /// the divergence as phantom adds/removes. Pass the same `limits` the
    /// exec-path reconciler will use (see
    /// [`ReconcilingTool`](../../arcan_lago/struct.ReconcilingTool.html)).
    pub fn with_baseline(
        workspace_root: &Path,
        blob_store: Arc<dyn BlobBackend>,
        limits: SnapshotLimits,
    ) -> LagoResult<Self> {
        let baseline = snapshot::snapshot_bounded(
            workspace_root,
            &Manifest::new(),
            blob_store.as_ref(),
            limits,
        )?;
        Ok(Self {
            manifest: Mutex::new(baseline),
            blob_store,
        })
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
    ///
    /// Uses unbounded snapshot limits. The exec-path uses
    /// [`reconcile_bounded`](Self::reconcile_bounded) to cap the walk.
    ///
    /// ## Known limitations (tracked for follow-up)
    ///
    /// Reconciliation is best-effort observability. A few edge cases are
    /// knowingly deferred (ticketed separately):
    ///
    /// - **Same-size + same-second content edits** — CLOSED (BRO-1481). The
    ///   snapshot fast path (`snapshot.rs`) reuses a file's prior hash when its
    ///   size and mtime-in-seconds both match; because mtime has one-second
    ///   resolution, a same-length in-place edit landing in the same wall-clock
    ///   second as the recorded write once slipped through as "unchanged".
    ///   `snapshot_bounded` now re-hashes any file modified within
    ///   [`RACY_MTIME_WINDOW_SECS`](crate::snapshot::RACY_MTIME_WINDOW_SECS) of
    ///   "now", so a promptly-reconciled same-second edit is detected.
    /// - **Channel back-pressure on bursts.** Emitted payloads go through a
    ///   bounded mpsc; a single reconcile of a huge tree could in principle fill
    ///   it. In practice — with the workspace baselined at boot (see
    ///   [`with_baseline`](Self::with_baseline)) — a normal reconcile only
    ///   carries the handful of paths a single shell command touched, so the
    ///   channel is never stressed.
    pub fn reconcile(&self, workspace_root: &Path) -> LagoResult<Vec<EventPayload>> {
        self.reconcile_bounded(workspace_root, SnapshotLimits::unbounded())
    }

    /// Bounded reconciliation: like [`reconcile`](Self::reconcile) but caps the
    /// number of files scanned and the per-file size that is read + blob-stored.
    ///
    /// This is the exec-path safety net — after a shell command runs, the
    /// workspace is re-scanned (subject to `limits`), diffed against the tracked
    /// manifest, and every created/modified/deleted *file* is turned into a
    /// `FileWrite`/`FileDelete` payload, identical in shape to the inline
    /// `track_write`/`track_delete` events. The manifest is updated in place.
    ///
    /// ## Directory sentinels are never emitted
    ///
    /// `Manifest::apply_write` materializes `inode/directory` sentinel entries
    /// for parent dirs. The snapshot walk yields only regular files, so when a
    /// command deletes the last file under a previously-tracked subdir, the
    /// orphaned sentinel diffs as `Removed`. Those sentinel diffs are filtered
    /// out here so a directory never becomes a phantom `FileDelete` (and an
    /// added/modified sentinel never becomes a phantom `FileWrite`).
    ///
    /// ## Locking
    ///
    /// The O(n) walk + blob puts run WITHOUT holding the manifest lock (the
    /// snapshot is built against a cheap clone of the current manifest, used
    /// only as a hash-reuse hint). The lock is taken only to diff + swap.
    ///
    /// Race window: a concurrent FsPort `track_write` that lands after the walk
    /// observed that path's prior state but before the swap will be clobbered by
    /// the swap-to-disk-truth. Because the FsPort write path writes through to
    /// disk, the swapped-in snapshot still reflects on-disk truth; the only
    /// consequence is that the racing write's event may be re-emitted by the
    /// next reconcile (a duplicate observability event, never a lost on-disk
    /// write). Exec-path reconciles run serially after a single shell command,
    /// so this window is small and benign.
    pub fn reconcile_bounded(
        &self,
        workspace_root: &Path,
        limits: SnapshotLimits,
    ) -> LagoResult<Vec<EventPayload>> {
        // Snapshot the workspace WITHOUT holding the lock. Clone the current
        // manifest only as a hash-reuse hint for the walk; correctness of the
        // resulting snapshot does not depend on it (it is a full disk scan).
        let base = {
            let guard = self.manifest.lock().unwrap();
            guard.clone()
        };
        let new_manifest =
            snapshot::snapshot_bounded(workspace_root, &base, self.blob_store.as_ref(), limits)?;

        // Re-take the lock only to diff + swap.
        let diffs = {
            let mut manifest = self.manifest.lock().unwrap();
            let diffs = diff::diff(&manifest, &new_manifest);
            *manifest = new_manifest;
            diffs
        };

        let payloads = diffs
            .into_iter()
            // Drop directory-sentinel diffs: a sentinel is never a real file,
            // so it must not become a FileWrite/FileDelete payload.
            .filter(|d| match d {
                DiffEntry::Added { entry, .. }
                | DiffEntry::Removed { entry, .. }
                | DiffEntry::Modified { new: entry, .. } => !is_directory_sentinel(entry),
            })
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
    use lago_store::{BlobStore, LocalBlobBackend};
    use std::fs;

    fn setup() -> (tempfile::TempDir, Arc<LocalBlobBackend>, FsTracker) {
        let tmp = tempfile::tempdir().unwrap();
        let blob_store = Arc::new(LocalBlobBackend::new(Arc::new(
            BlobStore::open(tmp.path().join("blobs")).unwrap(),
        )));
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
        let initial =
            crate::snapshot::snapshot(&ws, &Manifest::new(), blob_store.as_ref()).unwrap();

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
    fn reconcile_bounded_skips_oversized_file() {
        let (tmp, blob_store, _) = setup();
        let ws = tmp.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        fs::write(ws.join("small.txt"), "ok").unwrap();
        fs::write(ws.join("huge.bin"), vec![7u8; 8192]).unwrap();

        let tracker = FsTracker::new(Manifest::new(), blob_store);
        let limits = SnapshotLimits {
            max_files: 10_000,
            max_file_bytes: 1024,
        };
        let payloads = tracker.reconcile_bounded(&ws, limits).unwrap();

        // small.txt is reconciled; huge.bin is skipped (over the size cap).
        assert!(payloads.iter().any(|p| matches!(
            p,
            EventPayload::FileWrite { path, .. } if path == "/small.txt"
        )));
        assert!(!payloads.iter().any(|p| matches!(
            p,
            EventPayload::FileWrite { path, .. } if path == "/huge.bin"
        )));
        assert!(tracker.manifest().exists("/small.txt"));
        assert!(!tracker.manifest().exists("/huge.bin"));
    }

    #[test]
    fn with_baseline_then_unchanged_reconcile_emits_zero_events() {
        // Must-fix #1: a tracker baselined against a populated dir must NOT
        // emit a spurious FileWrite for every pre-existing file on the first
        // reconcile. With no on-disk changes, reconcile emits nothing.
        let tmp = tempfile::tempdir().unwrap();
        let blob_store: Arc<dyn lago_store::BlobBackend> = Arc::new(LocalBlobBackend::new(
            Arc::new(BlobStore::open(tmp.path().join("blobs")).unwrap()),
        ));
        let ws = tmp.path().join("ws");
        fs::create_dir_all(ws.join("sub")).unwrap();
        fs::write(ws.join("a.txt"), "alpha").unwrap();
        fs::write(ws.join("sub/b.txt"), "beta").unwrap();

        let tracker = FsTracker::with_baseline(&ws, blob_store, SnapshotLimits::default()).unwrap();

        // Baseline already recorded both files — no events.
        assert!(tracker.manifest().exists("/a.txt"));
        assert!(tracker.manifest().exists("/sub/b.txt"));

        // First reconcile with nothing changed on disk → ZERO events.
        let payloads = tracker.reconcile(&ws).unwrap();
        assert!(
            payloads.is_empty(),
            "baselined tracker must emit no events when disk is unchanged, got {payloads:?}"
        );
    }

    #[test]
    fn deleting_last_file_in_subdir_emits_no_directory_delete() {
        // Must-fix #2: a directory sentinel orphaned by deleting the last file
        // under it must NOT become a phantom FileDelete.
        let tmp = tempfile::tempdir().unwrap();
        let blob_store: Arc<dyn lago_store::BlobBackend> = Arc::new(LocalBlobBackend::new(
            Arc::new(BlobStore::open(tmp.path().join("blobs")).unwrap()),
        ));
        let ws = tmp.path().join("ws");
        fs::create_dir_all(ws.join("sub")).unwrap();
        fs::write(ws.join("sub/a.txt"), "data").unwrap();

        // Baseline records /sub/a.txt (and the /sub sentinel via apply_write).
        let tracker = FsTracker::with_baseline(&ws, blob_store, SnapshotLimits::default()).unwrap();
        assert!(tracker.manifest().exists("/sub/a.txt"));
        assert!(
            tracker.manifest().exists("/sub"),
            "baseline should carry the /sub directory sentinel"
        );

        // Delete the only file, leaving /sub empty on disk.
        fs::remove_file(ws.join("sub/a.txt")).unwrap();

        let payloads = tracker.reconcile(&ws).unwrap();

        // Exactly ONE FileDelete, for the file — never for the /sub sentinel.
        let deletes: Vec<&String> = payloads
            .iter()
            .filter_map(|p| match p {
                EventPayload::FileDelete { path } => Some(path),
                _ => None,
            })
            .collect();
        assert_eq!(
            deletes,
            vec![&"/sub/a.txt".to_string()],
            "expected exactly one FileDelete for the file, none for /sub, got {payloads:?}"
        );
        assert!(
            !payloads
                .iter()
                .any(|p| matches!(p, EventPayload::FileDelete { path } if path == "/sub")),
            "the /sub directory sentinel must not produce a FileDelete"
        );
    }

    #[test]
    fn reconcile_detects_same_size_same_second_inplace_edit() {
        // BRO-1481 exec-path reproduction: a same-length in-place edit within the
        // same wall-clock second as the baselined write must still surface a
        // FileWrite payload on reconcile — and an unchanged re-reconcile must
        // stay silent (no over-emission). Both writes are pinned to one recent
        // second so the race is deterministic.
        let tmp = tempfile::tempdir().unwrap();
        let blob_store: Arc<dyn lago_store::BlobBackend> = Arc::new(LocalBlobBackend::new(
            Arc::new(BlobStore::open(tmp.path().join("blobs")).unwrap()),
        ));
        let ws = tmp.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        let file = ws.join("cfg.env");

        let t0 = std::time::SystemTime::now();
        fs::write(&file, "KEY=foo").unwrap(); // len 7
        set_test_mtime(&file, t0);

        // Baseline records the file at the recorded (recent) second.
        let tracker = FsTracker::with_baseline(&ws, blob_store, SnapshotLimits::default()).unwrap();

        // Same-length in-place edit, re-pinned to the SAME second.
        fs::write(&file, "KEY=bar").unwrap(); // len 7, changed content
        set_test_mtime(&file, t0);

        let payloads = tracker.reconcile(&ws).unwrap();
        assert!(
            payloads.iter().any(|p| matches!(
                p,
                EventPayload::FileWrite { path, .. } if path == "/cfg.env"
            )),
            "same-size/same-second in-place edit must emit a FileWrite, got {payloads:?}"
        );

        // Healthy no-op: nothing changed on disk since the swap → zero events,
        // even though the file's mtime is still recent (would be re-hashed).
        let quiet = tracker.reconcile(&ws).unwrap();
        assert!(
            quiet.is_empty(),
            "unchanged reconcile must emit nothing, got {quiet:?}"
        );
    }

    /// Pin a file's mtime to `t` without altering its content.
    fn set_test_mtime(path: &std::path::Path, t: std::time::SystemTime) {
        let f = fs::File::options().write(true).open(path).unwrap();
        f.set_modified(t).unwrap();
        f.sync_all().unwrap();
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
