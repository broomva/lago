//! Content-addressed blob storage abstraction.
//!
//! [`BlobBackend`] decouples blob *content* storage from its callers
//! ([`crate::BlobStore`] is the local reference implementation;
//! `arcan_lago::RemoteBlobBackend` talks to a remote `lagod` over HTTP).
//! This lets arcan keep blob content durable end-to-end when running against
//! a remote Lago daemon (`LAGO_URL` set) instead of leaving content stranded
//! on local container disk while only the event journal goes remote.
//!
//! # Why this trait is synchronous
//!
//! The sole hot consumer — [`crate::BlobStore::put`] via `lago_fs::FsTracker::track_write`
//! — is reached through an entirely **synchronous** call chain: the agent's
//! tool harness invokes `aios_protocol::tool::Tool::execute` (a sync `fn`),
//! which delegates to `FsPort::write` (sync), which calls `track_write`
//! (sync). There is no `.await` available at the blob `put` call site, and
//! turning the trait async would force that whole chain — and the stable
//! `Tool`/`FsPort` contracts — to become async, a refactor well outside this
//! abstraction's scope.
//!
//! Keeping the trait synchronous makes the local path zero-cost and
//! byte-identical to calling [`crate::BlobStore`] directly, and confines the
//! inherently-async remote HTTP work (reqwest) entirely inside the remote
//! implementation, which bridges async→sync internally.
//!
//! This is a deliberately lago-native abstraction (operating in
//! [`BlobHash`] / [`LagoResult`] / `&[u8]` terms). It is distinct from the
//! kernel-contract `aios_protocol::ports::BlobStorePort`, which is async and
//! uses the kernel's own `BlobHash`/`bytes::Bytes` types — that port serves
//! the `life-kernel-facade` cluster and is not what the lago filesystem
//! tracker consumes.

use lago_core::{BlobHash, LagoResult};

/// Storage backend for content-addressed blobs.
///
/// Implementations store opaque byte payloads keyed by their content hash
/// (SHA-256), providing automatic deduplication: writing identical content
/// twice yields the same [`BlobHash`] and is a storage no-op.
///
/// The trait is object-safe so callers can hold `Arc<dyn BlobBackend>` and
/// swap a local store for a remote one at runtime.
pub trait BlobBackend: Send + Sync {
    /// Store `data` and return its content hash.
    ///
    /// Implementations compute the hash from the content, so callers always
    /// receive a stable [`BlobHash`] regardless of where the bytes land.
    /// Storing content that already exists is a no-op (content-addressed
    /// deduplication).
    fn put(&self, data: &[u8]) -> LagoResult<BlobHash>;

    /// Retrieve the contents of a blob by its hash.
    ///
    /// Returns [`lago_core::LagoError::BlobNotFound`] if no blob with the
    /// given hash exists.
    fn get(&self, hash: &BlobHash) -> LagoResult<Vec<u8>>;

    /// Check whether a blob with the given hash exists.
    fn exists(&self, hash: &BlobHash) -> bool;
}

/// Local filesystem [`BlobBackend`] — a thin, behavior-identical wrapper over
/// [`crate::BlobStore`].
///
/// Every method delegates directly to the underlying store, so blobs are
/// written to the exact same on-disk layout, at the exact same hashes, as
/// using [`crate::BlobStore`] directly.
pub struct LocalBlobBackend {
    store: std::sync::Arc<crate::BlobStore>,
}

impl LocalBlobBackend {
    /// Wrap an existing [`crate::BlobStore`] as a [`BlobBackend`].
    pub fn new(store: std::sync::Arc<crate::BlobStore>) -> Self {
        Self { store }
    }

    /// Borrow the underlying store (e.g. for code paths that still need the
    /// concrete local API such as `lago_fs::snapshot`).
    pub fn store(&self) -> &std::sync::Arc<crate::BlobStore> {
        &self.store
    }
}

impl BlobBackend for LocalBlobBackend {
    fn put(&self, data: &[u8]) -> LagoResult<BlobHash> {
        self.store.put(data)
    }

    fn get(&self, hash: &BlobHash) -> LagoResult<Vec<u8>> {
        self.store.get(hash)
    }

    fn exists(&self, hash: &BlobHash) -> bool {
        self.store.exists(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BlobStore;
    use std::sync::Arc;

    fn temp_backend() -> (tempfile::TempDir, LocalBlobBackend) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(BlobStore::open(dir.path().join("blobs")).unwrap());
        (dir, LocalBlobBackend::new(store))
    }

    #[test]
    fn local_backend_roundtrips() {
        let (_dir, backend) = temp_backend();
        let data = b"hello via the backend trait";
        let hash = backend.put(data).unwrap();
        assert_eq!(backend.get(&hash).unwrap(), data);
        assert!(backend.exists(&hash));
    }

    #[test]
    fn local_backend_hash_matches_raw_blobstore() {
        // The local backend must produce byte-identical hashes to calling
        // BlobStore directly — same content, same hash.
        let dir = tempfile::tempdir().unwrap();
        let raw = BlobStore::open(dir.path().join("raw")).unwrap();
        let store = Arc::new(BlobStore::open(dir.path().join("backed")).unwrap());
        let backend = LocalBlobBackend::new(store);

        let data = b"identical content yields identical hash";
        let raw_hash = raw.put(data).unwrap();
        let backend_hash = backend.put(data).unwrap();
        assert_eq!(raw_hash, backend_hash);
    }

    #[test]
    fn local_backend_missing_is_not_found() {
        let (_dir, backend) = temp_backend();
        let hash =
            BlobHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000");
        assert!(!backend.exists(&hash));
        let err = backend.get(&hash).unwrap_err();
        assert!(matches!(err, lago_core::LagoError::BlobNotFound(_)));
    }

    /// Proves the trait is object-safe: a single `Arc<dyn BlobBackend>` can be
    /// held and every method dispatched dynamically.
    #[test]
    fn local_backend_is_dyn_compatible() {
        let (_dir, backend) = temp_backend();
        let dynamic: Arc<dyn BlobBackend> = Arc::new(backend);
        let hash = dynamic.put(b"dyn dispatch").unwrap();
        assert!(dynamic.exists(&hash));
        assert_eq!(dynamic.get(&hash).unwrap(), b"dyn dispatch");
    }
}
