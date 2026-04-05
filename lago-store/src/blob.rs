use std::fs;
use std::path::{Path, PathBuf};

use lago_core::{BlobHash, LagoError, LagoResult};
use tracing::{debug, instrument, trace};

use crate::compress;
use crate::hash;

/// Content-addressed blob store backed by the local filesystem.
///
/// Blobs are stored compressed (zstd) under a git-like object layout:
/// `{root}/{first-2-chars}/{remaining-hash}.zst`
///
/// Deduplication is automatic — writing the same content twice is a no-op
/// because the content hash determines the storage path.
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    /// Open (or create) a blob store rooted at the given directory.
    pub fn open(path: impl AsRef<Path>) -> LagoResult<Self> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        debug!(path = %root.display(), "blob store opened");
        Ok(Self { root })
    }

    /// Return the root directory of the blob store.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Store data and return its content hash.
    ///
    /// If a blob with the same hash already exists on disk, the write is
    /// skipped (content-addressed deduplication).
    #[instrument(skip(self, data), fields(lago.blob_size = data.len()))]
    pub fn put(&self, data: &[u8]) -> LagoResult<BlobHash> {
        let hash = hash::hash_bytes(data);

        if self.exists(&hash) {
            trace!(hash = %hash, "blob already exists, skipping write");
            return Ok(hash);
        }

        let blob_path = self.blob_path(&hash);

        // Ensure the shard directory exists
        if let Some(parent) = blob_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let compressed = compress::compress(data)?;

        // Write atomically via a temp file to avoid partial writes on crash
        let tmp_path = blob_path.with_extension("zst.tmp");
        fs::write(&tmp_path, &compressed)?;
        fs::rename(&tmp_path, &blob_path)?;

        debug!(hash = %hash, size = data.len(), compressed = compressed.len(), "blob stored");
        Ok(hash)
    }

    /// Retrieve the decompressed contents of a blob by its hash.
    #[instrument(skip(self), fields(lago.blob_hash = %hash))]
    pub fn get(&self, hash: &BlobHash) -> LagoResult<Vec<u8>> {
        let blob_path = self.blob_path(hash);

        if !blob_path.exists() {
            return Err(LagoError::BlobNotFound(hash.to_string()));
        }

        let compressed = fs::read(&blob_path)?;
        let data = compress::decompress(&compressed)?;

        trace!(hash = %hash, size = data.len(), "blob retrieved");
        Ok(data)
    }

    /// Check whether a blob with the given hash exists on disk.
    pub fn exists(&self, hash: &BlobHash) -> bool {
        self.blob_path(hash).exists()
    }

    /// Delete a blob from disk. Returns an error if the blob does not exist.
    #[instrument(skip(self), fields(lago.blob_hash = %hash))]
    pub fn delete(&self, hash: &BlobHash) -> LagoResult<()> {
        let blob_path = self.blob_path(hash);

        if !blob_path.exists() {
            return Err(LagoError::BlobNotFound(hash.to_string()));
        }

        fs::remove_file(&blob_path)?;
        debug!(hash = %hash, "blob deleted");

        // Try to remove the shard directory if empty (best-effort)
        if let Some(parent) = blob_path.parent() {
            let _ = fs::remove_dir(parent);
        }

        Ok(())
    }

    // ---
    // Internal helpers

    /// Compute the on-disk path for a given blob hash.
    ///
    /// Layout: `{root}/{hash[0..2]}/{hash[2..]}.zst`
    fn blob_path(&self, hash: &BlobHash) -> PathBuf {
        let hex = hash.as_str();
        let (prefix, rest) = hex.split_at(2);
        self.root.join(prefix).join(format!("{rest}.zst"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, BlobStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::open(dir.path().join("blobs")).unwrap();
        (dir, store)
    }

    #[test]
    fn put_and_get_roundtrip() {
        let (_dir, store) = temp_store();
        let data = b"hello, lago blob store!";
        let hash = store.put(data).unwrap();
        let retrieved = store.get(&hash).unwrap();
        assert_eq!(retrieved, data);
    }

    #[test]
    fn put_is_idempotent() {
        let (_dir, store) = temp_store();
        let data = b"duplicate data";
        let hash1 = store.put(data).unwrap();
        let hash2 = store.put(data).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn exists_returns_true_for_stored_blob() {
        let (_dir, store) = temp_store();
        let hash = store.put(b"some data").unwrap();
        assert!(store.exists(&hash));
    }

    #[test]
    fn exists_returns_false_for_missing_blob() {
        let (_dir, store) = temp_store();
        let hash =
            BlobHash::from_hex("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
        assert!(!store.exists(&hash));
    }

    #[test]
    fn get_missing_blob_returns_error() {
        let (_dir, store) = temp_store();
        let hash =
            BlobHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000");
        let result = store.get(&hash);
        assert!(result.is_err());
    }

    #[test]
    fn delete_removes_blob() {
        let (_dir, store) = temp_store();
        let hash = store.put(b"to be deleted").unwrap();
        assert!(store.exists(&hash));
        store.delete(&hash).unwrap();
        assert!(!store.exists(&hash));
    }

    #[test]
    fn delete_missing_blob_returns_error() {
        let (_dir, store) = temp_store();
        let hash =
            BlobHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000");
        let result = store.delete(&hash);
        assert!(result.is_err());
    }

    #[test]
    fn blob_path_layout() {
        let (_dir, store) = temp_store();
        let hash = BlobHash::from_hex("abcdef1234567890");
        let path = store.blob_path(&hash);
        let path_str = path.to_string_lossy();
        assert!(path_str.contains("ab"));
        assert!(path_str.ends_with("cdef1234567890.zst"));
    }

    #[test]
    fn large_blob_roundtrip() {
        let (_dir, store) = temp_store();
        // 1 MB of repeated data — should compress well
        let data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
        let hash = store.put(&data).unwrap();
        let retrieved = store.get(&hash).unwrap();
        assert_eq!(retrieved, data);
    }
}
