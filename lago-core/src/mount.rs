use crate::error::LagoResult;
use crate::id::BlobHash;
use serde::{Deserialize, Serialize};

/// A single entry in the filesystem manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub path: String,
    pub blob_hash: BlobHash,
    pub size_bytes: u64,
    pub content_type: Option<String>,
    pub updated_at: u64,
}

/// File stat information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileStat {
    pub path: String,
    pub size_bytes: u64,
    pub content_type: Option<String>,
    pub updated_at: u64,
    pub blob_hash: BlobHash,
}

/// Virtual filesystem trait backed by a manifest + blob store.
#[allow(async_fn_in_trait)]
pub trait Mount: Send + Sync {
    /// Read file contents by path.
    async fn read(&self, path: &str) -> LagoResult<Vec<u8>>;

    /// Write file contents, returning the blob hash.
    async fn write(&self, path: &str, data: &[u8]) -> LagoResult<BlobHash>;

    /// Delete a file by path.
    async fn delete(&self, path: &str) -> LagoResult<()>;

    /// List files under a directory path.
    async fn list(&self, path: &str) -> LagoResult<Vec<ManifestEntry>>;

    /// Check if a file exists.
    async fn exists(&self, path: &str) -> LagoResult<bool>;

    /// Get file metadata.
    async fn stat(&self, path: &str) -> LagoResult<Option<FileStat>>;
}
