use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Storage backend configuration for the blob store.
///
/// Supports local filesystem (default) and Cloudflare R2 (S3-compatible).
/// When using R2, an optional local cache provides read-through caching
/// for hot data.
///
/// # Configuration (lago.toml)
///
/// ```toml
/// # Local filesystem (default)
/// [storage]
/// backend = "fs"
///
/// # Cloudflare R2
/// [storage]
/// backend = "r2"
/// r2_account_id = "..."
/// r2_access_key_id = "..."
/// r2_secret_access_key = "..."
/// r2_bucket = "lago-blobs"
/// cache_dir = "/data/.lago/cache"
/// cache_max_size_bytes = 1073741824  # 1 GB
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "lowercase")]
pub enum StorageConfig {
    /// Local filesystem backend (default).
    Fs {
        /// Root directory for blob storage.
        /// Defaults to `{data_dir}/blobs` when `None`.
        #[serde(default)]
        path: Option<PathBuf>,
    },
    /// Cloudflare R2 backend (S3-compatible, zero egress fees).
    R2 {
        /// Cloudflare account ID.
        r2_account_id: String,
        /// R2 access key ID.
        r2_access_key_id: String,
        /// R2 secret access key.
        r2_secret_access_key: String,
        /// R2 bucket name.
        r2_bucket: String,
        /// Local cache directory for read-through caching.
        /// When set, blobs are cached locally on first read from R2.
        #[serde(default)]
        cache_dir: Option<PathBuf>,
        /// Maximum local cache size in bytes. Default: 1 GB.
        /// When exceeded, oldest cached blobs are evicted.
        #[serde(default = "default_cache_max_size")]
        cache_max_size_bytes: u64,
    },
}

fn default_cache_max_size() -> u64 {
    1_073_741_824 // 1 GB
}

impl Default for StorageConfig {
    fn default() -> Self {
        StorageConfig::Fs { path: None }
    }
}
