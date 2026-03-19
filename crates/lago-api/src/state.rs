use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use lago_auth::AuthLayer;
use lago_core::Journal;
use lago_store::BlobStore;

/// Shared application state threaded through all axum handlers.
///
/// Wrapped in `Arc` so it can be cheaply cloned into every request.
pub struct AppState {
    /// Event journal (session + event persistence).
    pub journal: Arc<dyn Journal>,
    /// Content-addressed blob store.
    pub blob_store: Arc<BlobStore>,
    /// Root path for filesystem data.
    pub data_dir: PathBuf,
    /// Daemon startup time for uptime reporting.
    pub started_at: Instant,
    /// Auth layer for JWT-protected routes (None = auth disabled).
    pub auth: Option<Arc<AuthLayer>>,
}
