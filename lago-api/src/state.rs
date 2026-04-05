use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use lago_auth::AuthLayer;
use lago_core::{Journal, ManifestEntry};
use lago_policy::{HookRunner, PolicyEngine, RbacManager};
use lago_store::BlobStore;
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::sync::RwLock;

/// Cached manifest entry with expiration timestamp.
pub struct CachedManifest {
    pub entries: Vec<ManifestEntry>,
    pub cached_at: Instant,
}

/// Default manifest cache TTL: 60 seconds.
pub const MANIFEST_CACHE_TTL_SECS: u64 = 60;

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
    /// Rule-based policy engine for tool governance (None = no enforcement).
    pub policy_engine: Option<Arc<PolicyEngine>>,
    /// RBAC manager for session-to-role assignments (None = no RBAC).
    /// Wrapped in RwLock to support runtime role assignments.
    pub rbac_manager: Option<Arc<RwLock<RbacManager>>>,
    /// Hook runner for pre/post operation hooks (None = no hooks).
    pub hook_runner: Option<Arc<HookRunner>>,
    /// Rate limiter for public endpoints (None = no rate limiting).
    pub rate_limiter: Option<Arc<crate::rate_limit::RateLimiter>>,
    /// Prometheus metrics handle for rendering the `/metrics` endpoint.
    pub prometheus_handle: PrometheusHandle,
    /// In-memory manifest cache keyed by (session_id, branch_id).
    /// Avoids replaying all journal events on every file/manifest request.
    pub manifest_cache: RwLock<HashMap<(String, String), CachedManifest>>,
}
