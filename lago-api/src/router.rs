use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

/// Global body limit for file/blob uploads (512 MB).
/// Individual endpoints may enforce stricter limits at the application level.
const MAX_BODY_SIZE: usize = 512 * 1024 * 1024;

use crate::routes;
use crate::state::AppState;

/// Build the complete axum Router with all routes nested under `/v1`.
///
/// Includes CORS middleware (permissive for development) and request tracing.
/// When auth is configured, `/v1/memory/*` routes are protected by JWT middleware.
/// Public blob routes are always available without authentication.
pub fn build_router(state: Arc<AppState>) -> Router {
    // --- Policy middleware: evaluates write operations against the policy engine.
    // Applied to all v1 routes. Read operations pass through unconditionally.
    let policy_layer = if state.policy_engine.is_some() {
        Some(from_fn_with_state(
            state.clone(),
            crate::middleware::policy_middleware,
        ))
    } else {
        None
    };

    let mut v1 = Router::new()
        // --- Sessions: POST and GET on the same path must be combined
        .route(
            "/sessions",
            post(routes::sessions::create_session).get(routes::sessions::list_sessions),
        )
        .route(
            "/sessions/{id}",
            get(routes::sessions::get_session).put(routes::sessions::upsert_session),
        )
        // --- Events: SSE stream + write/read/head
        .route(
            "/sessions/{id}/events",
            get(routes::events::stream_events).post(routes::events::append_event),
        )
        .route(
            "/sessions/{id}/events/read",
            get(routes::events::read_events),
        )
        .route(
            "/sessions/{id}/events/head",
            get(routes::events::head_seq),
        )
        // --- Branches: POST and GET on the same path
        .route(
            "/sessions/{id}/branches",
            post(routes::branches::create_branch).get(routes::branches::list_branches),
        )
        // --- Branch merge
        .route(
            "/sessions/{id}/branches/{branch}/merge",
            post(routes::branches::merge_branch),
        )
        // --- Files: GET, PUT, DELETE, PATCH on the same path
        .route(
            "/sessions/{id}/files/{*path}",
            get(routes::files::read_file)
                .put(routes::files::write_file)
                .delete(routes::files::delete_file)
                .patch(routes::files::patch_file),
        )
        // --- Manifest
        .route(
            "/sessions/{id}/manifest",
            get(routes::files::get_manifest),
        )
        // --- Blobs: GET and PUT on the same path (authenticated)
        .route(
            "/blobs/{hash}",
            get(routes::blobs::get_blob).put(routes::blobs::put_blob),
        )
        // Note: public blob route is mounted separately below with rate limiting
        // --- Snapshots: POST and GET, plus manifest at snapshot point
        .route(
            "/sessions/{id}/snapshots",
            post(routes::snapshots::create_snapshot).get(routes::snapshots::list_snapshots),
        )
        .route(
            "/sessions/{id}/snapshots/{name}/manifest",
            get(routes::snapshots::get_snapshot_manifest),
        )
        // --- Diff: compare two refs within a session
        .route(
            "/sessions/{id}/diff",
            get(routes::diffs::get_diff),
        );

    // Apply policy enforcement layer when policy engine is loaded
    if let Some(layer) = policy_layer {
        v1 = v1.layer(layer);
    }

    // --- Public blob route: rate limited, no auth
    let mut public_blobs =
        Router::new().route("/public/blobs/{hash}", get(routes::blobs::get_public_blob));

    if let Some(ref limiter) = state.rate_limiter {
        public_blobs = public_blobs.layer(from_fn_with_state(
            limiter.clone(),
            crate::rate_limit::rate_limit_middleware,
        ));
    }

    // Merge public routes into v1
    v1 = v1.merge(public_blobs);

    let mut root = Router::new()
        .route("/health", get(routes::health::health))
        .route("/health/ready", get(routes::health::readiness))
        .route("/metrics", get(routes::health::prometheus_metrics))
        .nest("/v1", v1);

    // --- Memory routes (auth-protected when auth is configured)
    if let Some(auth) = &state.auth {
        let memory = Router::new()
            .route("/memory/manifest", get(routes::memory::get_manifest))
            .route(
                "/memory/files/{*path}",
                get(routes::memory::read_file)
                    .put(routes::memory::write_file)
                    .delete(routes::memory::delete_file),
            )
            .route("/memory/search", post(routes::memory::search))
            .route("/memory/traverse", post(routes::memory::traverse))
            .route("/memory/note/{name}", get(routes::memory::read_note))
            .layer(from_fn_with_state(auth.clone(), lago_auth::auth_middleware));

        root = root.nest("/v1", memory);
    }

    root.layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
        .layer(from_fn_with_state(
            state.clone(),
            crate::metrics::http_metrics_middleware,
        ))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
