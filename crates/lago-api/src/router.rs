use std::sync::Arc;

use axum::Router;
use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::routes;
use crate::state::AppState;

/// Build the complete axum Router with all routes nested under `/v1`.
///
/// Includes CORS middleware (permissive for development) and request tracing.
/// When auth is configured, `/v1/memory/*` routes are protected by JWT middleware.
pub fn build_router(state: Arc<AppState>) -> Router {
    let v1 = Router::new()
        // --- Sessions: POST and GET on the same path must be combined
        .route(
            "/sessions",
            post(routes::sessions::create_session).get(routes::sessions::list_sessions),
        )
        .route("/sessions/{id}", get(routes::sessions::get_session))
        // --- Events (SSE)
        .route(
            "/sessions/{id}/events",
            get(routes::events::stream_events),
        )
        // --- Branches: POST and GET on the same path
        .route(
            "/sessions/{id}/branches",
            post(routes::branches::create_branch).get(routes::branches::list_branches),
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
        // --- Blobs: GET and PUT on the same path
        .route(
            "/blobs/{hash}",
            get(routes::blobs::get_blob).put(routes::blobs::put_blob),
        );

    let mut root = Router::new()
        .route("/health", get(routes::health::health))
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

    root.layer(
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any),
    )
    .layer(TraceLayer::new_for_http())
    .with_state(state)
}
