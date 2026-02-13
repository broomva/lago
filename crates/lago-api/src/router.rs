use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::routes;
use crate::state::AppState;

/// Build the complete axum Router with all routes nested under `/v1`.
///
/// Includes CORS middleware (permissive for development) and request tracing.
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
        // --- Files: GET, PUT, DELETE on the same path
        .route(
            "/sessions/{id}/files/{*path}",
            get(routes::files::read_file)
                .put(routes::files::write_file)
                .delete(routes::files::delete_file),
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

    Router::new()
        .route("/health", get(routes::health::health))
        .nest("/v1", v1)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
