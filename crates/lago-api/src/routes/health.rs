use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde_json::json;

use crate::state::AppState;

/// GET /health
pub async fn health(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let uptime_seconds = state.started_at.elapsed().as_secs();
    let otlp_configured = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok();
    Json(json!({
        "status": "ok",
        "service": "lago",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": uptime_seconds,
        "telemetry": {
            "sdk": "vigil",
            "otlp_configured": otlp_configured,
        },
    }))
}
