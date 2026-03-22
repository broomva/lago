use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::json;

use crate::state::AppState;

/// GET /health — Liveness check with subsystem status.
pub async fn health(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let uptime_seconds = state.started_at.elapsed().as_secs();
    let otlp_configured = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok();

    // Check journal by attempting to list sessions
    let journal_ok = state.journal.list_sessions().await.is_ok();
    // Check blob store root directory exists
    let blobs_ok = state.data_dir.join("blobs").is_dir();

    let auth_active = state.auth.is_some();
    let policy_rules = state.policy_engine.as_ref().map(|p| p.rules().len());
    let rbac_roles = if let Some(rbac) = &state.rbac_manager {
        Some(rbac.read().await.roles().len())
    } else {
        None
    };

    let overall = if journal_ok && blobs_ok {
        "ok"
    } else {
        "degraded"
    };

    Json(json!({
        "status": overall,
        "service": "lago",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": uptime_seconds,
        "subsystems": {
            "journal": if journal_ok { "ok" } else { "error" },
            "blob_store": if blobs_ok { "ok" } else { "error" },
            "auth": if auth_active { "active" } else { "disabled" },
            "policy": {
                "active": policy_rules.is_some(),
                "rules": policy_rules.unwrap_or(0),
                "roles": rbac_roles.unwrap_or(0),
            },
        },
        "telemetry": {
            "sdk": "vigil",
            "otlp_configured": otlp_configured,
        },
    }))
}

/// GET /health/ready — Readiness probe (503 during startup or degraded state).
pub async fn readiness(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let journal_ok = state.journal.list_sessions().await.is_ok();
    let blobs_ok = state.data_dir.join("blobs").is_dir();

    let ready = journal_ok && blobs_ok;
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(json!({
            "ready": ready,
            "checks": {
                "journal": journal_ok,
                "blob_store": blobs_ok,
            },
        })),
    )
}

/// GET /metrics — Prometheus text exposition format.
///
/// Renders all registered `metrics` crate counters, gauges, and histograms
/// via the installed `PrometheusHandle`. Also refreshes the `lago_active_sessions`
/// gauge with the current session count before rendering.
pub async fn prometheus_metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Refresh the active-sessions gauge before rendering.
    if let Ok(sessions) = state.journal.list_sessions().await {
        crate::metrics::set_active_sessions(sessions.len() as u64);
    }

    let handle = state.prometheus_handle.render();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        handle,
    )
}
