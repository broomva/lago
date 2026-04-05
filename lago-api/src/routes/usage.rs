//! Usage metering API endpoints.
//!
//! - `GET /v1/sessions/{id}/usage` — per-session usage with optional time range
//! - `GET /v1/usage/summary` — admin overview across all sessions

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};

use lago_journal::usage::{UsageDimension, UsageRecord};
use lago_journal::RedbJournal;

use crate::error::ApiError;
use crate::state::AppState;

// ─── Query parameters ────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UsageQuery {
    /// Start of time range (hourly bucket, Unix seconds). Defaults to 0.
    pub from: Option<u64>,
    /// End of time range (hourly bucket, Unix seconds). Defaults to u64::MAX.
    pub to: Option<u64>,
    /// Filter by dimension name (events, storage_bytes, api_calls, egress_bytes).
    pub dimension: Option<UsageDimension>,
}

// ─── Response types ──────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct UsageResponse {
    pub session_id: String,
    pub records: Vec<UsageRecordResponse>,
}

#[derive(Serialize)]
pub struct UsageRecordResponse {
    pub dimension: UsageDimension,
    pub period: u64,
    pub count: u64,
}

impl From<&UsageRecord> for UsageRecordResponse {
    fn from(r: &UsageRecord) -> Self {
        Self {
            dimension: r.dimension,
            period: r.period,
            count: r.count,
        }
    }
}

#[derive(Serialize)]
pub struct UsageSummaryResponse {
    pub records: Vec<UsageSummaryEntry>,
}

#[derive(Serialize)]
pub struct UsageSummaryEntry {
    pub session_id: String,
    pub dimension: UsageDimension,
    pub total: u64,
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// GET /v1/sessions/{id}/usage
///
/// Returns per-session usage counters, optionally filtered by time range
/// and dimension.
pub async fn get_session_usage(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<UsageQuery>,
) -> Result<Json<UsageResponse>, ApiError> {
    let from = query.from.unwrap_or(0);
    let to = query.to.unwrap_or(u64::MAX);

    let journal = get_redb_journal(&state)?;
    let records = journal
        .query_session_usage(id.clone(), query.dimension, from, to)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(UsageResponse {
        session_id: id,
        records: records.iter().map(UsageRecordResponse::from).collect(),
    }))
}

/// GET /v1/usage/summary
///
/// Returns aggregated usage across all sessions, grouped by session + dimension.
pub async fn get_usage_summary(
    State(state): State<Arc<AppState>>,
    Query(query): Query<UsageQuery>,
) -> Result<Json<UsageSummaryResponse>, ApiError> {
    let from = query.from.unwrap_or(0);
    let to = query.to.unwrap_or(u64::MAX);

    let journal = get_redb_journal(&state)?;
    let records = journal
        .query_usage_summary(from, to)
        .await
        .map_err(ApiError::from)?;

    let entries = records
        .iter()
        .map(|r| UsageSummaryEntry {
            session_id: r.session_id.as_str().to_string(),
            dimension: r.dimension,
            total: r.count,
        })
        .collect();

    Ok(Json(UsageSummaryResponse { records: entries }))
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Downcast the journal to RedbJournal for usage queries.
fn get_redb_journal(state: &AppState) -> Result<&RedbJournal, ApiError> {
    state
        .journal
        .as_any()
        .downcast_ref::<RedbJournal>()
        .ok_or_else(|| {
            ApiError::Internal("usage metering requires RedbJournal backend".to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_record_response_from() {
        use lago_core::SessionId;
        let record = UsageRecord {
            session_id: SessionId::from_string("S1"),
            dimension: UsageDimension::Events,
            period: 3600,
            count: 42,
        };
        let resp = UsageRecordResponse::from(&record);
        assert_eq!(resp.count, 42);
        assert_eq!(resp.period, 3600);
    }
}
