use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};

use lago_core::event::{EventEnvelope, EventPayload};
use lago_core::id::{BranchId, EventId, SessionId};
use lago_core::session::{Session, SessionConfig};

use crate::error::ApiError;
use crate::state::AppState;

// --- Request / Response types

#[derive(Deserialize, Serialize)]
pub struct CreateSessionRequest {
    pub name: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub params: Option<HashMap<String, String>>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateSessionResponse {
    pub session_id: String,
    pub branch_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct SessionResponse {
    pub session_id: String,
    pub name: String,
    pub model: String,
    pub created_at: u64,
    pub branches: Vec<String>,
}

impl From<&Session> for SessionResponse {
    fn from(s: &Session) -> Self {
        Self {
            session_id: s.session_id.to_string(),
            name: s.config.name.clone(),
            model: s.config.model.clone(),
            created_at: s.created_at,
            branches: s.branches.iter().map(|b| b.to_string()).collect(),
        }
    }
}

// --- Handlers

/// POST /v1/sessions
pub async fn create_session(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateSessionRequest>,
) -> Result<(axum::http::StatusCode, Json<CreateSessionResponse>), ApiError> {
    let session_id = SessionId::new();
    let branch_id = BranchId::from_string("main");

    let config = SessionConfig {
        name: body.name.clone(),
        model: body.model.unwrap_or_default(),
        params: body.params.unwrap_or_default(),
    };

    let session = Session {
        session_id: session_id.clone(),
        config: config.clone(),
        created_at: EventEnvelope::now_micros(),
        branches: vec![branch_id.clone()],
    };

    state.journal.put_session(session).await?;

    // Emit a SessionCreated event
    let event = EventEnvelope {
        event_id: EventId::new(),
        session_id: session_id.clone(),
        branch_id: branch_id.clone(),
        run_id: None,
        seq: 0,
        timestamp: EventEnvelope::now_micros(),
        parent_id: None,
        payload: EventPayload::SessionCreated {
            name: body.name,
            config: serde_json::to_value(&config).unwrap_or_default(),
        },
        metadata: HashMap::new(),
    };

    state.journal.append(event).await?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(CreateSessionResponse {
            session_id: session_id.to_string(),
            branch_id: branch_id.to_string(),
        }),
    ))
}

/// GET /v1/sessions
pub async fn list_sessions(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<SessionResponse>>, ApiError> {
    let sessions = state.journal.list_sessions().await?;
    let responses: Vec<SessionResponse> = sessions.iter().map(SessionResponse::from).collect();
    Ok(Json(responses))
}

/// GET /v1/sessions/:id
pub async fn get_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<SessionResponse>, ApiError> {
    let session_id = SessionId::from_string(id.clone());
    let session = state
        .journal
        .get_session(&session_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("session not found: {id}")))?;
    Ok(Json(SessionResponse::from(&session)))
}
