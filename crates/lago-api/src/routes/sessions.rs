use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};

use lago_core::event::{EventEnvelope, EventPayload};
use lago_core::id::{BranchId, EventId, SessionId};
use lago_core::session::{Session, SessionConfig};

use crate::error::ApiError;
use crate::state::AppState;

// --- Session type classification

/// Known session type prefixes. A session name like `agent:my-agent` has type `agent`.
/// Sessions without a recognized prefix are classified as `default`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionType {
    /// User vault session (`vault:{user_id}`)
    Vault,
    /// Agent workspace session (`agent:{agent_id}`)
    Agent,
    /// Site-assets session (`site-assets:{scope}`)
    SiteAssets,
    /// Site-content session (`site-content:{scope}`)
    SiteContent,
    /// Any session without a recognized prefix
    Default,
}

impl SessionType {
    /// Derive the session type from a session name.
    pub fn from_name(name: &str) -> Self {
        if name.starts_with("vault:") {
            Self::Vault
        } else if name.starts_with("agent:") {
            Self::Agent
        } else if name.starts_with("site-assets:") {
            Self::SiteAssets
        } else if name.starts_with("site-content:") {
            Self::SiteContent
        } else {
            Self::Default
        }
    }

    /// Return the string representation used in query parameters.
    fn as_str(self) -> &'static str {
        match self {
            Self::Vault => "vault",
            Self::Agent => "agent",
            Self::SiteAssets => "site_assets",
            Self::SiteContent => "site_content",
            Self::Default => "default",
        }
    }

    /// Parse from a query-parameter string (case-insensitive).
    fn from_query(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "vault" => Some(Self::Vault),
            "agent" => Some(Self::Agent),
            "site_assets" | "site-assets" => Some(Self::SiteAssets),
            "site_content" | "site-content" => Some(Self::SiteContent),
            "default" => Some(Self::Default),
            _ => None,
        }
    }
}

impl std::fmt::Display for SessionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Validate that a session name with a reserved prefix is well-formed.
///
/// Rules:
/// - `agent:` sessions require a non-empty agent ID after the colon
/// - `vault:` sessions require a non-empty user ID after the colon
/// - `site-assets:` and `site-content:` require a non-empty scope after the colon
/// - Names without a recognized prefix are always valid
fn validate_session_name(name: &str) -> Result<SessionType, ApiError> {
    let session_type = SessionType::from_name(name);

    match session_type {
        SessionType::Agent => {
            let agent_id = name.strip_prefix("agent:").unwrap_or("");
            if agent_id.is_empty() {
                return Err(ApiError::BadRequest(
                    "agent: session requires a non-empty agent ID (e.g. agent:my-agent)".into(),
                ));
            }
        }
        SessionType::Vault => {
            let user_id = name.strip_prefix("vault:").unwrap_or("");
            if user_id.is_empty() {
                return Err(ApiError::BadRequest(
                    "vault: session requires a non-empty user ID (e.g. vault:user_123)".into(),
                ));
            }
        }
        SessionType::SiteAssets => {
            let scope = name.strip_prefix("site-assets:").unwrap_or("");
            if scope.is_empty() {
                return Err(ApiError::BadRequest(
                    "site-assets: session requires a non-empty scope (e.g. site-assets:public)"
                        .into(),
                ));
            }
        }
        SessionType::SiteContent => {
            let scope = name.strip_prefix("site-content:").unwrap_or("");
            if scope.is_empty() {
                return Err(ApiError::BadRequest(
                    "site-content: session requires a non-empty scope (e.g. site-content:public)"
                        .into(),
                ));
            }
        }
        SessionType::Default => {}
    }

    Ok(session_type)
}

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
    pub session_type: SessionType,
}

#[derive(Serialize, Deserialize)]
pub struct SessionResponse {
    pub session_id: String,
    pub name: String,
    pub model: String,
    pub created_at: u64,
    pub branches: Vec<String>,
    pub session_type: SessionType,
}

impl From<&Session> for SessionResponse {
    fn from(s: &Session) -> Self {
        Self {
            session_id: s.session_id.to_string(),
            name: s.config.name.clone(),
            model: s.config.model.clone(),
            created_at: s.created_at,
            branches: s.branches.iter().map(|b| b.to_string()).collect(),
            session_type: SessionType::from_name(&s.config.name),
        }
    }
}

/// Query parameters for `GET /v1/sessions`.
#[derive(Deserialize)]
pub struct ListSessionsQuery {
    /// Filter by session type (e.g. `?type=agent`, `?type=vault`).
    #[serde(rename = "type")]
    pub session_type: Option<String>,
}

// --- Handlers

/// POST /v1/sessions
pub async fn create_session(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateSessionRequest>,
) -> Result<(axum::http::StatusCode, Json<CreateSessionResponse>), ApiError> {
    // Validate the session name format
    let session_type = validate_session_name(&body.name)?;

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
        schema_version: 1,
    };

    state.journal.append(event).await?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(CreateSessionResponse {
            session_id: session_id.to_string(),
            branch_id: branch_id.to_string(),
            session_type,
        }),
    ))
}

/// GET /v1/sessions
///
/// Supports optional `?type=<session_type>` query parameter to filter sessions
/// by their type prefix (e.g. `?type=agent`, `?type=vault`, `?type=site_content`).
pub async fn list_sessions(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListSessionsQuery>,
) -> Result<Json<Vec<SessionResponse>>, ApiError> {
    let sessions = state.journal.list_sessions().await?;

    // Parse the type filter if provided
    let type_filter = match &query.session_type {
        Some(t) => {
            let st = SessionType::from_query(t).ok_or_else(|| {
                ApiError::BadRequest(format!(
                    "unknown session type: {t}. Valid types: vault, agent, site_assets, site_content, default"
                ))
            })?;
            Some(st)
        }
        None => None,
    };

    let responses: Vec<SessionResponse> = sessions
        .iter()
        .filter(|s| match type_filter {
            Some(t) => SessionType::from_name(&s.config.name) == t,
            None => true,
        })
        .map(SessionResponse::from)
        .collect();

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_type_from_name() {
        assert_eq!(SessionType::from_name("vault:user_123"), SessionType::Vault);
        assert_eq!(SessionType::from_name("agent:my-agent"), SessionType::Agent);
        assert_eq!(
            SessionType::from_name("site-assets:public"),
            SessionType::SiteAssets
        );
        assert_eq!(
            SessionType::from_name("site-content:public"),
            SessionType::SiteContent
        );
        assert_eq!(
            SessionType::from_name("my-custom-session"),
            SessionType::Default
        );
        assert_eq!(SessionType::from_name(""), SessionType::Default);
    }

    #[test]
    fn session_type_from_query() {
        assert_eq!(SessionType::from_query("vault"), Some(SessionType::Vault));
        assert_eq!(SessionType::from_query("agent"), Some(SessionType::Agent));
        assert_eq!(
            SessionType::from_query("site_assets"),
            Some(SessionType::SiteAssets)
        );
        assert_eq!(
            SessionType::from_query("site-assets"),
            Some(SessionType::SiteAssets)
        );
        assert_eq!(
            SessionType::from_query("site_content"),
            Some(SessionType::SiteContent)
        );
        assert_eq!(
            SessionType::from_query("site-content"),
            Some(SessionType::SiteContent)
        );
        assert_eq!(
            SessionType::from_query("default"),
            Some(SessionType::Default)
        );
        assert_eq!(SessionType::from_query("AGENT"), Some(SessionType::Agent));
        assert_eq!(SessionType::from_query("unknown"), None);
    }

    #[test]
    fn validate_session_name_valid() {
        assert_eq!(
            validate_session_name("agent:my-agent").unwrap(),
            SessionType::Agent
        );
        assert_eq!(
            validate_session_name("vault:user_123").unwrap(),
            SessionType::Vault
        );
        assert_eq!(
            validate_session_name("site-content:public").unwrap(),
            SessionType::SiteContent
        );
        assert_eq!(
            validate_session_name("site-assets:images").unwrap(),
            SessionType::SiteAssets
        );
        assert_eq!(
            validate_session_name("my-session").unwrap(),
            SessionType::Default
        );
        assert_eq!(validate_session_name("").unwrap(), SessionType::Default);
    }

    #[test]
    fn validate_session_name_empty_prefix() {
        assert!(validate_session_name("agent:").is_err());
        assert!(validate_session_name("vault:").is_err());
        assert!(validate_session_name("site-content:").is_err());
        assert!(validate_session_name("site-assets:").is_err());
    }

    #[test]
    fn session_type_display() {
        assert_eq!(SessionType::Vault.to_string(), "vault");
        assert_eq!(SessionType::Agent.to_string(), "agent");
        assert_eq!(SessionType::SiteAssets.to_string(), "site_assets");
        assert_eq!(SessionType::SiteContent.to_string(), "site_content");
        assert_eq!(SessionType::Default.to_string(), "default");
    }

    #[test]
    fn session_type_serde_roundtrip() {
        let json = serde_json::to_string(&SessionType::Agent).unwrap();
        assert_eq!(json, r#""agent""#);

        let parsed: SessionType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, SessionType::Agent);
    }

    #[test]
    fn create_session_response_includes_type() {
        let resp = CreateSessionResponse {
            session_id: "s1".into(),
            branch_id: "main".into(),
            session_type: SessionType::Agent,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["session_type"], "agent");
    }

    #[test]
    fn session_response_from_session() {
        let session = Session {
            session_id: SessionId::from_string("s1".to_string()),
            config: SessionConfig {
                name: "agent:test-bot".to_string(),
                model: "mock".to_string(),
                params: HashMap::new(),
            },
            created_at: 12345,
            branches: vec![BranchId::from_string("main".to_string())],
        };

        let resp = SessionResponse::from(&session);
        assert_eq!(resp.session_type, SessionType::Agent);
        assert_eq!(resp.name, "agent:test-bot");
    }
}
