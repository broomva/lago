use crate::id::{BranchId, SessionId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents an agent session — the top-level unit of work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: SessionId,
    pub config: SessionConfig,
    pub created_at: u64,
    pub branches: Vec<BranchId>,
}

/// Configuration for a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub name: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub params: HashMap<String, String>,
}

impl SessionConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            model: String::new(),
            params: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_config_new() {
        let config = SessionConfig::new("test-session");
        assert_eq!(config.name, "test-session");
        assert_eq!(config.model, "");
        assert!(config.params.is_empty());
    }

    #[test]
    fn session_serde_roundtrip() {
        let session = Session {
            session_id: SessionId::from_string("SESS001"),
            config: SessionConfig {
                name: "my-session".to_string(),
                model: "gpt-4".to_string(),
                params: HashMap::from([("temp".to_string(), "0.7".to_string())]),
            },
            created_at: 1700000000,
            branches: vec![BranchId::from_string("main"), BranchId::from_string("dev")],
        };
        let json = serde_json::to_string(&session).unwrap();
        let back: Session = serde_json::from_str(&json).unwrap();
        assert_eq!(back.session_id.as_str(), "SESS001");
        assert_eq!(back.config.name, "my-session");
        assert_eq!(back.config.model, "gpt-4");
        assert_eq!(back.config.params["temp"], "0.7");
        assert_eq!(back.branches.len(), 2);
        assert_eq!(back.created_at, 1700000000);
    }
}
