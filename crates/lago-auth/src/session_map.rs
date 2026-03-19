//! Maps authenticated users to Lago sessions.
//!
//! Each user gets a dedicated Lago session named `vault:{user_id}`.
//! The mapping is cached in memory and created on first access.

use std::collections::HashMap;
use std::sync::Arc;

use lago_core::{Journal, Session, SessionConfig, SessionId};
use tokio::sync::RwLock;
use tracing::info;

/// Maps `user_id` → `SessionId` for vault sessions.
pub struct SessionMap {
    journal: Arc<dyn Journal>,
    cache: RwLock<HashMap<String, SessionId>>,
}

impl SessionMap {
    /// Create a new session map backed by the given journal.
    pub fn new(journal: Arc<dyn Journal>) -> Self {
        Self {
            journal,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Get an existing session or create a new one for the user.
    ///
    /// Sessions are named `vault:{user_id}` and cached in memory.
    pub async fn get_or_create(
        &self,
        user_id: &str,
        email: &str,
    ) -> Result<SessionId, lago_core::LagoError> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(session_id) = cache.get(user_id) {
                return Ok(session_id.clone());
            }
        }

        // Not cached — search existing sessions
        let vault_name = format!("vault:{user_id}");
        let sessions = self.journal.list_sessions().await?;

        for session in &sessions {
            if session.config.name == vault_name {
                let session_id = session.session_id.clone();
                let mut cache = self.cache.write().await;
                cache.insert(user_id.to_string(), session_id.clone());
                info!(user_id, session_id = %session_id, "mapped user to existing vault session");
                return Ok(session_id);
            }
        }

        // Not found — create a new session
        let session_id = SessionId::new();
        let branch_id = lago_core::BranchId::from_string("main".to_string());

        let session = Session {
            session_id: session_id.clone(),
            config: SessionConfig {
                name: vault_name,
                model: String::new(),
                params: {
                    let mut params = HashMap::new();
                    params.insert("email".to_string(), email.to_string());
                    params.insert("type".to_string(), "vault".to_string());
                    params
                },
            },
            created_at: lago_core::event::EventEnvelope::now_micros(),
            branches: vec![branch_id],
        };

        self.journal.put_session(session).await?;

        let mut cache = self.cache.write().await;
        cache.insert(user_id.to_string(), session_id.clone());
        info!(user_id, session_id = %session_id, "created new vault session");

        Ok(session_id)
    }

    /// Rebuild the cache from existing sessions (call on daemon startup).
    pub async fn rebuild(&self) -> Result<usize, lago_core::LagoError> {
        let sessions = self.journal.list_sessions().await?;
        let mut cache = self.cache.write().await;
        cache.clear();

        let mut count = 0;
        for session in &sessions {
            if let Some(user_id) = session.config.name.strip_prefix("vault:") {
                cache.insert(user_id.to_string(), session.session_id.clone());
                count += 1;
            }
        }

        info!(vault_sessions = count, "session map rebuilt");
        Ok(count)
    }
}
