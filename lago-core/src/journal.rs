use crate::error::LagoResult;
use crate::event::EventEnvelope;
use crate::id::{BranchId, EventId, SeqNo, SessionId};
use crate::session::Session;
use futures::Stream;
use std::pin::Pin;

/// Query parameters for reading events.
#[derive(Debug, Clone, Default)]
pub struct EventQuery {
    pub session_id: Option<SessionId>,
    pub branch_id: Option<BranchId>,
    pub after_seq: Option<SeqNo>,
    pub before_seq: Option<SeqNo>,
    pub limit: Option<usize>,
    /// Filter events by metadata key-value pairs (all must match).
    pub metadata_filters: Option<Vec<(String, String)>>,
    /// Filter by event kind discriminant name (e.g. "HiveArtifactShared").
    pub kind_filter: Option<Vec<String>>,
}

impl EventQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn session(mut self, id: SessionId) -> Self {
        self.session_id = Some(id);
        self
    }

    pub fn branch(mut self, id: BranchId) -> Self {
        self.branch_id = Some(id);
        self
    }

    pub fn after(mut self, seq: SeqNo) -> Self {
        self.after_seq = Some(seq);
        self
    }

    pub fn before(mut self, seq: SeqNo) -> Self {
        self.before_seq = Some(seq);
        self
    }

    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    /// Add a metadata key-value filter. All metadata filters must match.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata_filters
            .get_or_insert_with(Vec::new)
            .push((key.into(), value.into()));
        self
    }

    /// Add a kind filter. Events must match any of the specified kind names.
    pub fn with_kind(mut self, kind_name: impl Into<String>) -> Self {
        self.kind_filter
            .get_or_insert_with(Vec::new)
            .push(kind_name.into());
        self
    }
}

impl EventQuery {
    /// Check if an event envelope matches the metadata and kind filters.
    /// Used for post-deserialization filtering in journal implementations.
    pub fn matches_filters(&self, envelope: &EventEnvelope) -> bool {
        // Check metadata filters — all must match
        if let Some(ref filters) = self.metadata_filters {
            for (key, value) in filters {
                match envelope.metadata.get(key) {
                    Some(v) if v == value => {}
                    _ => return false,
                }
            }
        }

        // Check kind filter — event must match any specified kind
        if let Some(ref kinds) = self.kind_filter {
            let event_json = serde_json::to_value(&envelope.payload).ok();
            let event_type = event_json
                .as_ref()
                .and_then(|v| v.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !kinds.iter().any(|k| k == event_type) {
                return false;
            }
        }

        true
    }
}

/// Event stream type alias.
pub type EventStream = Pin<Box<dyn Stream<Item = LagoResult<EventEnvelope>> + Send>>;

/// Boxed future type alias for dyn-compatible async trait methods.
type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// The primary trait for event persistence.
///
/// Uses boxed futures for dyn-compatibility (`Arc<dyn Journal>`).
pub trait Journal: Send + Sync {
    /// Append a single event. Returns the assigned sequence number.
    fn append(&self, event: EventEnvelope) -> BoxFuture<'_, LagoResult<SeqNo>>;

    /// Append a batch of events atomically. Returns the last assigned sequence number.
    fn append_batch(&self, events: Vec<EventEnvelope>) -> BoxFuture<'_, LagoResult<SeqNo>>;

    /// Read events matching a query.
    fn read(&self, query: EventQuery) -> BoxFuture<'_, LagoResult<Vec<EventEnvelope>>>;

    /// Look up a single event by ID.
    fn get_event(&self, event_id: &EventId) -> BoxFuture<'_, LagoResult<Option<EventEnvelope>>>;

    /// Get the current head sequence number for a session+branch.
    fn head_seq(
        &self,
        session_id: &SessionId,
        branch_id: &BranchId,
    ) -> BoxFuture<'_, LagoResult<SeqNo>>;

    /// Create a tailing stream of events.
    fn stream(
        &self,
        session_id: SessionId,
        branch_id: BranchId,
        after_seq: SeqNo,
    ) -> BoxFuture<'_, LagoResult<EventStream>>;

    /// Create or update a session.
    fn put_session(&self, session: Session) -> BoxFuture<'_, LagoResult<()>>;

    /// Get a session by ID.
    fn get_session(&self, session_id: &SessionId) -> BoxFuture<'_, LagoResult<Option<Session>>>;

    /// List all sessions.
    fn list_sessions(&self) -> BoxFuture<'_, LagoResult<Vec<Session>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_query_default_is_empty() {
        let q = EventQuery::new();
        assert!(q.session_id.is_none());
        assert!(q.branch_id.is_none());
        assert!(q.after_seq.is_none());
        assert!(q.before_seq.is_none());
        assert!(q.limit.is_none());
    }

    #[test]
    fn event_query_builder_chain() {
        let q = EventQuery::new()
            .session(SessionId::from_string("SESS001"))
            .branch(BranchId::from_string("main"))
            .after(10)
            .before(100)
            .limit(50);

        assert_eq!(q.session_id.as_ref().unwrap().as_str(), "SESS001");
        assert_eq!(q.branch_id.as_ref().unwrap().as_str(), "main");
        assert_eq!(q.after_seq, Some(10));
        assert_eq!(q.before_seq, Some(100));
        assert_eq!(q.limit, Some(50));
    }

    #[test]
    fn event_query_partial_builder() {
        let q = EventQuery::new()
            .session(SessionId::from_string("S1"))
            .limit(5);
        assert!(q.session_id.is_some());
        assert!(q.branch_id.is_none());
        assert!(q.after_seq.is_none());
        assert_eq!(q.limit, Some(5));
    }

    #[test]
    fn event_query_metadata_builder() {
        let q = EventQuery::new()
            .with_metadata("hive_task_id", "HIVE001")
            .with_metadata("agent", "alpha");
        let filters = q.metadata_filters.unwrap();
        assert_eq!(filters.len(), 2);
        assert_eq!(filters[0], ("hive_task_id".into(), "HIVE001".into()));
    }

    #[test]
    fn event_query_kind_builder() {
        let q = EventQuery::new()
            .with_kind("HiveArtifactShared")
            .with_kind("HiveSelectionMade");
        let kinds = q.kind_filter.unwrap();
        assert_eq!(kinds.len(), 2);
        assert_eq!(kinds[0], "HiveArtifactShared");
    }

    #[test]
    fn matches_filters_metadata() {
        use crate::event::EventEnvelope;
        use std::collections::HashMap;

        let mut metadata = HashMap::new();
        metadata.insert("hive_task_id".to_string(), "H1".to_string());
        metadata.insert("agent".to_string(), "a1".to_string());

        let envelope = EventEnvelope {
            event_id: EventId::from_string("E1"),
            session_id: SessionId::from_string("S1"),
            branch_id: BranchId::from_string("main"),
            run_id: None,
            seq: 1,
            timestamp: 100,
            parent_id: None,
            payload: crate::event::EventPayload::ErrorRaised {
                message: "test".into(),
            },
            metadata,
            schema_version: 1,
        };

        // Match
        let q = EventQuery::new().with_metadata("hive_task_id", "H1");
        assert!(q.matches_filters(&envelope));

        // Mismatch
        let q = EventQuery::new().with_metadata("hive_task_id", "H2");
        assert!(!q.matches_filters(&envelope));

        // No filters = match
        let q = EventQuery::new();
        assert!(q.matches_filters(&envelope));
    }

    #[test]
    fn matches_filters_kind() {
        use crate::event::EventEnvelope;

        let envelope = EventEnvelope {
            event_id: EventId::from_string("E1"),
            session_id: SessionId::from_string("S1"),
            branch_id: BranchId::from_string("main"),
            run_id: None,
            seq: 1,
            timestamp: 100,
            parent_id: None,
            payload: crate::event::EventPayload::ErrorRaised {
                message: "test".into(),
            },
            metadata: std::collections::HashMap::new(),
            schema_version: 1,
        };

        let q = EventQuery::new().with_kind("ErrorRaised");
        assert!(q.matches_filters(&envelope));

        let q = EventQuery::new().with_kind("HiveTaskCreated");
        assert!(!q.matches_filters(&envelope));
    }
}
