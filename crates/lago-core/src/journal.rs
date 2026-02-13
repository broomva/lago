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
}
