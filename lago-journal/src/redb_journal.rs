//! RedbJournal — the primary Journal trait implementation backed by redb.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use redb::{Database, ReadableTable};
use tokio::sync::broadcast;
use tracing::{Instrument, debug};

use lago_core::{
    BranchId, EventEnvelope, EventId, EventQuery, EventStream, Journal, LagoError, LagoResult,
    SeqNo, Session, SessionId,
};

use crate::keys::{encode_branch_key, encode_event_key};
use crate::stream::EventTailStream;
use crate::tables::{BRANCH_HEADS, EVENT_INDEX, EVENTS, SESSIONS, SNAPSHOTS};

/// Notification payload broadcast when new events are appended.
#[derive(Debug, Clone)]
pub struct EventNotification {
    pub session_id: SessionId,
    pub branch_id: BranchId,
    pub seq: SeqNo,
}

/// An event journal backed by redb — an embedded, ACID, key-value store.
///
/// All redb operations are run on a blocking thread pool via
/// `tokio::task::spawn_blocking` because redb is synchronous.
#[derive(Clone)]
pub struct RedbJournal {
    db: Arc<Database>,
    notify_tx: broadcast::Sender<EventNotification>,
}

impl RedbJournal {
    /// Open (or create) a journal database at the given filesystem path.
    ///
    /// Creates all required tables if they do not already exist.
    pub fn open(path: impl AsRef<Path>) -> LagoResult<Self> {
        let db = Database::create(path.as_ref())
            .map_err(|e| LagoError::Journal(format!("failed to open redb database: {e}")))?;

        // Ensure all tables exist by opening a write transaction.
        {
            let txn = db.begin_write().map_err(|e| {
                LagoError::Journal(format!("failed to begin write txn for table init: {e}"))
            })?;
            txn.open_table(EVENTS)
                .map_err(|e| LagoError::Journal(format!("failed to open events table: {e}")))?;
            txn.open_table(EVENT_INDEX).map_err(|e| {
                LagoError::Journal(format!("failed to open event_index table: {e}"))
            })?;
            txn.open_table(BRANCH_HEADS).map_err(|e| {
                LagoError::Journal(format!("failed to open branch_heads table: {e}"))
            })?;
            txn.open_table(SESSIONS)
                .map_err(|e| LagoError::Journal(format!("failed to open sessions table: {e}")))?;
            txn.open_table(SNAPSHOTS)
                .map_err(|e| LagoError::Journal(format!("failed to open snapshots table: {e}")))?;
            txn.commit()
                .map_err(|e| LagoError::Journal(format!("failed to commit table init: {e}")))?;
        }

        let (notify_tx, _) = broadcast::channel(4096);
        Ok(Self {
            db: Arc::new(db),
            notify_tx,
        })
    }

    /// Get a broadcast receiver for event notifications.
    pub fn subscribe(&self) -> broadcast::Receiver<EventNotification> {
        self.notify_tx.subscribe()
    }

    /// Get a reference to the underlying database.
    pub fn db(&self) -> &Arc<Database> {
        &self.db
    }

    // ---  Internal helpers (blocking, run on spawn_blocking)

    /// Append a batch of events inside a single redb write transaction.
    /// Returns the last assigned sequence number.
    fn append_batch_blocking(
        db: &Database,
        events: Vec<EventEnvelope>,
    ) -> LagoResult<(SeqNo, Vec<EventNotification>)> {
        let txn = db
            .begin_write()
            .map_err(|e| LagoError::Journal(format!("begin_write failed: {e}")))?;

        let mut last_seq = 0u64;
        let mut notifications = Vec::with_capacity(events.len());
        let mut branch_heads_cache: HashMap<Vec<u8>, SeqNo> = HashMap::new();

        {
            let mut events_table = txn
                .open_table(EVENTS)
                .map_err(|e| LagoError::Journal(format!("open events table: {e}")))?;
            let mut index_table = txn
                .open_table(EVENT_INDEX)
                .map_err(|e| LagoError::Journal(format!("open event_index table: {e}")))?;
            let mut heads_table = txn
                .open_table(BRANCH_HEADS)
                .map_err(|e| LagoError::Journal(format!("open branch_heads table: {e}")))?;

            for event in &events {
                let session_str = event.session_id.as_str();
                let branch_str = event.branch_id.as_str();
                let branch_key = encode_branch_key(session_str, branch_str);
                let current_head = if let Some(cached) = branch_heads_cache.get(&branch_key) {
                    *cached
                } else {
                    let head = heads_table
                        .get(branch_key.as_slice())
                        .map_err(|e| LagoError::Journal(format!("get branch head: {e}")))?
                        .map(|v| v.value())
                        .unwrap_or(0);
                    branch_heads_cache.insert(branch_key.clone(), head);
                    head
                };
                let assigned_seq = current_head.saturating_add(1);
                branch_heads_cache.insert(branch_key.clone(), assigned_seq);

                let mut assigned_event = event.clone();
                assigned_event.seq = assigned_seq;
                // Serialize event to JSON
                let json = serde_json::to_string(&assigned_event)?;

                // Encode compound key
                let event_key = encode_event_key(session_str, branch_str, assigned_seq);

                // Write to events table
                events_table
                    .insert(event_key.as_slice(), json.as_str())
                    .map_err(|e| LagoError::Journal(format!("insert event: {e}")))?;

                // Write to event index
                index_table
                    .insert(assigned_event.event_id.as_str(), event_key.as_slice())
                    .map_err(|e| LagoError::Journal(format!("insert event index: {e}")))?;

                // Update branch head
                heads_table
                    .insert(branch_key.as_slice(), assigned_seq)
                    .map_err(|e| LagoError::Journal(format!("update branch head: {e}")))?;

                last_seq = assigned_seq;

                notifications.push(EventNotification {
                    session_id: assigned_event.session_id.clone(),
                    branch_id: assigned_event.branch_id.clone(),
                    seq: assigned_seq,
                });
            }
        }

        txn.commit()
            .map_err(|e| LagoError::Journal(format!("commit failed: {e}")))?;

        Ok((last_seq, notifications))
    }

    /// Read events matching a query in a read transaction.
    fn read_blocking(db: &Database, query: EventQuery) -> LagoResult<Vec<EventEnvelope>> {
        let txn = db
            .begin_read()
            .map_err(|e| LagoError::Journal(format!("begin_read failed: {e}")))?;
        let events_table = txn
            .open_table(EVENTS)
            .map_err(|e| LagoError::Journal(format!("open events table: {e}")))?;

        let has_post_filters = query.metadata_filters.is_some() || query.kind_filter.is_some();

        let mut results = Vec::new();

        // Build the key range based on query parameters
        match (&query.session_id, &query.branch_id) {
            (Some(session_id), Some(branch_id)) => {
                // Specific session + branch: scan within that prefix
                let after = query.after_seq.unwrap_or(0);
                let before = query.before_seq.unwrap_or(u64::MAX);
                let start_key = encode_event_key(session_id.as_str(), branch_id.as_str(), after);
                let end_key = encode_event_key(session_id.as_str(), branch_id.as_str(), before);

                let range = events_table
                    .range(start_key.as_slice()..=end_key.as_slice())
                    .map_err(|e| LagoError::Journal(format!("range scan: {e}")))?;

                for item in range {
                    let (_, value) =
                        item.map_err(|e| LagoError::Journal(format!("range item: {e}")))?;
                    let envelope: EventEnvelope = serde_json::from_str(value.value())?;

                    // Filter: after_seq is exclusive
                    if let Some(after_seq) = query.after_seq
                        && envelope.seq <= after_seq
                    {
                        continue;
                    }
                    // Filter: before_seq is exclusive
                    if let Some(before_seq) = query.before_seq
                        && envelope.seq >= before_seq
                    {
                        continue;
                    }
                    // Post-deserialization filters (metadata + kind)
                    if has_post_filters && !query.matches_filters(&envelope) {
                        continue;
                    }

                    results.push(envelope);
                    if let Some(limit) = query.limit
                        && results.len() >= limit
                    {
                        break;
                    }
                }
            }
            (Some(session_id), None) => {
                // All branches for a session: scan the session prefix.
                // Start key = session_id + min_branch + 0
                // End key   = session_id + max_branch + u64::MAX
                let start_key = encode_event_key(session_id.as_str(), "", 0);
                // Use a key that is just past all valid branch IDs for this session
                let mut end_prefix = vec![0xFFu8; crate::keys::EVENT_KEY_LEN];
                let sid_bytes = session_id.as_str().as_bytes();
                let copy_len = sid_bytes.len().min(26);
                end_prefix[..copy_len].copy_from_slice(&sid_bytes[..copy_len]);

                let range = events_table
                    .range(start_key.as_slice()..=end_prefix.as_slice())
                    .map_err(|e| LagoError::Journal(format!("range scan: {e}")))?;

                for item in range {
                    let (_, value) =
                        item.map_err(|e| LagoError::Journal(format!("range item: {e}")))?;
                    let envelope: EventEnvelope = serde_json::from_str(value.value())?;

                    if let Some(after_seq) = query.after_seq
                        && envelope.seq <= after_seq
                    {
                        continue;
                    }
                    if let Some(before_seq) = query.before_seq
                        && envelope.seq >= before_seq
                    {
                        continue;
                    }
                    if has_post_filters && !query.matches_filters(&envelope) {
                        continue;
                    }

                    results.push(envelope);
                    if let Some(limit) = query.limit
                        && results.len() >= limit
                    {
                        break;
                    }
                }
            }
            (None, _) => {
                // Full scan (no session filter)
                let range = events_table
                    .iter()
                    .map_err(|e| LagoError::Journal(format!("iter: {e}")))?;

                for item in range {
                    let (_key, value) =
                        item.map_err(|e| LagoError::Journal(format!("range item: {e}")))?;
                    let json_str: &str = value.value();
                    let envelope: EventEnvelope = serde_json::from_str(json_str)?;

                    if let Some(ref sid) = query.session_id
                        && envelope.session_id.as_str() != sid.as_str()
                    {
                        continue;
                    }
                    if let Some(ref bid) = query.branch_id
                        && envelope.branch_id.as_str() != bid.as_str()
                    {
                        continue;
                    }
                    if let Some(after_seq) = query.after_seq
                        && envelope.seq <= after_seq
                    {
                        continue;
                    }
                    if let Some(before_seq) = query.before_seq
                        && envelope.seq >= before_seq
                    {
                        continue;
                    }
                    if has_post_filters && !query.matches_filters(&envelope) {
                        continue;
                    }

                    results.push(envelope);
                    if let Some(limit) = query.limit
                        && results.len() >= limit
                    {
                        break;
                    }
                }
            }
        }

        Ok(results)
    }

    /// Get a single event by its EventId via the index table.
    fn get_event_blocking(db: &Database, event_id: &str) -> LagoResult<Option<EventEnvelope>> {
        let txn = db
            .begin_read()
            .map_err(|e| LagoError::Journal(format!("begin_read failed: {e}")))?;

        let index_table = txn
            .open_table(EVENT_INDEX)
            .map_err(|e| LagoError::Journal(format!("open event_index table: {e}")))?;

        let compound_key = match index_table
            .get(event_id)
            .map_err(|e| LagoError::Journal(format!("get event index: {e}")))?
        {
            Some(v) => v.value().to_vec(),
            None => return Ok(None),
        };

        let events_table = txn
            .open_table(EVENTS)
            .map_err(|e| LagoError::Journal(format!("open events table: {e}")))?;

        match events_table
            .get(compound_key.as_slice())
            .map_err(|e| LagoError::Journal(format!("get event: {e}")))?
        {
            Some(v) => {
                let envelope: EventEnvelope = serde_json::from_str(v.value())?;
                Ok(Some(envelope))
            }
            None => Ok(None),
        }
    }

    /// Get the head sequence number for a session+branch.
    fn head_seq_blocking(db: &Database, session_id: &str, branch_id: &str) -> LagoResult<SeqNo> {
        let txn = db
            .begin_read()
            .map_err(|e| LagoError::Journal(format!("begin_read failed: {e}")))?;
        let heads_table = txn
            .open_table(BRANCH_HEADS)
            .map_err(|e| LagoError::Journal(format!("open branch_heads table: {e}")))?;

        let branch_key = encode_branch_key(session_id, branch_id);
        match heads_table
            .get(branch_key.as_slice())
            .map_err(|e| LagoError::Journal(format!("get branch head: {e}")))?
        {
            Some(v) => Ok(v.value()),
            None => Ok(0),
        }
    }

    /// Put a session into the sessions table.
    fn put_session_blocking(db: &Database, session: Session) -> LagoResult<()> {
        let json = serde_json::to_string(&session)?;
        let txn = db
            .begin_write()
            .map_err(|e| LagoError::Journal(format!("begin_write failed: {e}")))?;
        {
            let mut table = txn
                .open_table(SESSIONS)
                .map_err(|e| LagoError::Journal(format!("open sessions table: {e}")))?;
            table
                .insert(session.session_id.as_str(), json.as_str())
                .map_err(|e| LagoError::Journal(format!("insert session: {e}")))?;
        }
        txn.commit()
            .map_err(|e| LagoError::Journal(format!("commit failed: {e}")))?;
        Ok(())
    }

    /// Get a session by ID.
    fn get_session_blocking(db: &Database, session_id: &str) -> LagoResult<Option<Session>> {
        let txn = db
            .begin_read()
            .map_err(|e| LagoError::Journal(format!("begin_read failed: {e}")))?;
        let table = txn
            .open_table(SESSIONS)
            .map_err(|e| LagoError::Journal(format!("open sessions table: {e}")))?;

        match table
            .get(session_id)
            .map_err(|e| LagoError::Journal(format!("get session: {e}")))?
        {
            Some(v) => {
                let session: Session = serde_json::from_str(v.value())?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    /// List all sessions.
    fn list_sessions_blocking(db: &Database) -> LagoResult<Vec<Session>> {
        let txn = db
            .begin_read()
            .map_err(|e| LagoError::Journal(format!("begin_read failed: {e}")))?;
        let table = txn
            .open_table(SESSIONS)
            .map_err(|e| LagoError::Journal(format!("open sessions table: {e}")))?;

        let mut sessions = Vec::new();
        for item in table
            .iter()
            .map_err(|e| LagoError::Journal(format!("iter sessions: {e}")))?
        {
            let (_key, value) =
                item.map_err(|e| LagoError::Journal(format!("session item: {e}")))?;
            let json_str: &str = value.value();
            let session: Session = serde_json::from_str(json_str)?;
            sessions.push(session);
        }
        Ok(sessions)
    }
}

impl Journal for RedbJournal {
    fn append(
        &self,
        event: EventEnvelope,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = LagoResult<SeqNo>> + Send + '_>> {
        let span = tracing::info_span!(
            "lago.journal.append",
            lago.stream_id = %event.session_id,
            lago.event_count = 1,
        );
        let db = Arc::clone(&self.db);
        let notify_tx = self.notify_tx.clone();
        Box::pin(
            async move {
                let events = vec![event];
                let (last_seq, notifications) =
                    tokio::task::spawn_blocking(move || Self::append_batch_blocking(&db, events))
                        .await
                        .map_err(|e| {
                            LagoError::Journal(format!("spawn_blocking join error: {e}"))
                        })??;

                for notification in notifications {
                    let _ = notify_tx.send(notification);
                }
                debug!(seq = last_seq, "appended event");
                Ok(last_seq)
            }
            .instrument(span),
        )
    }

    fn append_batch(
        &self,
        events: Vec<EventEnvelope>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = LagoResult<SeqNo>> + Send + '_>> {
        let span =
            tracing::info_span!("lago.journal.append_batch", lago.event_count = events.len(),);
        let db = Arc::clone(&self.db);
        let notify_tx = self.notify_tx.clone();
        Box::pin(
            async move {
                if events.is_empty() {
                    return Ok(0);
                }
                let (last_seq, notifications) =
                    tokio::task::spawn_blocking(move || Self::append_batch_blocking(&db, events))
                        .await
                        .map_err(|e| {
                            LagoError::Journal(format!("spawn_blocking join error: {e}"))
                        })??;

                for notification in notifications {
                    let _ = notify_tx.send(notification);
                }
                debug!(seq = last_seq, "appended batch");
                Ok(last_seq)
            }
            .instrument(span),
        )
    }

    fn read(
        &self,
        query: EventQuery,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = LagoResult<Vec<EventEnvelope>>> + Send + '_>,
    > {
        let span = tracing::info_span!("lago.journal.read");
        let db = Arc::clone(&self.db);
        Box::pin(
            async move {
                tokio::task::spawn_blocking(move || Self::read_blocking(&db, query))
                    .await
                    .map_err(|e| LagoError::Journal(format!("spawn_blocking join error: {e}")))?
            }
            .instrument(span),
        )
    }

    fn get_event(
        &self,
        event_id: &EventId,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = LagoResult<Option<EventEnvelope>>> + Send + '_>,
    > {
        let id_str = event_id.as_str().to_string();
        let db = Arc::clone(&self.db);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || Self::get_event_blocking(&db, &id_str))
                .await
                .map_err(|e| LagoError::Journal(format!("spawn_blocking join error: {e}")))?
        })
    }

    fn head_seq(
        &self,
        session_id: &SessionId,
        branch_id: &BranchId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = LagoResult<SeqNo>> + Send + '_>> {
        let span = tracing::info_span!(
            "lago.journal.head_seq",
            lago.stream_id = %session_id,
        );
        let db = Arc::clone(&self.db);
        let sid = session_id.as_str().to_string();
        let bid = branch_id.as_str().to_string();
        Box::pin(
            async move {
                tokio::task::spawn_blocking(move || Self::head_seq_blocking(&db, &sid, &bid))
                    .await
                    .map_err(|e| LagoError::Journal(format!("spawn_blocking join error: {e}")))?
            }
            .instrument(span),
        )
    }

    fn stream(
        &self,
        session_id: SessionId,
        branch_id: BranchId,
        after_seq: SeqNo,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = LagoResult<EventStream>> + Send + '_>>
    {
        let span = tracing::info_span!(
            "lago.journal.stream",
            lago.stream_id = %session_id,
        );
        let db = Arc::clone(&self.db);
        let rx = self.notify_tx.subscribe();
        Box::pin(
            async move {
                let tail = EventTailStream::new(db, rx, session_id, branch_id, after_seq);
                Ok(Box::pin(tail) as EventStream)
            }
            .instrument(span),
        )
    }

    fn put_session(
        &self,
        session: Session,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = LagoResult<()>> + Send + '_>> {
        let db = Arc::clone(&self.db);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || Self::put_session_blocking(&db, session))
                .await
                .map_err(|e| LagoError::Journal(format!("spawn_blocking join error: {e}")))?
        })
    }

    fn get_session(
        &self,
        session_id: &SessionId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = LagoResult<Option<Session>>> + Send + '_>>
    {
        let db = Arc::clone(&self.db);
        let sid = session_id.as_str().to_string();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || Self::get_session_blocking(&db, &sid))
                .await
                .map_err(|e| LagoError::Journal(format!("spawn_blocking join error: {e}")))?
        })
    }

    fn list_sessions(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = LagoResult<Vec<Session>>> + Send + '_>>
    {
        let db = Arc::clone(&self.db);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || Self::list_sessions_blocking(&db))
                .await
                .map_err(|e| LagoError::Journal(format!("spawn_blocking join error: {e}")))?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lago_core::event::{EventEnvelope, EventPayload};
    use lago_core::session::SessionConfig;
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn make_event(session: &str, branch: &str, seq: u64) -> EventEnvelope {
        EventEnvelope {
            event_id: EventId::new(),
            session_id: SessionId::from_string(session),
            branch_id: BranchId::from_string(branch),
            run_id: None,
            seq,
            timestamp: EventEnvelope::now_micros(),
            parent_id: None,
            payload: EventPayload::Message {
                role: "user".to_string(),
                content: format!("message at seq {seq}"),
                model: None,
                token_usage: None,
            },
            metadata: HashMap::new(),
            schema_version: 1,
        }
    }

    fn setup() -> (TempDir, RedbJournal) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("test.redb");
        let journal = RedbJournal::open(&db_path).unwrap();
        (dir, journal)
    }

    #[tokio::test]
    async fn open_creates_database() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("test.redb");
        assert!(!db_path.exists());
        let _journal = RedbJournal::open(&db_path).unwrap();
        assert!(db_path.exists());
    }

    #[tokio::test]
    async fn append_and_read_single_event() {
        let (_dir, journal) = setup();
        let event = make_event("s1", "main", 1);
        let event_id = event.event_id.clone();

        let seq = journal.append(event).await.unwrap();
        assert_eq!(seq, 1);

        // Read back via query
        let results = journal
            .read(
                EventQuery::new()
                    .session(SessionId::from_string("s1"))
                    .branch(BranchId::from_string("main")),
            )
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event_id, event_id);
        assert_eq!(results[0].seq, 1);
    }

    #[tokio::test]
    async fn append_batch_multiple_events() {
        let (_dir, journal) = setup();
        let events: Vec<_> = (1..=5).map(|i| make_event("s1", "main", i)).collect();

        let last_seq = journal.append_batch(events).await.unwrap();
        assert_eq!(last_seq, 5);

        let results = journal
            .read(
                EventQuery::new()
                    .session(SessionId::from_string("s1"))
                    .branch(BranchId::from_string("main")),
            )
            .await
            .unwrap();
        assert_eq!(results.len(), 5);
    }

    #[tokio::test]
    async fn append_batch_empty_returns_zero() {
        let (_dir, journal) = setup();
        let seq = journal.append_batch(vec![]).await.unwrap();
        assert_eq!(seq, 0);
    }

    #[tokio::test]
    async fn read_with_after_seq_filter() {
        let (_dir, journal) = setup();
        let events: Vec<_> = (1..=10).map(|i| make_event("s1", "main", i)).collect();
        journal.append_batch(events).await.unwrap();

        let results = journal
            .read(
                EventQuery::new()
                    .session(SessionId::from_string("s1"))
                    .branch(BranchId::from_string("main"))
                    .after(5),
            )
            .await
            .unwrap();
        assert_eq!(results.len(), 5);
        assert!(results.iter().all(|e| e.seq > 5));
    }

    #[tokio::test]
    async fn read_with_before_seq_filter() {
        let (_dir, journal) = setup();
        let events: Vec<_> = (1..=10).map(|i| make_event("s1", "main", i)).collect();
        journal.append_batch(events).await.unwrap();

        let results = journal
            .read(
                EventQuery::new()
                    .session(SessionId::from_string("s1"))
                    .branch(BranchId::from_string("main"))
                    .before(4),
            )
            .await
            .unwrap();
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|e| e.seq < 4));
    }

    #[tokio::test]
    async fn read_with_limit() {
        let (_dir, journal) = setup();
        let events: Vec<_> = (1..=20).map(|i| make_event("s1", "main", i)).collect();
        journal.append_batch(events).await.unwrap();

        let results = journal
            .read(
                EventQuery::new()
                    .session(SessionId::from_string("s1"))
                    .branch(BranchId::from_string("main"))
                    .limit(5),
            )
            .await
            .unwrap();
        assert_eq!(results.len(), 5);
    }

    #[tokio::test]
    async fn read_across_branches() {
        let (_dir, journal) = setup();
        journal.append(make_event("s1", "main", 1)).await.unwrap();
        journal.append(make_event("s1", "main", 2)).await.unwrap();
        journal.append(make_event("s1", "dev", 1)).await.unwrap();

        // Only "main"
        let main_events = journal
            .read(
                EventQuery::new()
                    .session(SessionId::from_string("s1"))
                    .branch(BranchId::from_string("main")),
            )
            .await
            .unwrap();
        assert_eq!(main_events.len(), 2);

        // Only "dev"
        let dev_events = journal
            .read(
                EventQuery::new()
                    .session(SessionId::from_string("s1"))
                    .branch(BranchId::from_string("dev")),
            )
            .await
            .unwrap();
        assert_eq!(dev_events.len(), 1);

        // All branches for session
        let all_events = journal
            .read(EventQuery::new().session(SessionId::from_string("s1")))
            .await
            .unwrap();
        assert_eq!(all_events.len(), 3);
    }

    #[tokio::test]
    async fn get_event_by_id() {
        let (_dir, journal) = setup();
        let event = make_event("s1", "main", 1);
        let event_id = event.event_id.clone();
        journal.append(event).await.unwrap();

        let found = journal.get_event(&event_id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().event_id, event_id);
    }

    #[tokio::test]
    async fn get_event_not_found() {
        let (_dir, journal) = setup();
        let fake_id = EventId::from_string("NONEXISTENT");
        let found = journal.get_event(&fake_id).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn head_seq_tracking() {
        let (_dir, journal) = setup();
        let sid = SessionId::from_string("s1");
        let bid = BranchId::from_string("main");

        // Initially 0
        let head = journal.head_seq(&sid, &bid).await.unwrap();
        assert_eq!(head, 0);

        journal.append(make_event("s1", "main", 5)).await.unwrap();
        let head = journal.head_seq(&sid, &bid).await.unwrap();
        assert_eq!(head, 1);

        journal.append(make_event("s1", "main", 10)).await.unwrap();
        let head = journal.head_seq(&sid, &bid).await.unwrap();
        assert_eq!(head, 2);
    }

    #[tokio::test]
    async fn append_ignores_caller_provided_seq() {
        let (_dir, journal) = setup();
        let sid = SessionId::from_string("s1");
        let bid = BranchId::from_string("main");

        // Caller provides non-monotonic sequence values, journal assigns 1..N.
        journal.append(make_event("s1", "main", 99)).await.unwrap();
        journal.append(make_event("s1", "main", 42)).await.unwrap();

        let events = journal
            .read(EventQuery::new().session(sid).branch(bid))
            .await
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].seq, 1);
        assert_eq!(events[1].seq, 2);
    }

    #[tokio::test]
    async fn session_crud() {
        let (_dir, journal) = setup();
        let sid = SessionId::from_string("SESS001");

        // Initially no sessions
        let sessions = journal.list_sessions().await.unwrap();
        assert!(sessions.is_empty());

        // Get non-existent session returns None
        let s = journal.get_session(&sid).await.unwrap();
        assert!(s.is_none());

        // Put a session
        let session = Session {
            session_id: sid.clone(),
            config: SessionConfig {
                name: "test-session".to_string(),
                model: "gpt-4".to_string(),
                params: HashMap::from([("temp".to_string(), "0.5".to_string())]),
            },
            created_at: 1700000000,
            branches: vec![BranchId::from_string("main")],
        };
        journal.put_session(session).await.unwrap();

        // Get session
        let found = journal.get_session(&sid).await.unwrap().unwrap();
        assert_eq!(found.config.name, "test-session");
        assert_eq!(found.config.model, "gpt-4");
        assert_eq!(found.config.params["temp"], "0.5");

        // List sessions
        let sessions = journal.list_sessions().await.unwrap();
        assert_eq!(sessions.len(), 1);
    }

    #[tokio::test]
    async fn session_update_overwrites() {
        let (_dir, journal) = setup();
        let sid = SessionId::from_string("S1");

        let session1 = Session {
            session_id: sid.clone(),
            config: SessionConfig::new("v1"),
            created_at: 100,
            branches: vec![],
        };
        journal.put_session(session1).await.unwrap();

        let session2 = Session {
            session_id: sid.clone(),
            config: SessionConfig::new("v2"),
            created_at: 200,
            branches: vec![BranchId::from_string("main")],
        };
        journal.put_session(session2).await.unwrap();

        let found = journal.get_session(&sid).await.unwrap().unwrap();
        assert_eq!(found.config.name, "v2");
        assert_eq!(found.created_at, 200);

        // Still only one session
        assert_eq!(journal.list_sessions().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn multiple_sessions() {
        let (_dir, journal) = setup();

        for i in 0..5 {
            let session = Session {
                session_id: SessionId::from_string(format!("S{i}")),
                config: SessionConfig::new(format!("session-{i}")),
                created_at: i as u64,
                branches: vec![],
            };
            journal.put_session(session).await.unwrap();
        }

        let sessions = journal.list_sessions().await.unwrap();
        assert_eq!(sessions.len(), 5);
    }

    #[tokio::test]
    async fn notifications_are_sent_on_append() {
        let (_dir, journal) = setup();
        let mut rx = journal.subscribe();

        journal.append(make_event("s1", "main", 1)).await.unwrap();

        let notification = rx.try_recv().unwrap();
        assert_eq!(notification.session_id.as_str(), "s1");
        assert_eq!(notification.branch_id.as_str(), "main");
        assert_eq!(notification.seq, 1);
    }

    #[tokio::test]
    async fn full_scan_no_session_filter() {
        let (_dir, journal) = setup();
        journal.append(make_event("s1", "main", 1)).await.unwrap();
        journal.append(make_event("s2", "main", 1)).await.unwrap();

        let results = journal.read(EventQuery::new()).await.unwrap();
        assert_eq!(results.len(), 2);
    }
}
