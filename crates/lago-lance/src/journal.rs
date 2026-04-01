//! `LanceJournal` — a [`Journal`] implementation backed by Lance columnar storage.
//!
//! Lance is an async-native columnar format optimised for ML/AI workloads.
//! Unlike redb, all operations are natively async, so no `spawn_blocking` is needed.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use arrow_array::{RecordBatch, RecordBatchIterator};
use futures::StreamExt;
use lance::dataset::{Dataset, WriteMode, WriteParams};
use tokio::sync::Mutex;
use tracing::debug;

use lago_core::event::EventEnvelope;
use lago_core::id::{BranchId, EventId, SeqNo, SessionId};
use lago_core::journal::{EventQuery, EventStream, Journal};
use lago_core::session::Session;
use lago_core::{LagoError, LagoResult};

use crate::convert::{batch_to_events, batch_to_sessions, events_to_batch, session_to_batch};
use crate::schema::{event_schema, session_schema};

/// A Lance-backed event journal.
///
/// Stores events and sessions in separate Lance datasets under a base directory:
/// - `<base>/events.lance` — event envelopes
/// - `<base>/sessions.lance` — session records
///
/// Lance datasets are created lazily on the first write if they do not yet exist.
pub struct LanceJournal {
    events_uri: String,
    sessions_uri: String,
    /// Mutex to serialize writes and prevent concurrent version conflicts.
    write_lock: Mutex<()>,
}

impl LanceJournal {
    /// Open (or prepare) a Lance journal at the given base path.
    ///
    /// The Lance datasets are created lazily on the first write operation.
    pub async fn open(base_path: impl AsRef<Path>) -> LagoResult<Self> {
        let base = base_path.as_ref();
        std::fs::create_dir_all(base)
            .map_err(|e| LagoError::Journal(format!("failed to create base dir: {e}")))?;

        let events_uri = base.join("events.lance").to_string_lossy().to_string();
        let sessions_uri = base.join("sessions.lance").to_string_lossy().to_string();

        Ok(Self {
            events_uri,
            sessions_uri,
            write_lock: Mutex::new(()),
        })
    }

    /// Check whether the events dataset already exists on disk.
    fn events_exist(&self) -> bool {
        PathBuf::from(&self.events_uri).exists()
    }

    /// Check whether the sessions dataset already exists on disk.
    fn sessions_exist(&self) -> bool {
        PathBuf::from(&self.sessions_uri).exists()
    }

    /// Write a `RecordBatch` of events — creates the dataset on first call,
    /// appends on subsequent calls.
    async fn write_events_batch(&self, batch: RecordBatch) -> LagoResult<()> {
        let schema = Arc::new(event_schema());
        let batches: Vec<Result<RecordBatch, arrow::error::ArrowError>> = vec![Ok(batch)];
        let reader = RecordBatchIterator::new(batches, schema);

        if self.events_exist() {
            let mut ds = Dataset::open(&self.events_uri)
                .await
                .map_err(|e| LagoError::Journal(format!("open events dataset: {e}")))?;
            ds.append(reader, None)
                .await
                .map_err(|e| LagoError::Journal(format!("append events: {e}")))?;
        } else {
            let params = WriteParams {
                mode: WriteMode::Create,
                ..Default::default()
            };
            Dataset::write(reader, &self.events_uri, Some(params))
                .await
                .map_err(|e| LagoError::Journal(format!("create events dataset: {e}")))?;
        }

        Ok(())
    }

    /// Write a `RecordBatch` of sessions — creates the dataset on first call,
    /// appends on subsequent calls.
    async fn write_sessions_batch(&self, batch: RecordBatch) -> LagoResult<()> {
        let schema = Arc::new(session_schema());
        let batches: Vec<Result<RecordBatch, arrow::error::ArrowError>> = vec![Ok(batch)];
        let reader = RecordBatchIterator::new(batches, schema);

        if self.sessions_exist() {
            let mut ds = Dataset::open(&self.sessions_uri)
                .await
                .map_err(|e| LagoError::Journal(format!("open sessions dataset: {e}")))?;
            ds.append(reader, None)
                .await
                .map_err(|e| LagoError::Journal(format!("append sessions: {e}")))?;
        } else {
            let params = WriteParams {
                mode: WriteMode::Create,
                ..Default::default()
            };
            Dataset::write(reader, &self.sessions_uri, Some(params))
                .await
                .map_err(|e| LagoError::Journal(format!("create sessions dataset: {e}")))?;
        }

        Ok(())
    }

    /// Read all events from the dataset, optionally applying Lance SQL filters.
    async fn scan_events(&self, lance_filter: Option<&str>) -> LagoResult<Vec<EventEnvelope>> {
        if !self.events_exist() {
            return Ok(Vec::new());
        }

        let ds = Dataset::open(&self.events_uri)
            .await
            .map_err(|e| LagoError::Journal(format!("open events for scan: {e}")))?;

        let mut scanner = ds.scan();
        if let Some(filter) = lance_filter {
            scanner
                .filter(filter)
                .map_err(|e| LagoError::Journal(format!("filter events: {e}")))?;
        }

        let mut stream = scanner
            .try_into_stream()
            .await
            .map_err(|e| LagoError::Journal(format!("events scan stream: {e}")))?;

        let mut events = Vec::new();
        while let Some(result) = stream.next().await {
            let batch =
                result.map_err(|e| LagoError::Journal(format!("events batch read: {e}")))?;
            events.extend(batch_to_events(&batch));
        }

        Ok(events)
    }

    /// Read all sessions from the dataset, optionally applying a Lance SQL filter.
    async fn scan_sessions(&self, lance_filter: Option<&str>) -> LagoResult<Vec<Session>> {
        if !self.sessions_exist() {
            return Ok(Vec::new());
        }

        let ds = Dataset::open(&self.sessions_uri)
            .await
            .map_err(|e| LagoError::Journal(format!("open sessions for scan: {e}")))?;

        let mut scanner = ds.scan();
        if let Some(filter) = lance_filter {
            scanner
                .filter(filter)
                .map_err(|e| LagoError::Journal(format!("filter sessions: {e}")))?;
        }

        let mut stream = scanner
            .try_into_stream()
            .await
            .map_err(|e| LagoError::Journal(format!("sessions scan stream: {e}")))?;

        let mut sessions = Vec::new();
        while let Some(result) = stream.next().await {
            let batch =
                result.map_err(|e| LagoError::Journal(format!("sessions batch read: {e}")))?;
            sessions.extend(batch_to_sessions(&batch));
        }

        Ok(sessions)
    }

    /// Compute the current head sequence number for a (session, branch) pair.
    async fn compute_head_seq(&self, session_id: &str, branch_id: &str) -> LagoResult<SeqNo> {
        let filter = format!(
            "session_id = '{}' AND branch_id = '{}'",
            escape_sql(session_id),
            escape_sql(branch_id),
        );

        let events = self.scan_events(Some(&filter)).await?;
        Ok(events.iter().map(|e| e.seq).max().unwrap_or(0))
    }
}

/// Escape single quotes in SQL string literals to prevent injection.
fn escape_sql(s: &str) -> String {
    s.replace('\'', "''")
}

impl Journal for LanceJournal {
    fn append(
        &self,
        event: EventEnvelope,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = LagoResult<SeqNo>> + Send + '_>> {
        Box::pin(async move {
            let _lock = self.write_lock.lock().await;

            let session_id = event.session_id.as_str().to_string();
            let branch_id = event.branch_id.as_str().to_string();

            let current_head = self.compute_head_seq(&session_id, &branch_id).await?;
            let assigned_seq = current_head.saturating_add(1);

            let mut assigned_event = event;
            assigned_event.seq = assigned_seq;

            let batch = events_to_batch(&[assigned_event])
                .map_err(|e| LagoError::Journal(format!("arrow batch creation: {e}")))?;

            self.write_events_batch(batch).await?;

            debug!(seq = assigned_seq, "appended event to lance");
            Ok(assigned_seq)
        })
    }

    fn append_batch(
        &self,
        events: Vec<EventEnvelope>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = LagoResult<SeqNo>> + Send + '_>> {
        Box::pin(async move {
            if events.is_empty() {
                return Ok(0);
            }

            let _lock = self.write_lock.lock().await;

            // Group events by (session_id, branch_id) and assign sequences.
            let mut assigned_events = Vec::with_capacity(events.len());
            // Cache head sequences to avoid repeated scans within the batch.
            let mut head_cache: std::collections::HashMap<(String, String), SeqNo> =
                std::collections::HashMap::new();

            for event in events {
                let key = (
                    event.session_id.as_str().to_string(),
                    event.branch_id.as_str().to_string(),
                );
                let current_head = if let Some(h) = head_cache.get(&key) {
                    *h
                } else {
                    self.compute_head_seq(&key.0, &key.1).await?
                };
                let assigned_seq = current_head.saturating_add(1);
                head_cache.insert(key, assigned_seq);

                let mut assigned_event = event;
                assigned_event.seq = assigned_seq;
                assigned_events.push(assigned_event);
            }

            let last_seq = assigned_events.last().map(|e| e.seq).unwrap_or(0);

            let batch = events_to_batch(&assigned_events)
                .map_err(|e| LagoError::Journal(format!("arrow batch creation: {e}")))?;

            self.write_events_batch(batch).await?;

            debug!(
                seq = last_seq,
                count = assigned_events.len(),
                "appended batch to lance"
            );
            Ok(last_seq)
        })
    }

    fn read(
        &self,
        query: EventQuery,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = LagoResult<Vec<EventEnvelope>>> + Send + '_>,
    > {
        Box::pin(async move {
            // Build a Lance SQL filter from the EventQuery.
            let mut conditions = Vec::new();

            if let Some(ref sid) = query.session_id {
                conditions.push(format!("session_id = '{}'", escape_sql(sid.as_str())));
            }
            if let Some(ref bid) = query.branch_id {
                conditions.push(format!("branch_id = '{}'", escape_sql(bid.as_str())));
            }
            if let Some(after) = query.after_seq {
                conditions.push(format!("seq > {after}"));
            }
            if let Some(before) = query.before_seq {
                conditions.push(format!("seq < {before}"));
            }

            let filter = if conditions.is_empty() {
                None
            } else {
                Some(conditions.join(" AND "))
            };

            let mut events = self.scan_events(filter.as_deref()).await?;

            // Apply post-deserialization filters (metadata + kind).
            let has_post_filters = query.metadata_filters.is_some() || query.kind_filter.is_some();
            if has_post_filters {
                events.retain(|e| query.matches_filters(e));
            }

            // Sort by seq for consistent ordering.
            events.sort_by_key(|e| e.seq);

            // Apply limit.
            if let Some(limit) = query.limit {
                events.truncate(limit);
            }

            Ok(events)
        })
    }

    fn get_event(
        &self,
        event_id: &EventId,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = LagoResult<Option<EventEnvelope>>> + Send + '_>,
    > {
        let id_str = event_id.as_str().to_string();
        Box::pin(async move {
            let filter = format!("event_id = '{}'", escape_sql(&id_str));
            let events = self.scan_events(Some(&filter)).await?;
            Ok(events.into_iter().next())
        })
    }

    fn head_seq(
        &self,
        session_id: &SessionId,
        branch_id: &BranchId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = LagoResult<SeqNo>> + Send + '_>> {
        let sid = session_id.as_str().to_string();
        let bid = branch_id.as_str().to_string();
        Box::pin(async move { self.compute_head_seq(&sid, &bid).await })
    }

    fn stream(
        &self,
        _session_id: SessionId,
        _branch_id: BranchId,
        _after_seq: SeqNo,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = LagoResult<EventStream>> + Send + '_>>
    {
        // Tailing streams over Lance are not natively supported.
        // Return a stream that reads once and ends. A polling wrapper
        // could be added later for live-tailing use cases.
        Box::pin(async move {
            let stream = futures::stream::once(async {
                Err(LagoError::Journal(
                    "Lance journal stream() not yet implemented — use read() with polling".into(),
                ))
            });
            Ok(Box::pin(stream) as EventStream)
        })
    }

    fn put_session(
        &self,
        session: Session,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = LagoResult<()>> + Send + '_>> {
        Box::pin(async move {
            let _lock = self.write_lock.lock().await;

            // Check if session already exists and rebuild the dataset without it,
            // then append the new version. This is an upsert pattern.
            let existing = self.scan_sessions(None).await?;
            let session_id_str = session.session_id.as_str().to_string();

            // If the session already exists, we need to rewrite.
            let has_existing = existing
                .iter()
                .any(|s| s.session_id.as_str() == session_id_str);

            if has_existing {
                // Collect all sessions except the one being replaced, then add the new one.
                let mut all_sessions: Vec<Session> = existing
                    .into_iter()
                    .filter(|s| s.session_id.as_str() != session_id_str)
                    .collect();
                all_sessions.push(session);

                // Rewrite the entire sessions dataset.
                let mut batches: Vec<Result<RecordBatch, arrow::error::ArrowError>> = Vec::new();
                for s in &all_sessions {
                    let batch = session_to_batch(s)
                        .map_err(|e| LagoError::Journal(format!("session batch: {e}")))?;
                    batches.push(Ok(batch));
                }

                let schema = Arc::new(session_schema());
                let reader = RecordBatchIterator::new(batches, schema);
                let params = WriteParams {
                    mode: WriteMode::Overwrite,
                    ..Default::default()
                };
                Dataset::write(reader, &self.sessions_uri, Some(params))
                    .await
                    .map_err(|e| LagoError::Journal(format!("overwrite sessions: {e}")))?;
            } else {
                let batch = session_to_batch(&session)
                    .map_err(|e| LagoError::Journal(format!("session batch: {e}")))?;
                self.write_sessions_batch(batch).await?;
            }

            debug!(session_id = %session_id_str, "put session in lance");
            Ok(())
        })
    }

    fn get_session(
        &self,
        session_id: &SessionId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = LagoResult<Option<Session>>> + Send + '_>>
    {
        let sid = session_id.as_str().to_string();
        Box::pin(async move {
            let filter = format!("session_id = '{}'", escape_sql(&sid));
            let sessions = self.scan_sessions(Some(&filter)).await?;
            Ok(sessions.into_iter().next())
        })
    }

    fn list_sessions(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = LagoResult<Vec<Session>>> + Send + '_>>
    {
        Box::pin(async move { self.scan_sessions(None).await })
    }
}

// LanceJournal is Send + Sync automatically:
// - Mutex<()> is Send + Sync
// - String is Send + Sync
// - Lance's Dataset is opened fresh for each operation (no long-lived references)

#[cfg(test)]
mod tests {
    use super::*;
    use lago_core::event::EventPayload;
    use lago_core::session::SessionConfig;
    use std::collections::HashMap;

    fn make_test_event(
        event_id: &str,
        session_id: &str,
        branch_id: &str,
        seq: u64,
    ) -> EventEnvelope {
        EventEnvelope {
            event_id: EventId::from_string(event_id),
            session_id: SessionId::from_string(session_id),
            branch_id: BranchId::from_string(branch_id),
            run_id: None,
            seq,
            timestamp: 1_700_000_000_000_000 + seq,
            parent_id: None,
            payload: EventPayload::ErrorRaised {
                message: format!("test event {event_id}"),
            },
            metadata: HashMap::new(),
            schema_version: 1,
        }
    }

    fn make_test_session(session_id: &str) -> Session {
        Session {
            session_id: SessionId::from_string(session_id),
            config: SessionConfig::new(format!("session-{session_id}")),
            created_at: 1_700_000_000,
            branches: vec![BranchId::from_string("main")],
        }
    }

    #[tokio::test]
    async fn test_append_and_read() {
        let dir = tempfile::tempdir().unwrap();
        let journal = LanceJournal::open(dir.path()).await.unwrap();

        let event = make_test_event("E1", "S1", "main", 0);
        let seq = journal.append(event).await.unwrap();
        assert_eq!(seq, 1);

        let events = journal
            .read(EventQuery::new().session(SessionId::from_string("S1")))
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id.as_str(), "E1");
        assert_eq!(events[0].seq, 1);
    }

    #[tokio::test]
    async fn test_append_batch() {
        let dir = tempfile::tempdir().unwrap();
        let journal = LanceJournal::open(dir.path()).await.unwrap();

        let events = vec![
            make_test_event("E1", "S1", "main", 0),
            make_test_event("E2", "S1", "main", 0),
            make_test_event("E3", "S1", "main", 0),
        ];

        let last_seq = journal.append_batch(events).await.unwrap();
        assert_eq!(last_seq, 3);

        let read = journal
            .read(EventQuery::new().session(SessionId::from_string("S1")))
            .await
            .unwrap();
        assert_eq!(read.len(), 3);
        assert_eq!(read[0].seq, 1);
        assert_eq!(read[1].seq, 2);
        assert_eq!(read[2].seq, 3);
    }

    #[tokio::test]
    async fn test_head_seq() {
        let dir = tempfile::tempdir().unwrap();
        let journal = LanceJournal::open(dir.path()).await.unwrap();

        // No events yet — head should be 0.
        let head = journal
            .head_seq(
                &SessionId::from_string("S1"),
                &BranchId::from_string("main"),
            )
            .await
            .unwrap();
        assert_eq!(head, 0);

        // Append some events.
        let events = vec![
            make_test_event("E1", "S1", "main", 0),
            make_test_event("E2", "S1", "main", 0),
        ];
        journal.append_batch(events).await.unwrap();

        let head = journal
            .head_seq(
                &SessionId::from_string("S1"),
                &BranchId::from_string("main"),
            )
            .await
            .unwrap();
        assert_eq!(head, 2);
    }

    #[tokio::test]
    async fn test_put_get_session() {
        let dir = tempfile::tempdir().unwrap();
        let journal = LanceJournal::open(dir.path()).await.unwrap();

        let session = make_test_session("S1");
        journal.put_session(session).await.unwrap();

        let retrieved = journal
            .get_session(&SessionId::from_string("S1"))
            .await
            .unwrap();
        assert!(retrieved.is_some());
        let s = retrieved.unwrap();
        assert_eq!(s.session_id.as_str(), "S1");
        assert_eq!(s.config.name, "session-S1");
    }

    #[tokio::test]
    async fn test_put_session_upsert() {
        let dir = tempfile::tempdir().unwrap();
        let journal = LanceJournal::open(dir.path()).await.unwrap();

        let session = make_test_session("S1");
        journal.put_session(session).await.unwrap();

        // Update session.
        let mut updated = make_test_session("S1");
        updated.config = SessionConfig::new("updated-name");
        journal.put_session(updated).await.unwrap();

        let retrieved = journal
            .get_session(&SessionId::from_string("S1"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.config.name, "updated-name");

        // Should still be only one session.
        let all = journal.list_sessions().await.unwrap();
        assert_eq!(all.len(), 1);
    }

    #[tokio::test]
    async fn test_list_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let journal = LanceJournal::open(dir.path()).await.unwrap();

        journal.put_session(make_test_session("S1")).await.unwrap();
        journal.put_session(make_test_session("S2")).await.unwrap();
        journal.put_session(make_test_session("S3")).await.unwrap();

        let sessions = journal.list_sessions().await.unwrap();
        assert_eq!(sessions.len(), 3);

        let ids: Vec<&str> = sessions.iter().map(|s| s.session_id.as_str()).collect();
        assert!(ids.contains(&"S1"));
        assert!(ids.contains(&"S2"));
        assert!(ids.contains(&"S3"));
    }

    #[tokio::test]
    async fn test_read_with_query_filters() {
        let dir = tempfile::tempdir().unwrap();
        let journal = LanceJournal::open(dir.path()).await.unwrap();

        // Write events to two branches.
        let events = vec![
            make_test_event("E1", "S1", "main", 0),
            make_test_event("E2", "S1", "main", 0),
            make_test_event("E3", "S1", "dev", 0),
        ];
        journal.append_batch(events).await.unwrap();

        // Filter by session + branch.
        let main_events = journal
            .read(
                EventQuery::new()
                    .session(SessionId::from_string("S1"))
                    .branch(BranchId::from_string("main")),
            )
            .await
            .unwrap();
        assert_eq!(main_events.len(), 2);

        let dev_events = journal
            .read(
                EventQuery::new()
                    .session(SessionId::from_string("S1"))
                    .branch(BranchId::from_string("dev")),
            )
            .await
            .unwrap();
        assert_eq!(dev_events.len(), 1);
        assert_eq!(dev_events[0].event_id.as_str(), "E3");
    }

    #[tokio::test]
    async fn test_read_after_seq() {
        let dir = tempfile::tempdir().unwrap();
        let journal = LanceJournal::open(dir.path()).await.unwrap();

        let events = vec![
            make_test_event("E1", "S1", "main", 0),
            make_test_event("E2", "S1", "main", 0),
            make_test_event("E3", "S1", "main", 0),
        ];
        journal.append_batch(events).await.unwrap();

        let after_1 = journal
            .read(
                EventQuery::new()
                    .session(SessionId::from_string("S1"))
                    .after(1),
            )
            .await
            .unwrap();
        assert_eq!(after_1.len(), 2);
        assert_eq!(after_1[0].seq, 2);
        assert_eq!(after_1[1].seq, 3);
    }

    #[tokio::test]
    async fn test_get_event() {
        let dir = tempfile::tempdir().unwrap();
        let journal = LanceJournal::open(dir.path()).await.unwrap();

        let event = make_test_event("E42", "S1", "main", 0);
        journal.append(event).await.unwrap();

        let found = journal
            .get_event(&EventId::from_string("E42"))
            .await
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().event_id.as_str(), "E42");

        let missing = journal
            .get_event(&EventId::from_string("NONEXISTENT"))
            .await
            .unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_get_session_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let journal = LanceJournal::open(dir.path()).await.unwrap();

        let result = journal
            .get_session(&SessionId::from_string("NONEXISTENT"))
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_empty_read() {
        let dir = tempfile::tempdir().unwrap();
        let journal = LanceJournal::open(dir.path()).await.unwrap();

        let events = journal.read(EventQuery::new()).await.unwrap();
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn test_append_batch_empty() {
        let dir = tempfile::tempdir().unwrap();
        let journal = LanceJournal::open(dir.path()).await.unwrap();

        let seq = journal.append_batch(vec![]).await.unwrap();
        assert_eq!(seq, 0);
    }

    #[tokio::test]
    async fn test_concurrent_writers() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Arc::new(LanceJournal::open(dir.path()).await.unwrap());

        let j1 = Arc::clone(&journal);
        let j2 = Arc::clone(&journal);

        let h1 = tokio::spawn(async move {
            for i in 0..5 {
                let event = EventEnvelope {
                    event_id: EventId::from_string(format!("A{i}")),
                    session_id: SessionId::from_string("S1"),
                    branch_id: BranchId::from_string("main"),
                    run_id: None,
                    seq: 0,
                    timestamp: 1_700_000_000_000_000 + i,
                    parent_id: None,
                    payload: EventPayload::ErrorRaised {
                        message: format!("writer A event {i}"),
                    },
                    metadata: HashMap::new(),
                    schema_version: 1,
                };
                j1.append(event).await.unwrap();
            }
        });

        let h2 = tokio::spawn(async move {
            for i in 0..5 {
                let event = EventEnvelope {
                    event_id: EventId::from_string(format!("B{i}")),
                    session_id: SessionId::from_string("S1"),
                    branch_id: BranchId::from_string("main"),
                    run_id: None,
                    seq: 0,
                    timestamp: 1_700_000_000_000_000 + i + 100,
                    parent_id: None,
                    payload: EventPayload::ErrorRaised {
                        message: format!("writer B event {i}"),
                    },
                    metadata: HashMap::new(),
                    schema_version: 1,
                };
                j2.append(event).await.unwrap();
            }
        });

        h1.await.unwrap();
        h2.await.unwrap();

        let all_events = journal.read(EventQuery::new()).await.unwrap();
        assert_eq!(all_events.len(), 10);

        // Verify all sequence numbers are unique.
        let seqs: std::collections::HashSet<SeqNo> = all_events.iter().map(|e| e.seq).collect();
        assert_eq!(seqs.len(), 10);
    }

    #[tokio::test]
    async fn test_read_with_limit() {
        let dir = tempfile::tempdir().unwrap();
        let journal = LanceJournal::open(dir.path()).await.unwrap();

        let events = vec![
            make_test_event("E1", "S1", "main", 0),
            make_test_event("E2", "S1", "main", 0),
            make_test_event("E3", "S1", "main", 0),
        ];
        journal.append_batch(events).await.unwrap();

        let limited = journal.read(EventQuery::new().limit(2)).await.unwrap();
        assert_eq!(limited.len(), 2);
    }
}
