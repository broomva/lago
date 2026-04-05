//! Async Stream adapter for tailing new events from the journal.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::Stream;
use redb::Database;
use tokio::sync::broadcast;

use lago_core::{BranchId, EventEnvelope, LagoError, LagoResult, SeqNo, SessionId};

use crate::keys::encode_event_key;
use crate::redb_journal::EventNotification;
use crate::tables::EVENTS;

/// A tailing stream that yields new events as they are appended to the journal.
///
/// Uses a broadcast receiver to be notified when new events arrive, then reads
/// from the database to fetch the actual event data. This avoids polling and
/// provides near-real-time event delivery.
pub struct EventTailStream {
    db: Arc<Database>,
    rx: broadcast::Receiver<EventNotification>,
    session_id: SessionId,
    branch_id: BranchId,
    /// The last sequence number we have yielded. We only yield events with seq > last_seq.
    last_seq: SeqNo,
    /// Buffer of events fetched from the DB but not yet yielded.
    buffer: std::collections::VecDeque<EventEnvelope>,
    /// Whether we have been notified of new events but haven't fetched them yet.
    pending_fetch: bool,
}

impl EventTailStream {
    pub fn new(
        db: Arc<Database>,
        rx: broadcast::Receiver<EventNotification>,
        session_id: SessionId,
        branch_id: BranchId,
        after_seq: SeqNo,
    ) -> Self {
        Self {
            db,
            rx,
            session_id,
            branch_id,
            last_seq: after_seq,
            buffer: std::collections::VecDeque::new(),
            pending_fetch: false,
        }
    }

    /// Fetch new events from the database for our session/branch after last_seq.
    fn fetch_new_events(&self) -> LagoResult<Vec<EventEnvelope>> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| LagoError::Journal(format!("begin_read failed: {e}")))?;
        let table = txn
            .open_table(EVENTS)
            .map_err(|e| LagoError::Journal(format!("open events table: {e}")))?;

        let start_seq = self.last_seq + 1;
        let start_key =
            encode_event_key(self.session_id.as_str(), self.branch_id.as_str(), start_seq);
        let end_key = encode_event_key(self.session_id.as_str(), self.branch_id.as_str(), u64::MAX);

        let range = table
            .range(start_key.as_slice()..=end_key.as_slice())
            .map_err(|e| LagoError::Journal(format!("range scan: {e}")))?;

        let mut events = Vec::new();
        for item in range {
            let (_, value) = item.map_err(|e| LagoError::Journal(format!("range item: {e}")))?;
            let envelope: EventEnvelope = serde_json::from_str(value.value())?;
            events.push(envelope);
        }
        Ok(events)
    }
}

impl Stream for EventTailStream {
    type Item = LagoResult<EventEnvelope>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // First, drain the buffer
        if let Some(event) = self.buffer.pop_front() {
            self.last_seq = event.seq;
            return Poll::Ready(Some(Ok(event)));
        }

        // If we have a pending fetch, do it now
        if self.pending_fetch {
            self.pending_fetch = false;
            match self.fetch_new_events() {
                Ok(events) => {
                    for event in events {
                        self.buffer.push_back(event);
                    }
                    if let Some(event) = self.buffer.pop_front() {
                        self.last_seq = event.seq;
                        return Poll::Ready(Some(Ok(event)));
                    }
                }
                Err(e) => return Poll::Ready(Some(Err(e))),
            }
        }

        // Poll the broadcast receiver for notifications
        loop {
            match self.rx.try_recv() {
                Ok(notification) => {
                    // Only care about notifications for our session+branch
                    if notification.session_id.as_str() == self.session_id.as_str()
                        && notification.branch_id.as_str() == self.branch_id.as_str()
                        && notification.seq > self.last_seq
                    {
                        // Fetch new events from the DB
                        match self.fetch_new_events() {
                            Ok(events) => {
                                for event in events {
                                    self.buffer.push_back(event);
                                }
                                if let Some(event) = self.buffer.pop_front() {
                                    self.last_seq = event.seq;
                                    return Poll::Ready(Some(Ok(event)));
                                }
                            }
                            Err(e) => return Poll::Ready(Some(Err(e))),
                        }
                    }
                }
                Err(broadcast::error::TryRecvError::Empty) => {
                    // No notifications available; register waker and return Pending.
                    // We use a small trick: spawn a task that awaits the receiver
                    // and wakes us. This is necessary because broadcast::Receiver
                    // doesn't directly implement poll-based APIs in a way compatible
                    // with Stream.
                    let waker = cx.waker().clone();
                    let mut rx_clone = self.rx.resubscribe();
                    let session_id = self.session_id.clone();
                    let branch_id = self.branch_id.clone();
                    let last_seq = self.last_seq;
                    self.pending_fetch = false;

                    tokio::spawn(async move {
                        // Wait for any notification, then wake the stream
                        loop {
                            match rx_clone.recv().await {
                                Ok(n) => {
                                    if n.session_id.as_str() == session_id.as_str()
                                        && n.branch_id.as_str() == branch_id.as_str()
                                        && n.seq > last_seq
                                    {
                                        break;
                                    }
                                }
                                Err(broadcast::error::RecvError::Lagged(_)) => {
                                    // Missed some notifications, wake anyway
                                    break;
                                }
                                Err(broadcast::error::RecvError::Closed) => {
                                    // Channel closed, wake to let stream return None eventually
                                    break;
                                }
                            }
                        }
                        waker.wake();
                    });

                    // Mark that we should fetch when woken
                    self.pending_fetch = true;
                    return Poll::Pending;
                }
                Err(broadcast::error::TryRecvError::Closed) => {
                    // Channel closed, stream is done
                    return Poll::Ready(None);
                }
                Err(broadcast::error::TryRecvError::Lagged(_)) => {
                    // We missed some notifications; fetch whatever is new
                    match self.fetch_new_events() {
                        Ok(events) => {
                            for event in events {
                                self.buffer.push_back(event);
                            }
                            if let Some(event) = self.buffer.pop_front() {
                                self.last_seq = event.seq;
                                return Poll::Ready(Some(Ok(event)));
                            }
                            // No new events despite lag notification; continue polling
                        }
                        Err(e) => return Poll::Ready(Some(Err(e))),
                    }
                }
            }
        }
    }
}
