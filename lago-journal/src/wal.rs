//! Write-ahead log buffer that batches events before flushing to the journal.
//!
//! The WAL provides two mechanisms for flushing:
//! 1. **Threshold flush** — when the buffer reaches a configurable size (default 100)
//! 2. **Interval flush** — a background task flushes on a timer (default 50ms)
//!
//! This amortizes the cost of redb write transactions across multiple events.

use std::sync::Arc;

use tokio::sync::Mutex;
use tokio::time::{self, Duration};
use tracing::{debug, warn};

use lago_core::{EventEnvelope, Journal, LagoResult, SeqNo};

/// Default number of events before an automatic flush.
const DEFAULT_FLUSH_THRESHOLD: usize = 100;

/// Default interval between background flushes.
const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_millis(50);

/// A write-ahead log that buffers events and flushes them to a Journal in batches.
pub struct Wal<J: Journal> {
    journal: Arc<J>,
    buffer: Arc<Mutex<Vec<EventEnvelope>>>,
    flush_threshold: usize,
    flush_interval: Duration,
}

impl<J: Journal + 'static> Wal<J> {
    /// Create a new WAL with default settings.
    pub fn new(journal: Arc<J>) -> Self {
        Self {
            journal,
            buffer: Arc::new(Mutex::new(Vec::new())),
            flush_threshold: DEFAULT_FLUSH_THRESHOLD,
            flush_interval: DEFAULT_FLUSH_INTERVAL,
        }
    }

    /// Create a new WAL with custom threshold and interval.
    pub fn with_config(journal: Arc<J>, flush_threshold: usize, flush_interval: Duration) -> Self {
        Self {
            journal,
            buffer: Arc::new(Mutex::new(Vec::new())),
            flush_threshold,
            flush_interval,
        }
    }

    /// Push an event into the buffer. If the threshold is reached, the buffer
    /// is flushed immediately.
    pub async fn push(&self, event: EventEnvelope) -> LagoResult<Option<SeqNo>> {
        let should_flush;
        {
            let mut buf = self.buffer.lock().await;
            buf.push(event);
            should_flush = buf.len() >= self.flush_threshold;
        }

        if should_flush {
            let seq = self.flush().await?;
            Ok(Some(seq))
        } else {
            Ok(None)
        }
    }

    /// Flush all buffered events to the underlying journal.
    ///
    /// Returns the last sequence number written, or 0 if the buffer was empty.
    pub async fn flush(&self) -> LagoResult<SeqNo> {
        let events = {
            let mut buf = self.buffer.lock().await;
            if buf.is_empty() {
                return Ok(0);
            }
            std::mem::take(&mut *buf)
        };

        let count = events.len();
        let seq = self.journal.append_batch(events).await?;
        debug!(count, seq, "WAL flushed events");
        Ok(seq)
    }

    /// Return the current number of buffered (unflushed) events.
    pub async fn buffered_count(&self) -> usize {
        self.buffer.lock().await.len()
    }

    /// Spawn a background task that periodically flushes the buffer.
    ///
    /// Returns a `tokio::task::JoinHandle` that can be used to abort the task.
    /// The task runs until the handle is dropped/aborted or the runtime shuts down.
    pub fn spawn_flush_task(&self) -> tokio::task::JoinHandle<()> {
        let journal = Arc::clone(&self.journal);
        let buffer = Arc::clone(&self.buffer);
        let interval_dur = self.flush_interval;

        tokio::spawn(async move {
            let mut interval = time::interval(interval_dur);
            // The first tick completes immediately; skip it.
            interval.tick().await;

            loop {
                interval.tick().await;

                let events = {
                    let mut buf = buffer.lock().await;
                    if buf.is_empty() {
                        continue;
                    }
                    std::mem::take(&mut *buf)
                };

                let count = events.len();
                match journal.append_batch(events).await {
                    Ok(seq) => {
                        debug!(count, seq, "WAL background flush");
                    }
                    Err(e) => {
                        warn!(error = %e, count, "WAL background flush failed");
                        // Events are lost if the journal fails. In production
                        // you would want retry logic or a persistent WAL file.
                    }
                }
            }
        })
    }
}
