//! lago-journal — Event journal backed by redb.
//!
//! This crate provides the primary persistence layer for Lago's event-sourced
//! architecture. Events are stored in a redb embedded database with compound
//! keys that enable efficient range scans by session, branch, and sequence
//! number.
//!
//! # Key Components
//!
//! - [`RedbJournal`] — implements the `Journal` trait from lago-core
//! - [`Wal`] — write-ahead log buffer for batching events
//! - [`EventTailStream`] — async Stream for tailing new events
//! - Snapshot helpers for fast session restoration

pub mod keys;
pub mod redb_journal;
pub mod snapshot;
pub mod stream;
pub mod tables;
pub mod wal;

pub use redb_journal::{EventNotification, RedbJournal};
pub use snapshot::{SNAPSHOT_THRESHOLD, create_snapshot, load_snapshot, should_snapshot};
pub use stream::EventTailStream;
pub use wal::Wal;
