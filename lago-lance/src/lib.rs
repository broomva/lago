//! `lago-lance` — Lance-backed storage for the Lago event journal.
//!
//! This crate provides [`LanceJournal`], an implementation of the
//! [`lago_core::Journal`] trait backed by [Lance](https://lancedb.github.io/lance/)
//! columnar datasets. Events and sessions are stored as Arrow `RecordBatch`es
//! in separate Lance datasets under a base directory.
//!
//! # Architecture
//!
//! ```text
//! <base_path>/
//! ├── events.lance/    — EventEnvelope rows (append-only)
//! └── sessions.lance/  — Session rows (upsert via overwrite)
//! ```
//!
//! Lance is async-native, so unlike the redb-backed journal, no
//! `spawn_blocking` is required.
//!
//! # Usage
//!
//! ```rust,no_run
//! use lago_lance::LanceJournal;
//!
//! # async fn example() -> lago_core::LagoResult<()> {
//! let journal = LanceJournal::open("/tmp/lago-lance-data").await?;
//! // Use journal as `Arc<dyn lago_core::Journal>`
//! # Ok(())
//! # }
//! ```

pub mod convert;
pub mod journal;
pub mod schema;

pub use convert::EMBEDDING_META_KEY;
pub use journal::LanceJournal;
pub use schema::EMBEDDING_DIM;
