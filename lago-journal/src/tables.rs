//! redb table definitions for the Lago event journal.
//!
//! Key layout:
//! - EVENTS:      compound key (session_id 26B + branch_id 26B + seq 8B BE) -> JSON event
//! - EVENT_INDEX: event_id string -> compound key bytes (for O(1) lookup)
//! - BRANCH_HEADS: compound key (session_id 26B + branch_id 26B) -> head seq (u64)
//! - SESSIONS:    session_id string -> JSON Session
//! - SNAPSHOTS:   snapshot_id string -> serialized snapshot bytes

use redb::TableDefinition;

/// Events table: compound key -> JSON-serialized EventEnvelope.
///
/// The compound key is 60 bytes: session_id (26B) + branch_id (26B) + seq (8B big-endian).
/// This layout gives lexicographic ordering that naturally groups events by
/// session, then branch, then sequence number.
pub const EVENTS: TableDefinition<&[u8], &str> = TableDefinition::new("events");

/// Event index table: event_id -> compound key bytes.
///
/// Enables O(1) lookup of any event by its unique EventId without scanning.
pub const EVENT_INDEX: TableDefinition<&str, &[u8]> = TableDefinition::new("event_index");

/// Branch heads table: (session_id + branch_id) -> current head sequence number.
///
/// The key is 52 bytes: session_id (26B) + branch_id (26B).
pub const BRANCH_HEADS: TableDefinition<&[u8], u64> = TableDefinition::new("branch_heads");

/// Sessions table: session_id -> JSON-serialized Session.
pub const SESSIONS: TableDefinition<&str, &str> = TableDefinition::new("sessions");

/// Snapshots table: snapshot_id -> serialized snapshot data.
pub const SNAPSHOTS: TableDefinition<&str, &[u8]> = TableDefinition::new("snapshots");
