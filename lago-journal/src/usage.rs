//! Usage metering counters for billing dimensions.
//!
//! Tracks four billing dimensions per session with hourly bucket granularity:
//! - **Events**: incremented on each journal append
//! - **StorageBytes**: incremented by original uncompressed size on blob put
//! - **ApiCalls**: incremented per HTTP request
//! - **EgressBytes**: incremented by bytes served via REST/SSE blob reads
//!
//! Counters are stored atomically in the same redb write transaction as the
//! operation they meter, ensuring zero drift between events and usage records.

use redb::{Database, ReadableTable};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use lago_core::{LagoError, LagoResult, SessionId};

use crate::keys::{decode_usage_key, encode_usage_key, USAGE_KEY_LEN};
use crate::tables::USAGE;

// ─── UsageDimension ──────────────────────────────────────────────────────────

/// The four metered billing dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageDimension {
    /// Number of events ingested into the journal.
    Events,
    /// Total uncompressed bytes stored in the blob store.
    StorageBytes,
    /// Number of API calls served.
    ApiCalls,
    /// Total bytes served via blob reads (REST + SSE egress).
    EgressBytes,
}

impl UsageDimension {
    /// Encode as a single discriminant byte for the compound key.
    pub fn as_byte(self) -> u8 {
        match self {
            Self::Events => 0,
            Self::StorageBytes => 1,
            Self::ApiCalls => 2,
            Self::EgressBytes => 3,
        }
    }

    /// Decode from the discriminant byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Events),
            1 => Some(Self::StorageBytes),
            2 => Some(Self::ApiCalls),
            3 => Some(Self::EgressBytes),
            _ => None,
        }
    }

    /// All four dimensions, useful for iteration.
    pub fn all() -> [Self; 4] {
        [
            Self::Events,
            Self::StorageBytes,
            Self::ApiCalls,
            Self::EgressBytes,
        ]
    }
}

impl std::fmt::Display for UsageDimension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Events => write!(f, "events"),
            Self::StorageBytes => write!(f, "storage_bytes"),
            Self::ApiCalls => write!(f, "api_calls"),
            Self::EgressBytes => write!(f, "egress_bytes"),
        }
    }
}

// ─── UsageRecord ─────────────────────────────────────────────────────────────

/// A single usage counter record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRecord {
    pub session_id: SessionId,
    pub dimension: UsageDimension,
    /// Hourly bucket: Unix seconds truncated to the hour (unix_secs / 3600 * 3600).
    pub period: u64,
    /// Accumulated counter value.
    pub count: u64,
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Truncate a Unix-seconds timestamp to the start of its hour.
pub fn hourly_bucket(unix_secs: u64) -> u64 {
    unix_secs / 3600 * 3600
}

/// Return the current hourly bucket.
pub fn current_bucket() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    hourly_bucket(now)
}

// ─── Blocking operations (called via spawn_blocking) ─────────────────────────

/// Atomically increment a usage counter within an **existing** write transaction.
///
/// This is the hot-path function called inside `append_batch_blocking` and
/// similar write paths. It opens the USAGE table on the given transaction
/// and performs a read-modify-write to increment the counter.
///
/// # Arguments
/// * `usage_table` — a mutable reference to the opened USAGE table
/// * `session_id` — the session to meter
/// * `dimension` — which billing dimension
/// * `period` — hourly bucket (pre-computed by caller)
/// * `delta` — amount to add
pub fn increment_usage_in_txn(
    usage_table: &mut redb::Table<&[u8], u64>,
    session_id: &str,
    dimension: UsageDimension,
    period: u64,
    delta: u64,
) -> LagoResult<()> {
    let key = encode_usage_key(session_id, dimension.as_byte(), period);
    let current = usage_table
        .get(key.as_slice())
        .map_err(|e| LagoError::Journal(format!("get usage counter: {e}")))?
        .map(|v| v.value())
        .unwrap_or(0);
    usage_table
        .insert(key.as_slice(), current.saturating_add(delta))
        .map_err(|e| LagoError::Journal(format!("insert usage counter: {e}")))?;
    Ok(())
}

/// Query usage records for a single session within a time range.
///
/// Returns all records where `from <= period <= to` for the given session.
/// If `dimension` is `Some`, filters to that dimension only.
pub fn query_session_usage_blocking(
    db: &Database,
    session_id: &str,
    dimension: Option<UsageDimension>,
    from: u64,
    to: u64,
) -> LagoResult<Vec<UsageRecord>> {
    let txn = db
        .begin_read()
        .map_err(|e| LagoError::Journal(format!("begin_read failed: {e}")))?;
    let table = txn
        .open_table(USAGE)
        .map_err(|e| LagoError::Journal(format!("open usage table: {e}")))?;

    let mut records = Vec::new();

    // Scan each requested dimension
    let dims: Vec<UsageDimension> = match dimension {
        Some(d) => vec![d],
        None => UsageDimension::all().to_vec(),
    };

    for dim in dims {
        let start = encode_usage_key(session_id, dim.as_byte(), from);
        let end = encode_usage_key(session_id, dim.as_byte(), to);

        let range = table
            .range(start.as_slice()..=end.as_slice())
            .map_err(|e| LagoError::Journal(format!("usage range scan: {e}")))?;

        for item in range {
            let (key_guard, value_guard) =
                item.map_err(|e| LagoError::Journal(format!("usage range item: {e}")))?;
            let key_bytes = key_guard.value();
            if key_bytes.len() != USAGE_KEY_LEN {
                continue;
            }
            let (sid, dim_byte, period) = decode_usage_key(key_bytes);
            let Some(dimension) = UsageDimension::from_byte(dim_byte) else {
                continue;
            };
            records.push(UsageRecord {
                session_id: SessionId::from_string(sid),
                dimension,
                period,
                count: value_guard.value(),
            });
        }
    }

    Ok(records)
}

/// Query aggregated usage summary across all sessions within a time range.
///
/// Returns records grouped by session + dimension, with counts summed
/// across all hourly buckets in the range.
pub fn query_usage_summary_blocking(
    db: &Database,
    from: u64,
    to: u64,
) -> LagoResult<Vec<UsageRecord>> {
    let txn = db
        .begin_read()
        .map_err(|e| LagoError::Journal(format!("begin_read failed: {e}")))?;
    let table = txn
        .open_table(USAGE)
        .map_err(|e| LagoError::Journal(format!("open usage table: {e}")))?;

    // Aggregate: key = (session_id, dimension) -> total count
    let mut agg: std::collections::HashMap<(String, u8), u64> = std::collections::HashMap::new();

    let range = table
        .iter()
        .map_err(|e| LagoError::Journal(format!("usage iter: {e}")))?;

    for item in range {
        let (key_guard, value_guard) =
            item.map_err(|e| LagoError::Journal(format!("usage iter item: {e}")))?;
        let key_bytes = key_guard.value();
        if key_bytes.len() != USAGE_KEY_LEN {
            continue;
        }
        let (sid, dim_byte, period) = decode_usage_key(key_bytes);
        if period < from || period > to {
            continue;
        }
        *agg.entry((sid, dim_byte)).or_insert(0) += value_guard.value();
    }

    let mut records: Vec<UsageRecord> = agg
        .into_iter()
        .filter_map(|((sid, dim_byte), count)| {
            let dimension = UsageDimension::from_byte(dim_byte)?;
            Some(UsageRecord {
                session_id: SessionId::from_string(sid),
                dimension,
                period: 0, // Aggregated — no single period
                count,
            })
        })
        .collect();

    // Sort by session_id then dimension for deterministic output
    records.sort_by(|a, b| {
        a.session_id
            .as_str()
            .cmp(b.session_id.as_str())
            .then(a.dimension.as_byte().cmp(&b.dimension.as_byte()))
    });

    Ok(records)
}

// ─── Async wrappers ──────────────────────────────────────────────────────────

/// Increment a usage counter (standalone, not inside an existing transaction).
///
/// Use this for operations that don't already have an open write transaction
/// (e.g., API call counting, egress metering in response handlers).
pub async fn increment_usage(
    db: Arc<Database>,
    session_id: String,
    dimension: UsageDimension,
    delta: u64,
) -> LagoResult<()> {
    tokio::task::spawn_blocking(move || {
        let period = current_bucket();
        let txn = db
            .begin_write()
            .map_err(|e| LagoError::Journal(format!("begin_write failed: {e}")))?;
        {
            let mut table = txn
                .open_table(USAGE)
                .map_err(|e| LagoError::Journal(format!("open usage table: {e}")))?;
            increment_usage_in_txn(&mut table, &session_id, dimension, period, delta)?;
        }
        txn.commit()
            .map_err(|e| LagoError::Journal(format!("commit failed: {e}")))?;
        Ok(())
    })
    .await
    .map_err(|e| LagoError::Journal(format!("spawn_blocking join error: {e}")))?
}

/// Query usage for a single session.
pub async fn query_session_usage(
    db: Arc<Database>,
    session_id: String,
    dimension: Option<UsageDimension>,
    from: u64,
    to: u64,
) -> LagoResult<Vec<UsageRecord>> {
    tokio::task::spawn_blocking(move || {
        query_session_usage_blocking(&db, &session_id, dimension, from, to)
    })
    .await
    .map_err(|e| LagoError::Journal(format!("spawn_blocking join error: {e}")))?
}

/// Query aggregated usage summary across all sessions.
pub async fn query_usage_summary(
    db: Arc<Database>,
    from: u64,
    to: u64,
) -> LagoResult<Vec<UsageRecord>> {
    tokio::task::spawn_blocking(move || query_usage_summary_blocking(&db, from, to))
        .await
        .map_err(|e| LagoError::Journal(format!("spawn_blocking join error: {e}")))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use redb::Database;
    use tempfile::TempDir;

    fn setup() -> (TempDir, Database) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("test_usage.redb");
        let db = Database::create(&db_path).unwrap();
        // Create the usage table
        {
            let txn = db.begin_write().unwrap();
            { txn.open_table(USAGE).unwrap(); }
            txn.commit().unwrap();
        }
        (dir, db)
    }

    /// Helper: open a write transaction, run increments, commit.
    fn write_usage(db: &Database, ops: &[(& str, UsageDimension, u64, u64)]) {
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(USAGE).unwrap();
            for (sid, dim, period, delta) in ops {
                increment_usage_in_txn(&mut table, sid, *dim, *period, *delta).unwrap();
            }
        }
        txn.commit().unwrap();
    }

    #[test]
    fn dimension_byte_roundtrip() {
        for dim in UsageDimension::all() {
            assert_eq!(UsageDimension::from_byte(dim.as_byte()), Some(dim));
        }
        assert_eq!(UsageDimension::from_byte(255), None);
    }

    #[test]
    fn hourly_bucket_truncates() {
        // 1699933800 / 3600 = 472203 -> 472203 * 3600 = 1699930800
        assert_eq!(hourly_bucket(1699933800), 1699930800);
        // Exact hour boundary
        assert_eq!(hourly_bucket(3600), 3600);
        // Zero
        assert_eq!(hourly_bucket(0), 0);
        // One second before next hour
        assert_eq!(hourly_bucket(7199), 3600);
    }

    #[test]
    fn increment_and_query() {
        let (_dir, db) = setup();
        let sid = "01HQJG5B8P9RJXK7M3N4T6W2YA";
        let period = 3600u64;

        // Increment events counter by 5
        write_usage(&db, &[(sid, UsageDimension::Events, period, 5)]);
        // Increment again by 3
        write_usage(&db, &[(sid, UsageDimension::Events, period, 3)]);

        // Query
        let records = query_session_usage_blocking(&db, sid, None, 0, u64::MAX).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].count, 8);
        assert_eq!(records[0].dimension, UsageDimension::Events);
        assert_eq!(records[0].period, period);
    }

    #[test]
    fn multiple_dimensions() {
        let (_dir, db) = setup();
        let sid = "01HQJG5B8P9RJXK7M3N4T6W2YA";
        let period = 7200u64;

        write_usage(&db, &[
            (sid, UsageDimension::Events, period, 10),
            (sid, UsageDimension::StorageBytes, period, 1024),
            (sid, UsageDimension::ApiCalls, period, 3),
            (sid, UsageDimension::EgressBytes, period, 2048),
        ]);

        let records = query_session_usage_blocking(&db, sid, None, 0, u64::MAX).unwrap();
        assert_eq!(records.len(), 4);

        // Filter by specific dimension
        let events_only = query_session_usage_blocking(
            &db,
            sid,
            Some(UsageDimension::Events),
            0,
            u64::MAX,
        )
        .unwrap();
        assert_eq!(events_only.len(), 1);
        assert_eq!(events_only[0].count, 10);
    }

    #[test]
    fn time_range_filtering() {
        let (_dir, db) = setup();
        let sid = "01HQJG5B8P9RJXK7M3N4T6W2YA";

        // Insert across 3 hourly buckets
        write_usage(&db, &[
            (sid, UsageDimension::Events, 3600, 1),
            (sid, UsageDimension::Events, 7200, 2),
            (sid, UsageDimension::Events, 10800, 3),
        ]);

        // Query middle bucket only
        let records = query_session_usage_blocking(
            &db,
            sid,
            Some(UsageDimension::Events),
            7200,
            7200,
        )
        .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].count, 2);

        // Query first two buckets
        let records = query_session_usage_blocking(
            &db,
            sid,
            Some(UsageDimension::Events),
            3600,
            7200,
        )
        .unwrap();
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn summary_across_sessions() {
        let (_dir, db) = setup();

        write_usage(&db, &[
            ("S1", UsageDimension::Events, 3600, 10),
            ("S1", UsageDimension::Events, 7200, 20),
            ("S2", UsageDimension::Events, 3600, 5),
            ("S2", UsageDimension::StorageBytes, 3600, 1024),
        ]);

        let summary = query_usage_summary_blocking(&db, 0, u64::MAX).unwrap();
        // S1: Events=30, S2: Events=5, S2: StorageBytes=1024
        assert_eq!(summary.len(), 3);

        let s1_events = summary
            .iter()
            .find(|r| r.session_id.as_str() == "S1" && r.dimension == UsageDimension::Events)
            .unwrap();
        assert_eq!(s1_events.count, 30);

        let s2_storage = summary
            .iter()
            .find(|r| {
                r.session_id.as_str() == "S2" && r.dimension == UsageDimension::StorageBytes
            })
            .unwrap();
        assert_eq!(s2_storage.count, 1024);
    }

    #[test]
    fn dimension_display() {
        assert_eq!(UsageDimension::Events.to_string(), "events");
        assert_eq!(UsageDimension::StorageBytes.to_string(), "storage_bytes");
        assert_eq!(UsageDimension::ApiCalls.to_string(), "api_calls");
        assert_eq!(UsageDimension::EgressBytes.to_string(), "egress_bytes");
    }

    #[test]
    fn dimension_serde_roundtrip() {
        let dim = UsageDimension::StorageBytes;
        let json = serde_json::to_string(&dim).unwrap();
        assert_eq!(json, "\"storage_bytes\"");
        let back: UsageDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(back, dim);
    }

    #[test]
    fn usage_record_serde_roundtrip() {
        let record = UsageRecord {
            session_id: SessionId::from_string("S1"),
            dimension: UsageDimension::Events,
            period: 3600,
            count: 42,
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: UsageRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.count, 42);
        assert_eq!(back.dimension, UsageDimension::Events);
        assert_eq!(back.period, 3600);
    }
}
