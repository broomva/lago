//! Snapshot creation and loading for the event journal.
//!
//! A snapshot captures all events in a session+branch up to the current head
//! as a serialized JSON array. This allows fast session restoration without
//! replaying the full event history.

use lago_core::{BranchId, EventEnvelope, EventQuery, Journal, LagoResult, SeqNo, SessionId};

/// Number of events after which a snapshot is recommended.
pub const SNAPSHOT_THRESHOLD: u64 = 1000;

/// Create a snapshot of all events for a given session and branch, up to
/// the current head sequence number.
///
/// Returns the serialized snapshot data (JSON array of EventEnvelope) and
/// the sequence number through which the snapshot covers.
pub async fn create_snapshot<J: Journal>(
    journal: &J,
    session_id: &SessionId,
    branch_id: &BranchId,
) -> LagoResult<(Vec<u8>, SeqNo)> {
    let head = journal.head_seq(session_id, branch_id).await?;

    let query = EventQuery::new()
        .session(session_id.clone())
        .branch(branch_id.clone());

    let events = journal.read(query).await?;
    let data = serde_json::to_vec(&events)?;

    Ok((data, head))
}

/// Load a snapshot from serialized bytes back into a vector of EventEnvelopes.
pub fn load_snapshot(data: &[u8]) -> LagoResult<Vec<EventEnvelope>> {
    let events: Vec<EventEnvelope> = serde_json::from_slice(data)?;
    Ok(events)
}

/// Check whether a snapshot should be created based on the current head
/// sequence number. Returns true if head >= SNAPSHOT_THRESHOLD.
pub fn should_snapshot(head_seq: SeqNo) -> bool {
    head_seq >= SNAPSHOT_THRESHOLD
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_threshold_check() {
        assert!(!should_snapshot(0));
        assert!(!should_snapshot(999));
        assert!(should_snapshot(1000));
        assert!(should_snapshot(5000));
    }

    #[test]
    fn load_empty_snapshot() {
        let data = b"[]";
        let events = load_snapshot(data).unwrap();
        assert!(events.is_empty());
    }
}
