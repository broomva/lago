//! Conversions between Lago domain types and Arrow `RecordBatch`.

use std::collections::HashMap;
use std::sync::Arc;

use arrow_array::{
    Array, RecordBatch, StringArray, UInt8Array, UInt64Array,
    builder::{StringBuilder, UInt8Builder, UInt64Builder},
};

use lago_core::event::EventEnvelope;
use lago_core::id::{BranchId, EventId, RunId, SessionId};
use lago_core::session::{Session, SessionConfig};

use crate::schema::{event_schema, session_schema};

/// Convert a slice of `EventEnvelope` into an Arrow `RecordBatch`.
pub fn events_to_batch(events: &[EventEnvelope]) -> Result<RecordBatch, arrow::error::ArrowError> {
    let schema = Arc::new(event_schema());
    let len = events.len();

    let mut event_id_builder = StringBuilder::with_capacity(len, len * 26);
    let mut session_id_builder = StringBuilder::with_capacity(len, len * 26);
    let mut branch_id_builder = StringBuilder::with_capacity(len, len * 26);
    let mut run_id_builder = StringBuilder::with_capacity(len, len * 26);
    let mut seq_builder = UInt64Builder::with_capacity(len);
    let mut timestamp_builder = UInt64Builder::with_capacity(len);
    let mut parent_id_builder = StringBuilder::with_capacity(len, len * 26);
    let mut payload_json_builder = StringBuilder::with_capacity(len, len * 256);
    let mut metadata_json_builder = StringBuilder::with_capacity(len, len * 64);
    let mut schema_version_builder = UInt8Builder::with_capacity(len);

    for event in events {
        event_id_builder.append_value(event.event_id.as_str());
        session_id_builder.append_value(event.session_id.as_str());
        branch_id_builder.append_value(event.branch_id.as_str());

        match &event.run_id {
            Some(rid) => run_id_builder.append_value(rid.as_str()),
            None => run_id_builder.append_null(),
        }

        seq_builder.append_value(event.seq);
        timestamp_builder.append_value(event.timestamp);

        match &event.parent_id {
            Some(pid) => parent_id_builder.append_value(pid.as_str()),
            None => parent_id_builder.append_null(),
        }

        let payload_json =
            serde_json::to_string(&event.payload).unwrap_or_else(|_| "{}".to_string());
        payload_json_builder.append_value(&payload_json);

        if event.metadata.is_empty() {
            metadata_json_builder.append_null();
        } else {
            let meta_json =
                serde_json::to_string(&event.metadata).unwrap_or_else(|_| "{}".to_string());
            metadata_json_builder.append_value(&meta_json);
        }

        schema_version_builder.append_value(event.schema_version);
    }

    RecordBatch::try_new(
        schema,
        vec![
            Arc::new(event_id_builder.finish()),
            Arc::new(session_id_builder.finish()),
            Arc::new(branch_id_builder.finish()),
            Arc::new(run_id_builder.finish()),
            Arc::new(seq_builder.finish()),
            Arc::new(timestamp_builder.finish()),
            Arc::new(parent_id_builder.finish()),
            Arc::new(payload_json_builder.finish()),
            Arc::new(metadata_json_builder.finish()),
            Arc::new(schema_version_builder.finish()),
        ],
    )
}

/// Convert an Arrow `RecordBatch` back into a `Vec<EventEnvelope>`.
///
/// The batch must conform to the schema returned by [`event_schema`](crate::schema::event_schema).
pub fn batch_to_events(batch: &RecordBatch) -> Vec<EventEnvelope> {
    let event_ids = batch
        .column(0)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("event_id column must be StringArray");
    let session_ids = batch
        .column(1)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("session_id column must be StringArray");
    let branch_ids = batch
        .column(2)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("branch_id column must be StringArray");
    let run_ids = batch
        .column(3)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("run_id column must be StringArray");
    let seqs = batch
        .column(4)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .expect("seq column must be UInt64Array");
    let timestamps = batch
        .column(5)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .expect("timestamp column must be UInt64Array");
    let parent_ids = batch
        .column(6)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("parent_id column must be StringArray");
    let payload_jsons = batch
        .column(7)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("payload_json column must be StringArray");
    let metadata_jsons = batch
        .column(8)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("metadata_json column must be StringArray");
    let schema_versions = batch
        .column(9)
        .as_any()
        .downcast_ref::<UInt8Array>()
        .expect("schema_version column must be UInt8Array");

    let mut results = Vec::with_capacity(batch.num_rows());

    for i in 0..batch.num_rows() {
        let run_id = if run_ids.is_null(i) {
            None
        } else {
            Some(RunId::from_string(run_ids.value(i)))
        };

        let parent_id = if parent_ids.is_null(i) {
            None
        } else {
            Some(EventId::from_string(parent_ids.value(i)))
        };

        let payload = serde_json::from_str(payload_jsons.value(i))
            .expect("payload_json must be valid EventPayload JSON");

        let metadata: HashMap<String, String> = if metadata_jsons.is_null(i) {
            HashMap::new()
        } else {
            serde_json::from_str(metadata_jsons.value(i)).unwrap_or_default()
        };

        results.push(EventEnvelope {
            event_id: EventId::from_string(event_ids.value(i)),
            session_id: SessionId::from_string(session_ids.value(i)),
            branch_id: BranchId::from_string(branch_ids.value(i)),
            run_id,
            seq: seqs.value(i),
            timestamp: timestamps.value(i),
            parent_id,
            payload,
            metadata,
            schema_version: schema_versions.value(i),
        });
    }

    results
}

/// Convert a `Session` into an Arrow `RecordBatch` with one row.
pub fn session_to_batch(session: &Session) -> Result<RecordBatch, arrow::error::ArrowError> {
    let schema = Arc::new(session_schema());

    let config_json = serde_json::to_string(&session.config).unwrap_or_else(|_| "{}".to_string());
    let branches_json =
        serde_json::to_string(&session.branches).unwrap_or_else(|_| "[]".to_string());

    RecordBatch::try_new(
        schema,
        vec![
            Arc::new(StringArray::from(vec![session.session_id.as_str()])),
            Arc::new(StringArray::from(vec![config_json.as_str()])),
            Arc::new(UInt64Array::from(vec![session.created_at])),
            Arc::new(StringArray::from(vec![branches_json.as_str()])),
        ],
    )
}

/// Convert an Arrow `RecordBatch` back into a `Vec<Session>`.
///
/// The batch must conform to the schema returned by [`session_schema`](crate::schema::session_schema).
pub fn batch_to_sessions(batch: &RecordBatch) -> Vec<Session> {
    let session_ids = batch
        .column(0)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("session_id column must be StringArray");
    let config_jsons = batch
        .column(1)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("config_json column must be StringArray");
    let created_ats = batch
        .column(2)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .expect("created_at column must be UInt64Array");
    let branches_jsons = batch
        .column(3)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("branches_json column must be StringArray");

    let mut results = Vec::with_capacity(batch.num_rows());

    for i in 0..batch.num_rows() {
        let config: SessionConfig =
            serde_json::from_str(config_jsons.value(i)).expect("config_json must be valid JSON");
        let branches: Vec<BranchId> = serde_json::from_str(branches_jsons.value(i))
            .expect("branches_json must be valid JSON");

        results.push(Session {
            session_id: SessionId::from_string(session_ids.value(i)),
            config,
            created_at: created_ats.value(i),
            branches,
        });
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use lago_core::event::EventPayload;

    fn make_test_envelope(seq: u64, session: &str, branch: &str) -> EventEnvelope {
        EventEnvelope {
            event_id: EventId::from_string(format!("EVT{seq:03}")),
            session_id: SessionId::from_string(session),
            branch_id: BranchId::from_string(branch),
            run_id: None,
            seq,
            timestamp: 1_700_000_000_000_000 + seq,
            parent_id: None,
            payload: EventPayload::ErrorRaised {
                message: format!("test event {seq}"),
            },
            metadata: HashMap::new(),
            schema_version: 1,
        }
    }

    #[test]
    fn events_roundtrip_through_batch() {
        let events = vec![
            make_test_envelope(1, "SESS001", "main"),
            make_test_envelope(2, "SESS001", "main"),
        ];

        let batch = events_to_batch(&events).expect("should create batch");
        assert_eq!(batch.num_rows(), 2);
        assert_eq!(batch.num_columns(), 10);

        let recovered = batch_to_events(&batch);
        assert_eq!(recovered.len(), 2);
        assert_eq!(recovered[0].event_id.as_str(), "EVT001");
        assert_eq!(recovered[1].event_id.as_str(), "EVT002");
        assert_eq!(recovered[0].seq, 1);
        assert_eq!(recovered[1].seq, 2);
    }

    #[test]
    fn events_with_optional_fields() {
        let mut event = make_test_envelope(1, "S1", "main");
        event.run_id = Some(RunId::from_string("RUN001"));
        event.parent_id = Some(EventId::from_string("EVT000"));
        event
            .metadata
            .insert("key".to_string(), "value".to_string());

        let batch = events_to_batch(&[event]).expect("should create batch");
        let recovered = batch_to_events(&batch);

        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].run_id.as_ref().unwrap().as_str(), "RUN001");
        assert_eq!(recovered[0].parent_id.as_ref().unwrap().as_str(), "EVT000");
        assert_eq!(recovered[0].metadata["key"], "value");
    }

    #[test]
    fn empty_events_produce_empty_batch() {
        let batch = events_to_batch(&[]).expect("should create empty batch");
        assert_eq!(batch.num_rows(), 0);

        let recovered = batch_to_events(&batch);
        assert!(recovered.is_empty());
    }

    #[test]
    fn session_roundtrip_through_batch() {
        let session = Session {
            session_id: SessionId::from_string("SESS001"),
            config: SessionConfig::new("test-session"),
            created_at: 1_700_000_000,
            branches: vec![BranchId::from_string("main"), BranchId::from_string("dev")],
        };

        let batch = session_to_batch(&session).expect("should create batch");
        assert_eq!(batch.num_rows(), 1);

        let recovered = batch_to_sessions(&batch);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].session_id.as_str(), "SESS001");
        assert_eq!(recovered[0].config.name, "test-session");
        assert_eq!(recovered[0].created_at, 1_700_000_000);
        assert_eq!(recovered[0].branches.len(), 2);
    }

    #[test]
    fn batch_schema_matches_event_schema() {
        let events = vec![make_test_envelope(1, "S1", "main")];
        let batch = events_to_batch(&events).unwrap();

        let expected = crate::schema::event_schema();
        assert_eq!(
            *batch.schema(),
            arrow_schema::Schema::new(expected.fields().to_vec())
        );
    }

    #[test]
    fn batch_schema_matches_session_schema() {
        let session = Session {
            session_id: SessionId::from_string("S1"),
            config: SessionConfig::new("test"),
            created_at: 100,
            branches: vec![],
        };
        let batch = session_to_batch(&session).unwrap();

        let expected = crate::schema::session_schema();
        assert_eq!(
            *batch.schema(),
            arrow_schema::Schema::new(expected.fields().to_vec())
        );
    }
}
