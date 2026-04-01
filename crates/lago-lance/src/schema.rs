//! Arrow schemas for Lance-backed event and session storage.

use arrow_schema::{DataType, Field, Schema};

/// Arrow schema for `EventEnvelope` rows in the events Lance dataset.
pub fn event_schema() -> Schema {
    Schema::new(vec![
        Field::new("event_id", DataType::Utf8, false),
        Field::new("session_id", DataType::Utf8, false),
        Field::new("branch_id", DataType::Utf8, false),
        Field::new("run_id", DataType::Utf8, true),
        Field::new("seq", DataType::UInt64, false),
        Field::new("timestamp", DataType::UInt64, false),
        Field::new("parent_id", DataType::Utf8, true),
        Field::new("payload_json", DataType::Utf8, false), // JSON-encoded EventPayload
        Field::new("metadata_json", DataType::Utf8, true), // JSON-encoded HashMap
        Field::new("schema_version", DataType::UInt8, false),
    ])
}

/// Arrow schema for `Session` rows in the sessions Lance dataset.
pub fn session_schema() -> Schema {
    Schema::new(vec![
        Field::new("session_id", DataType::Utf8, false),
        Field::new("config_json", DataType::Utf8, false),
        Field::new("created_at", DataType::UInt64, false),
        Field::new("branches_json", DataType::Utf8, false),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_schema_has_expected_fields() {
        let schema = event_schema();
        assert_eq!(schema.fields().len(), 10);
        assert!(schema.field_with_name("event_id").is_ok());
        assert!(schema.field_with_name("session_id").is_ok());
        assert!(schema.field_with_name("branch_id").is_ok());
        assert!(schema.field_with_name("run_id").is_ok());
        assert!(schema.field_with_name("seq").is_ok());
        assert!(schema.field_with_name("timestamp").is_ok());
        assert!(schema.field_with_name("parent_id").is_ok());
        assert!(schema.field_with_name("payload_json").is_ok());
        assert!(schema.field_with_name("metadata_json").is_ok());
        assert!(schema.field_with_name("schema_version").is_ok());
    }

    #[test]
    fn session_schema_has_expected_fields() {
        let schema = session_schema();
        assert_eq!(schema.fields().len(), 4);
        assert!(schema.field_with_name("session_id").is_ok());
        assert!(schema.field_with_name("config_json").is_ok());
        assert!(schema.field_with_name("created_at").is_ok());
        assert!(schema.field_with_name("branches_json").is_ok());
    }

    #[test]
    fn event_schema_nullable_fields() {
        let schema = event_schema();
        // run_id, parent_id, metadata_json are nullable
        assert!(schema.field_with_name("run_id").unwrap().is_nullable());
        assert!(schema.field_with_name("parent_id").unwrap().is_nullable());
        assert!(
            schema
                .field_with_name("metadata_json")
                .unwrap()
                .is_nullable()
        );
        // Required fields are not nullable
        assert!(!schema.field_with_name("event_id").unwrap().is_nullable());
        assert!(!schema.field_with_name("seq").unwrap().is_nullable());
    }
}
