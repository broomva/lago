//! Bridge between Lago's internal types and the canonical `aios-protocol` types.
//!
//! Provides `From`/`Into` conversions for IDs and event payloads so that
//! Lago can interoperate with the Agent OS protocol without changing its
//! internal storage format.

use crate::event::{EventEnvelope, EventPayload};
use crate::id::*;

/// Re-export the canonical protocol for downstream convenience.
pub use aios_protocol;

// ─── ID conversions: Lago (ULID String) ↔ Protocol (String) ────────────────
//
// Both use String-based IDs, so conversions are trivial.

impl From<SessionId> for aios_protocol::SessionId {
    fn from(id: SessionId) -> Self {
        aios_protocol::SessionId::from_string(id.as_str())
    }
}

impl From<aios_protocol::SessionId> for SessionId {
    fn from(id: aios_protocol::SessionId) -> Self {
        SessionId::from_string(id.as_str())
    }
}

impl From<EventId> for aios_protocol::EventId {
    fn from(id: EventId) -> Self {
        aios_protocol::EventId::from_string(id.as_str())
    }
}

impl From<aios_protocol::EventId> for EventId {
    fn from(id: aios_protocol::EventId) -> Self {
        EventId::from_string(id.as_str())
    }
}

impl From<BranchId> for aios_protocol::BranchId {
    fn from(id: BranchId) -> Self {
        aios_protocol::BranchId::from_string(id.as_str())
    }
}

impl From<aios_protocol::BranchId> for BranchId {
    fn from(id: aios_protocol::BranchId) -> Self {
        BranchId::from_string(id.as_str())
    }
}

impl From<RunId> for aios_protocol::RunId {
    fn from(id: RunId) -> Self {
        aios_protocol::RunId::from_string(id.as_str())
    }
}

impl From<aios_protocol::RunId> for RunId {
    fn from(id: aios_protocol::RunId) -> Self {
        RunId::from_string(id.as_str())
    }
}

impl From<SnapshotId> for aios_protocol::SnapshotId {
    fn from(id: SnapshotId) -> Self {
        aios_protocol::SnapshotId::from_string(id.as_str())
    }
}

impl From<ApprovalId> for aios_protocol::ApprovalId {
    fn from(id: ApprovalId) -> Self {
        aios_protocol::ApprovalId::from_string(id.as_str())
    }
}

impl From<MemoryId> for aios_protocol::MemoryId {
    fn from(id: MemoryId) -> Self {
        aios_protocol::MemoryId::from_string(id.as_str())
    }
}

impl From<BlobHash> for aios_protocol::BlobHash {
    fn from(hash: BlobHash) -> Self {
        aios_protocol::BlobHash::from_hex(hash.as_str())
    }
}

impl From<aios_protocol::BlobHash> for BlobHash {
    fn from(hash: aios_protocol::BlobHash) -> Self {
        BlobHash::from_hex(hash.as_str())
    }
}

/// Convert a Lago `EventEnvelope` to a canonical `aios_protocol::EventEnvelope`.
///
/// Uses JSON round-trip for the payload to handle all current and future
/// event variants without maintaining a manual mapping.
impl EventEnvelope {
    pub fn to_protocol(&self) -> Option<aios_protocol::EventEnvelope> {
        let kind_json = serde_json::to_value(&self.payload).ok()?;
        let protocol_kind: aios_protocol::EventKind = serde_json::from_value(kind_json).ok()?;

        Some(aios_protocol::EventEnvelope {
            event_id: self.event_id.clone().into(),
            session_id: self.session_id.clone().into(),
            agent_id: self
                .metadata
                .get("agent_id")
                .map(|s| aios_protocol::AgentId::from_string(s.clone()))
                .unwrap_or_default(),
            branch_id: self.branch_id.clone().into(),
            run_id: self.run_id.clone().map(Into::into),
            seq: self.seq,
            timestamp: self.timestamp,
            actor: self
                .metadata
                .get("actor")
                .and_then(|v| serde_json::from_str::<aios_protocol::EventActor>(v).ok())
                .unwrap_or_default(),
            schema: self
                .metadata
                .get("schema")
                .and_then(|v| serde_json::from_str::<aios_protocol::EventSchema>(v).ok())
                .unwrap_or_default(),
            parent_id: self.parent_id.clone().map(Into::into),
            trace_id: self.metadata.get("trace_id").cloned(),
            span_id: self.metadata.get("span_id").cloned(),
            digest: self.metadata.get("digest").cloned(),
            kind: protocol_kind,
            metadata: self.metadata.clone(),
            schema_version: self.schema_version,
        })
    }
}

/// Convert a canonical `aios_protocol::EventEnvelope` back to Lago's format.
pub fn from_protocol(envelope: &aios_protocol::EventEnvelope) -> Option<EventEnvelope> {
    let kind_json = serde_json::to_value(&envelope.kind).ok()?;
    let lago_payload: EventPayload = serde_json::from_value(kind_json).ok()?;
    let mut metadata = envelope.metadata.clone();
    metadata
        .entry("agent_id".to_string())
        .or_insert_with(|| envelope.agent_id.to_string());
    metadata
        .entry("actor".to_string())
        .or_insert_with(|| serde_json::to_string(&envelope.actor).unwrap_or_default());
    metadata
        .entry("schema".to_string())
        .or_insert_with(|| serde_json::to_string(&envelope.schema).unwrap_or_default());
    if let Some(trace_id) = &envelope.trace_id {
        metadata.insert("trace_id".to_string(), trace_id.clone());
    }
    if let Some(span_id) = &envelope.span_id {
        metadata.insert("span_id".to_string(), span_id.clone());
    }
    if let Some(digest) = &envelope.digest {
        metadata.insert("digest".to_string(), digest.clone());
    }

    Some(EventEnvelope {
        event_id: EventId::from_string(envelope.event_id.as_str()),
        session_id: SessionId::from_string(envelope.session_id.as_str()),
        branch_id: BranchId::from_string(envelope.branch_id.as_str()),
        run_id: envelope
            .run_id
            .as_ref()
            .map(|id| RunId::from_string(id.as_str())),
        seq: envelope.seq,
        timestamp: envelope.timestamp,
        parent_id: envelope
            .parent_id
            .as_ref()
            .map(|id| EventId::from_string(id.as_str())),
        payload: lago_payload,
        metadata,
        schema_version: envelope.schema_version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventPayload;
    use std::collections::HashMap;

    #[test]
    fn session_id_roundtrip() {
        let lago_id = SessionId::from_string("SESS001");
        let proto_id: aios_protocol::SessionId = lago_id.clone().into();
        assert_eq!(proto_id.as_str(), "SESS001");
        let back: SessionId = proto_id.into();
        assert_eq!(back, lago_id);
    }

    #[test]
    fn blob_hash_roundtrip() {
        let lago_hash = BlobHash::from_hex("deadbeef");
        let proto_hash: aios_protocol::BlobHash = lago_hash.clone().into();
        assert_eq!(proto_hash.as_str(), "deadbeef");
        let back: BlobHash = proto_hash.into();
        assert_eq!(back, lago_hash);
    }

    #[test]
    fn envelope_to_protocol_roundtrip() {
        let envelope = EventEnvelope {
            event_id: EventId::from_string("EVT001"),
            session_id: SessionId::from_string("SESS001"),
            branch_id: BranchId::from_string("main"),
            run_id: None,
            seq: 42,
            timestamp: 1_700_000_000_000_000,
            parent_id: None,
            payload: EventPayload::RunStarted {
                provider: "anthropic".into(),
                max_iterations: 10,
            },
            metadata: HashMap::new(),
            schema_version: 1,
        };

        let proto = envelope.to_protocol().expect("convert to protocol");
        assert_eq!(proto.seq, 42);
        assert_eq!(proto.event_id.as_str(), "EVT001");
        assert!(matches!(
            proto.kind,
            aios_protocol::EventKind::RunStarted { .. }
        ));

        // Convert back
        let back = from_protocol(&proto).expect("convert from protocol");
        assert_eq!(back.seq, 42);
        assert!(matches!(back.payload, EventPayload::RunStarted { .. }));
    }

    #[test]
    fn lago_error_raised_converts_to_protocol() {
        let envelope = EventEnvelope {
            event_id: EventId::from_string("EVT002"),
            session_id: SessionId::from_string("SESS001"),
            branch_id: BranchId::from_string("main"),
            run_id: None,
            seq: 1,
            timestamp: 1_700_000_000_000_000,
            parent_id: None,
            payload: EventPayload::ErrorRaised {
                message: "test".into(),
            },
            metadata: HashMap::new(),
            schema_version: 1,
        };

        let proto = envelope.to_protocol().expect("convert to protocol");
        assert!(matches!(
            proto.kind,
            aios_protocol::EventKind::ErrorRaised { .. }
        ));
    }
}
