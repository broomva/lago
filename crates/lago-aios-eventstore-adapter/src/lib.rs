use std::sync::Arc;

use aios_protocol::{
    BranchId as ProtocolBranchId, EventRecord, EventRecordStream, EventStorePort, KernelError,
    SessionId as ProtocolSessionId,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::{StreamExt, stream::BoxStream};
use lago_core::protocol_bridge;
use lago_core::{EventQuery, Journal};
use tracing::warn;

fn to_kernel_error(error: impl std::fmt::Display) -> KernelError {
    KernelError::Runtime(error.to_string())
}

fn micros_to_datetime(timestamp_micros: u64) -> Result<DateTime<Utc>, KernelError> {
    DateTime::<Utc>::from_timestamp_micros(timestamp_micros as i64).ok_or_else(|| {
        KernelError::InvalidState(format!("invalid timestamp micros: {timestamp_micros}"))
    })
}

fn envelope_to_record(envelope: aios_protocol::EventEnvelope) -> Result<EventRecord, KernelError> {
    Ok(EventRecord {
        event_id: envelope.event_id,
        session_id: envelope.session_id,
        agent_id: envelope.agent_id,
        branch_id: envelope.branch_id,
        sequence: envelope.seq,
        timestamp: micros_to_datetime(envelope.timestamp)?,
        actor: envelope.actor,
        schema: envelope.schema,
        causation_id: envelope.parent_id,
        correlation_id: envelope.metadata.get("correlation_id").cloned(),
        trace_id: envelope.trace_id,
        span_id: envelope.span_id,
        digest: envelope.digest,
        kind: envelope.kind,
    })
}

#[derive(Clone)]
pub struct LagoAiosEventStoreAdapter {
    journal: Arc<dyn Journal>,
}

impl LagoAiosEventStoreAdapter {
    pub fn new(journal: Arc<dyn Journal>) -> Self {
        Self { journal }
    }
}

#[async_trait]
impl EventStorePort for LagoAiosEventStoreAdapter {
    async fn append(&self, event: EventRecord) -> Result<EventRecord, KernelError> {
        let protocol_envelope = event.to_envelope();
        let lago_envelope =
            protocol_bridge::from_protocol(&protocol_envelope).ok_or_else(|| {
                KernelError::Serialization("failed converting protocol envelope".to_owned())
            })?;
        let assigned_seq = self
            .journal
            .append(lago_envelope)
            .await
            .map_err(to_kernel_error)?;

        let mut persisted = event;
        persisted.sequence = assigned_seq;
        Ok(persisted)
    }

    async fn read(
        &self,
        session_id: ProtocolSessionId,
        branch_id: ProtocolBranchId,
        from_sequence: u64,
        limit: usize,
    ) -> Result<Vec<EventRecord>, KernelError> {
        let query = EventQuery::new()
            .session(session_id.into())
            .branch(branch_id.into())
            .after(from_sequence.saturating_sub(1))
            .limit(limit);
        let events = self.journal.read(query).await.map_err(to_kernel_error)?;

        events
            .into_iter()
            .map(|envelope| {
                let protocol = envelope.to_protocol().ok_or_else(|| {
                    KernelError::Serialization("failed converting lago envelope".to_owned())
                })?;
                envelope_to_record(protocol)
            })
            .collect()
    }

    async fn head(
        &self,
        session_id: ProtocolSessionId,
        branch_id: ProtocolBranchId,
    ) -> Result<u64, KernelError> {
        self.journal
            .head_seq(&session_id.into(), &branch_id.into())
            .await
            .map_err(to_kernel_error)
    }

    async fn subscribe(
        &self,
        session_id: ProtocolSessionId,
        branch_id: ProtocolBranchId,
        after_sequence: u64,
    ) -> Result<EventRecordStream, KernelError> {
        let stream = self
            .journal
            .stream(
                session_id.clone().into(),
                branch_id.clone().into(),
                after_sequence,
            )
            .await
            .map_err(to_kernel_error)?;

        let adapted = stream.filter_map(|item| async move {
            match item {
                Ok(envelope) => {
                    let protocol = match envelope.to_protocol() {
                        Some(protocol) => protocol,
                        None => {
                            warn!("failed converting lago event envelope to protocol");
                            return Some(Err(KernelError::Serialization(
                                "failed converting lago envelope".to_owned(),
                            )));
                        }
                    };
                    Some(envelope_to_record(protocol))
                }
                Err(error) => Some(Err(to_kernel_error(error))),
            }
        });

        Ok(Box::pin(adapted) as BoxStream<'static, Result<EventRecord, KernelError>>)
    }
}
