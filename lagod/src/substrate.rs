//! Substrate-plane gRPC service for lagod.
//!
//! Implements `lago.v1.LagoSubstrate` (defined in
//! `proto/lago/v1/substrate.proto`, generated in
//! `lago-substrate-proto`). This is the entry point that lifed reaches
//! via `lago-proxy` under Topology B for the small slice of lago RPCs
//! its saga driver + routing cache need (event append + namespace
//! enumeration). It is ADDITIVE to lagod's existing
//! `lago.v1.IngestService` (bidi-streaming ingest at the same gRPC
//! port, used by arcand for the session-bound event journal) and HTTP
//! `:8080` server — all three serve the same backing `RedbJournal` +
//! `BlobStore`.
//!
//! Phase 2 scope (BRO-1017):
//! - `Append`: wraps (namespace, event_type, payload) into a
//!   `EventKind::Custom { event_type, data }` envelope on the
//!   namespace's main branch and journals it. Returns the assigned
//!   monotonic sequence number. Closes the `idem_persist`-as-append
//!   shim in `lago-proxy::client::append_event` (the E3 deferral).
//! - `ListNamespaces`: returns every session id whose value starts
//!   with the supplied prefix. Closes the empty-vec fallback in
//!   `lago-proxy::client::list_namespaces`. lifed's
//!   `RoutingCache::cold_start` now warms from durable storage at
//!   boot instead of waiting for traffic.
//!
//! Phase 3+ (separate tickets) will lift the remaining lago-proxy
//! stub methods (`open_namespace`, `close_namespace`, `read`,
//! `subscribe`, `get_blob`, `idem_lookup`, `idem_persist`) to real
//! RPCs alongside their server-side counterparts.

use std::sync::Arc;

use aios_protocol::EventKind;
use lago_core::{BranchId, EventEnvelope, EventId, EventQuery, Journal, SessionId};
use lago_substrate_proto::lago::v1::{
    AppendReq, AppendResp, ListNamespacesReq, ListNamespacesResp,
    lago_substrate_server::LagoSubstrate,
};
use tonic::{Request, Response, Status};

/// lagod's `lago.v1.LagoSubstrate` impl. Holds a shared
/// `Arc<dyn Journal>` so every RPC reuses the same in-memory journal
/// handle the HTTP + IngestService planes are driving. lagod is
/// internally single-journal.
pub struct SubstrateService {
    journal: Arc<dyn Journal>,
}

impl SubstrateService {
    pub fn new(journal: Arc<dyn Journal>) -> Self {
        Self { journal }
    }
}

#[tonic::async_trait]
impl LagoSubstrate for SubstrateService {
    async fn append(&self, req: Request<AppendReq>) -> Result<Response<AppendResp>, Status> {
        let body = req.into_inner();
        if body.namespace.is_empty() {
            return Err(Status::invalid_argument("empty namespace"));
        }
        if body.event_type.is_empty() {
            return Err(Status::invalid_argument("empty event_type"));
        }

        // Parse the payload as JSON. Empty payload is treated as JSON
        // `null` (matches the proto comment: "an empty payload is
        // stored as JSON null"). This keeps the envelope shape
        // consistent — `EventKind::Custom.data` is always a
        // `serde_json::Value`.
        let data: serde_json::Value = if body.payload.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&body.payload).map_err(|e| {
                tracing::warn!(
                    namespace = %body.namespace,
                    event_type = %body.event_type,
                    error = %e,
                    "lago.Append: payload is not valid JSON"
                );
                Status::invalid_argument(format!("payload is not valid JSON: {e}"))
            })?
        };

        let envelope = EventEnvelope {
            event_id: EventId::new(),
            session_id: SessionId::from_string(&body.namespace),
            branch_id: BranchId::from_string("main"),
            run_id: None,
            seq: 0, // assigned by the journal
            timestamp: EventEnvelope::now_micros(),
            parent_id: None,
            payload: EventKind::Custom {
                event_type: body.event_type.clone(),
                data,
            },
            metadata: std::collections::HashMap::new(),
            schema_version: 1,
        };

        let assigned_seq = self.journal.append(envelope).await.map_err(|e| {
            tracing::warn!(
                namespace = %body.namespace,
                event_type = %body.event_type,
                error = %e,
                "lago.Append: journal append failed"
            );
            Status::internal(format!("journal append: {e}"))
        })?;

        Ok(Response::new(AppendResp {
            seq: assigned_seq,
            committed_at: Some(prost_types::Timestamp::from(std::time::SystemTime::now())),
        }))
    }

    async fn list_namespaces(
        &self,
        req: Request<ListNamespacesReq>,
    ) -> Result<Response<ListNamespacesResp>, Status> {
        let body = req.into_inner();
        // Strategy:
        // 1. Read every `Session` from the journal (rooted in the
        //    `SESSIONS` redb table). These are the "registered"
        //    namespaces created via `Journal::put_session`.
        // 2. Append every namespace seen as a session_id of any
        //    journaled event. The proxy's `append_event` shim
        //    (which the substrate is now closing out) produces
        //    namespaces that are NOT registered via put_session
        //    (e.g. `system/lifed/saga/<id>`). They show up only in
        //    the event journal. Without step 2, `cold_start` would
        //    miss saga namespaces.
        // 3. De-dup, prefix-filter, sort for determinism.
        let sessions = self.journal.list_sessions().await.map_err(|e| {
            tracing::warn!(error = %e, "lago.ListNamespaces: list_sessions failed");
            Status::internal(format!("list_sessions: {e}"))
        })?;

        // Pull every event so we can also pick up event-only
        // namespaces. This is a full scan; Phase 2 accepts the cost
        // because lifed only calls this on cold-start. A future
        // ticket can replace with a dedicated `namespaces` table.
        let events = self.journal.read(EventQuery::new()).await.map_err(|e| {
            tracing::warn!(error = %e, "lago.ListNamespaces: read all failed");
            Status::internal(format!("read all: {e}"))
        })?;

        let mut namespaces: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for session in sessions {
            namespaces.insert(session.session_id.as_str().to_string());
        }
        for envelope in events {
            namespaces.insert(envelope.session_id.as_str().to_string());
        }

        let filtered: Vec<String> = namespaces
            .into_iter()
            .filter(|n| body.prefix.is_empty() || n.starts_with(&body.prefix))
            .collect();

        Ok(Response::new(ListNamespacesResp {
            namespaces: filtered,
        }))
    }
}
