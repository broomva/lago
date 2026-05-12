//! Generated `lago.v1` proto types — the substrate-plane wire contract
//! between lifed (via `lago-proxy`) and lagod.
//!
//! All types live under `lago::v1` (the proto package path). The
//! generated client + server stubs are used by `lago-proxy` and the
//! `lagod::substrate` server respectively. `aios.v1.*` types are
//! re-exported from `aios-proto` via `extern_path` (Spec C₂ §10.3).
//!
//! NOT to be confused with the existing `lago.v1.IngestService` (lives
//! in `crates/lago/lago-ingest`, bidi-streaming ingest path used by
//! arcand's event journal). The substrate-plane `LagoSubstrate`
//! service is independent and serves lifed's saga + routing-cache
//! callers under Topology B.
//!
//! Reference: `docs/superpowers/specs/2026-04-25-life-runtime-architecture-spec.md`
//! and BRO-1017 (Phase 2 close-out of the Topology B substrate-stub gap
//! audit at `research/entities/concept/topology-b-substrate-stub-gap.md`).

#![deny(unsafe_code)]
#![allow(missing_docs)] // generated code

#[allow(unused_qualifications, clippy::all)]
pub mod lago {
    pub mod v1 {
        tonic::include_proto!("lago.v1");
    }
}

// Re-export aios-proto for callers that want a single import path.
pub use aios_proto::aios as aios_v1;
