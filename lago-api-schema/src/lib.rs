//! HTTP API DTOs for lagod — schema-only crate.
//!
//! This crate intentionally contains **no runtime code**. It exists so
//! `life-kernel-facade` can depend on typed request/response shapes without
//! pulling in lagod's server runtime. Types are filled in by Phase 0 tasks
//! that mirror the canonical HTTP surface at
//! `core/life/crates/lago/lagod/src/`.

#![forbid(unsafe_code)]
