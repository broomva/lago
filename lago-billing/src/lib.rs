//! Stripe Meters integration for Lago usage-based billing.
//!
//! This crate provides a [`MeterEmitter`] service that batches usage events
//! from `lago-journal` counters and sends them to Stripe Meters on a
//! configurable interval (default: 1 minute).
//!
//! ## Graceful degradation
//!
//! When `stripe_api_key` is not configured (neither in `lago.toml` nor the
//! `LAGO_STRIPE_API_KEY` env var), the entire billing subsystem is disabled.
//! No background tasks are spawned and no HTTP calls are made.
//!
//! ## Idempotency
//!
//! Each meter event includes an identifier of the form
//! `{session_id}:{dimension}:{period}` that prevents double-billing on
//! retries or overlapping flushes.

pub mod config;
pub mod emitter;

pub use config::BillingConfig;
pub use emitter::{BillingError, MeterEmitter};
