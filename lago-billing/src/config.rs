//! Billing configuration for Stripe Meters integration.

use serde::{Deserialize, Serialize};

/// Billing configuration section from `lago.toml`.
///
/// When `stripe_api_key` is `None` (or the `LAGO_STRIPE_API_KEY` env var is
/// unset), the entire billing subsystem is disabled — no background task is
/// spawned and no HTTP calls are made.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingConfig {
    /// Stripe secret API key (`sk_live_...` or `sk_test_...`).
    /// Prefer setting via `LAGO_STRIPE_API_KEY` env var.
    #[serde(default)]
    pub stripe_api_key: Option<String>,

    /// Stripe meter event name for events ingested.
    #[serde(default = "default_meter_events")]
    pub meter_events_name: String,

    /// Stripe meter event name for storage bytes.
    #[serde(default = "default_meter_storage")]
    pub meter_storage_name: String,

    /// Stripe meter event name for API calls.
    #[serde(default = "default_meter_api")]
    pub meter_api_name: String,

    /// Stripe meter event name for egress bytes.
    #[serde(default = "default_meter_egress")]
    pub meter_egress_name: String,

    /// Stripe customer ID for platform-level billing.
    /// When set, all usage events are attributed to this customer.
    #[serde(default)]
    pub stripe_customer_id: Option<String>,

    /// How often to flush accumulated usage to Stripe (seconds).
    #[serde(default = "default_flush_interval")]
    pub flush_interval_secs: u64,
}

impl Default for BillingConfig {
    fn default() -> Self {
        Self {
            stripe_api_key: None,
            meter_events_name: default_meter_events(),
            meter_storage_name: default_meter_storage(),
            meter_api_name: default_meter_api(),
            meter_egress_name: default_meter_egress(),
            stripe_customer_id: None,
            flush_interval_secs: default_flush_interval(),
        }
    }
}

impl BillingConfig {
    /// Returns `true` when billing is fully configured and should be enabled.
    pub fn is_enabled(&self) -> bool {
        self.stripe_api_key.is_some() && self.stripe_customer_id.is_some()
    }

    /// Resolve the API key, preferring the env var over the config file value.
    pub fn resolve_api_key(&self) -> Option<String> {
        std::env::var("LAGO_STRIPE_API_KEY")
            .ok()
            .or_else(|| self.stripe_api_key.clone())
    }

    /// Resolve the customer ID, preferring the env var over the config file value.
    pub fn resolve_customer_id(&self) -> Option<String> {
        std::env::var("LAGO_STRIPE_CUSTOMER_ID")
            .ok()
            .or_else(|| self.stripe_customer_id.clone())
    }
}

fn default_meter_events() -> String {
    "lago_events_ingested".into()
}
fn default_meter_storage() -> String {
    "lago_storage_bytes".into()
}
fn default_meter_api() -> String {
    "lago_api_calls".into()
}
fn default_meter_egress() -> String {
    "lago_egress_bytes".into()
}
fn default_flush_interval() -> u64 {
    60
}
