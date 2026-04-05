//! MeterEmitter — batched usage event emitter for Stripe Meters.
//!
//! Accumulates usage deltas in memory and flushes to Stripe on a configurable
//! interval (default: 60 s). This avoids per-event API calls at high volume.
//!
//! Idempotency keys follow the pattern `{session_id}:{dimension}:{period}`
//! so retries and overlapping flushes never double-bill.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use lago_journal::usage::UsageDimension;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::config::BillingConfig;

/// Composite key for the in-memory accumulator: (session_id, dimension).
type AccumKey = (String, UsageDimension);

/// MeterEmitter batches usage events and sends them to Stripe Meters.
///
/// # Usage
///
/// ```ignore
/// let emitter = MeterEmitter::new(config);
/// emitter.start(); // spawns background flush task
/// emitter.record("session-1", UsageDimension::Events, 1);
/// // ... later ...
/// emitter.shutdown().await;
/// ```
pub struct MeterEmitter {
    config: BillingConfig,
    api_key: String,
    customer_id: String,
    client: reqwest::Client,
    /// Accumulated deltas since last flush, keyed by (session_id, dimension).
    accumulator: Mutex<HashMap<AccumKey, u64>>,
    cancel: CancellationToken,
}

/// A single meter event payload sent to Stripe.
#[derive(Debug, serde::Serialize)]
struct MeterEventRequest {
    event_name: String,
    payload: MeterEventPayload,
    identifier: String,
    timestamp: u64,
}

#[derive(Debug, serde::Serialize)]
struct MeterEventPayload {
    stripe_customer_id: String,
    value: String,
}

impl MeterEmitter {
    /// Create a new MeterEmitter from a resolved billing config.
    ///
    /// Returns `None` if billing is not configured (no API key or customer ID).
    pub fn new(config: BillingConfig) -> Option<Self> {
        let api_key = config.resolve_api_key()?;
        let customer_id = config.resolve_customer_id()?;

        Some(Self {
            config,
            api_key,
            customer_id,
            client: reqwest::Client::new(),
            accumulator: Mutex::new(HashMap::new()),
            cancel: CancellationToken::new(),
        })
    }

    /// Record a usage delta for a session + dimension.
    ///
    /// This is lock-free on the fast path (single mutex acquire, no I/O).
    /// Accumulated values are flushed to Stripe on the next interval tick.
    pub fn record(&self, session_id: &str, dimension: UsageDimension, delta: u64) {
        if delta == 0 {
            return;
        }
        let key = (session_id.to_owned(), dimension);
        let mut acc = self.accumulator.lock().unwrap_or_else(|e| e.into_inner());
        *acc.entry(key).or_insert(0) += delta;
    }

    /// Spawn the background flush task. Call once after construction.
    pub fn start(self: &std::sync::Arc<Self>) {
        let emitter = std::sync::Arc::clone(self);
        let interval = Duration::from_secs(emitter.config.flush_interval_secs.max(1));
        let cancel = emitter.cancel.clone();

        tokio::spawn(async move {
            info!(
                interval_secs = interval.as_secs(),
                "billing meter emitter started"
            );
            loop {
                tokio::select! {
                    () = tokio::time::sleep(interval) => {
                        emitter.flush().await;
                    }
                    () = cancel.cancelled() => {
                        info!("billing meter emitter shutting down, final flush");
                        emitter.flush().await;
                        break;
                    }
                }
            }
            info!("billing meter emitter stopped");
        });
    }

    /// Signal the background task to stop and perform a final flush.
    pub async fn shutdown(&self) {
        self.cancel.cancel();
        // Give the background task a moment to complete its final flush.
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    /// Drain the accumulator and send batched events to Stripe.
    async fn flush(&self) {
        let batch = {
            let mut acc = self.accumulator.lock().unwrap_or_else(|e| e.into_inner());
            if acc.is_empty() {
                return;
            }
            std::mem::take(&mut *acc)
        };

        let period = current_minute_bucket();
        let total_events = batch.len();
        let mut success = 0u64;
        let mut failed = 0u64;

        for ((session_id, dimension), value) in &batch {
            if *value == 0 {
                continue;
            }

            let event_name = self.dimension_to_meter_name(*dimension);
            let identifier = format!("{session_id}:{dimension}:{period}");

            let req = MeterEventRequest {
                event_name,
                payload: MeterEventPayload {
                    stripe_customer_id: self.customer_id.clone(),
                    value: value.to_string(),
                },
                identifier,
                timestamp: period,
            };

            match self.send_meter_event(&req).await {
                Ok(()) => {
                    success += 1;
                    debug!(
                        session_id,
                        dimension = %dimension,
                        value,
                        "meter event sent"
                    );
                }
                Err(e) => {
                    failed += 1;
                    // Re-accumulate failed events so they retry on next flush.
                    let key = (session_id.clone(), *dimension);
                    let mut acc = self.accumulator.lock().unwrap_or_else(|e| e.into_inner());
                    *acc.entry(key).or_insert(0) += value;
                    warn!(
                        error = %e,
                        session_id,
                        dimension = %dimension,
                        value,
                        "meter event failed, will retry"
                    );
                }
            }
        }

        if success > 0 || failed > 0 {
            info!(
                total = total_events,
                success, failed, "billing flush complete"
            );
        }
    }

    /// Map a UsageDimension to its configured Stripe meter event name.
    fn dimension_to_meter_name(&self, dim: UsageDimension) -> String {
        match dim {
            UsageDimension::Events => self.config.meter_events_name.clone(),
            UsageDimension::StorageBytes => self.config.meter_storage_name.clone(),
            UsageDimension::ApiCalls => self.config.meter_api_name.clone(),
            UsageDimension::EgressBytes => self.config.meter_egress_name.clone(),
        }
    }

    /// Send a single meter event to the Stripe API.
    async fn send_meter_event(&self, event: &MeterEventRequest) -> Result<(), BillingError> {
        let resp = self
            .client
            .post("https://api.stripe.com/v1/billing/meter_events")
            .bearer_auth(&self.api_key)
            .form(&[
                ("event_name", &event.event_name),
                ("timestamp", &event.timestamp.to_string()),
                ("identifier", &event.identifier),
                (
                    "payload[stripe_customer_id]",
                    &event.payload.stripe_customer_id,
                ),
                ("payload[value]", &event.payload.value),
            ])
            .send()
            .await
            .map_err(|e| BillingError::Network(e.to_string()))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();

            // Idempotent duplicate — Stripe returns 400 with "identifier already exists"
            // This is expected and not an error.
            if status.as_u16() == 400 && body.contains("identifier") {
                debug!(
                    identifier = event.identifier,
                    "meter event already exists (idempotent)"
                );
                return Ok(());
            }

            Err(BillingError::Stripe {
                status: status.as_u16(),
                body,
            })
        }
    }
}

/// Truncate current time to the start of the current minute (Unix seconds).
fn current_minute_bucket() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now / 60 * 60
}

/// Errors from the billing subsystem.
#[derive(Debug, thiserror::Error)]
pub enum BillingError {
    #[error("network error: {0}")]
    Network(String),
    #[error("stripe API error (HTTP {status}): {body}")]
    Stripe { status: u16, body: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minute_bucket_truncates() {
        assert_eq!(current_minute_bucket() % 60, 0);
    }

    #[test]
    fn record_accumulates() {
        let config = BillingConfig {
            stripe_api_key: Some("sk_test_xxx".into()),
            stripe_customer_id: Some("cus_test".into()),
            ..Default::default()
        };
        let emitter = MeterEmitter::new(config).unwrap();

        emitter.record("s1", UsageDimension::Events, 5);
        emitter.record("s1", UsageDimension::Events, 3);
        emitter.record("s2", UsageDimension::ApiCalls, 10);

        let acc = emitter.accumulator.lock().unwrap();
        assert_eq!(acc[&("s1".to_owned(), UsageDimension::Events)], 8);
        assert_eq!(acc[&("s2".to_owned(), UsageDimension::ApiCalls)], 10);
    }

    #[test]
    fn zero_delta_ignored() {
        let config = BillingConfig {
            stripe_api_key: Some("sk_test_xxx".into()),
            stripe_customer_id: Some("cus_test".into()),
            ..Default::default()
        };
        let emitter = MeterEmitter::new(config).unwrap();

        emitter.record("s1", UsageDimension::Events, 0);

        let acc = emitter.accumulator.lock().unwrap();
        assert!(acc.is_empty());
    }

    #[test]
    fn new_returns_none_without_key() {
        let config = BillingConfig::default();
        assert!(MeterEmitter::new(config).is_none());
    }

    #[test]
    fn dimension_meter_names() {
        let config = BillingConfig {
            stripe_api_key: Some("sk_test_xxx".into()),
            stripe_customer_id: Some("cus_test".into()),
            ..Default::default()
        };
        let emitter = MeterEmitter::new(config).unwrap();

        assert_eq!(
            emitter.dimension_to_meter_name(UsageDimension::Events),
            "lago_events_ingested"
        );
        assert_eq!(
            emitter.dimension_to_meter_name(UsageDimension::StorageBytes),
            "lago_storage_bytes"
        );
        assert_eq!(
            emitter.dimension_to_meter_name(UsageDimension::ApiCalls),
            "lago_api_calls"
        );
        assert_eq!(
            emitter.dimension_to_meter_name(UsageDimension::EgressBytes),
            "lago_egress_bytes"
        );
    }
}
