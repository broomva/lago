//! Quota enforcement for multi-tenant resource limits.
//!
//! Evaluates current usage against the tenant's quota and returns a decision:
//! allow the operation, or reject with a `QuotaExceeded` error.

use lago_core::tenant::{TenantQuota, TenantQuotaOverrides, TenantTier};

/// Quota check result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaDecision {
    /// Usage is within limits.
    Allow,
    /// Usage exceeds the limit for the given dimension.
    Exceeded {
        dimension: String,
        current: u64,
        limit: u64,
    },
}

impl QuotaDecision {
    /// Returns `true` if the decision allows the operation.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// Quota enforcer that checks current usage against tenant limits.
pub struct QuotaEnforcer {
    overrides: TenantQuotaOverrides,
}

impl QuotaEnforcer {
    /// Create a new quota enforcer with optional overrides.
    pub fn new(overrides: TenantQuotaOverrides) -> Self {
        Self { overrides }
    }

    /// Create a quota enforcer with built-in defaults only.
    pub fn with_defaults() -> Self {
        Self {
            overrides: TenantQuotaOverrides::default(),
        }
    }

    /// Resolve the effective quota for a tenant tier.
    pub fn quota_for(&self, tier: TenantTier) -> TenantQuota {
        self.overrides.resolve(tier)
    }

    /// Check whether appending `delta` events would exceed the monthly event quota.
    pub fn check_events(
        &self,
        tier: TenantTier,
        current_monthly_events: u64,
        delta: u64,
    ) -> QuotaDecision {
        let quota = self.quota_for(tier);
        let projected = current_monthly_events.saturating_add(delta);
        if projected > quota.max_events_per_month {
            QuotaDecision::Exceeded {
                dimension: "events_per_month".to_string(),
                current: current_monthly_events,
                limit: quota.max_events_per_month,
            }
        } else {
            QuotaDecision::Allow
        }
    }

    /// Check whether storing `delta` bytes would exceed the storage quota.
    pub fn check_storage(
        &self,
        tier: TenantTier,
        current_storage_bytes: u64,
        delta: u64,
    ) -> QuotaDecision {
        let quota = self.quota_for(tier);
        let projected = current_storage_bytes.saturating_add(delta);
        if projected > quota.max_storage_bytes {
            QuotaDecision::Exceeded {
                dimension: "storage_bytes".to_string(),
                current: current_storage_bytes,
                limit: quota.max_storage_bytes,
            }
        } else {
            QuotaDecision::Allow
        }
    }

    /// Check whether creating a new session would exceed the session quota.
    pub fn check_sessions(
        &self,
        tier: TenantTier,
        current_session_count: u64,
    ) -> QuotaDecision {
        let quota = self.quota_for(tier);
        if current_session_count >= quota.max_sessions {
            QuotaDecision::Exceeded {
                dimension: "sessions".to_string(),
                current: current_session_count,
                limit: quota.max_sessions,
            }
        } else {
            QuotaDecision::Allow
        }
    }

    /// Check whether making an API call would exceed the hourly API call quota.
    pub fn check_api_calls(
        &self,
        tier: TenantTier,
        current_hourly_calls: u64,
    ) -> QuotaDecision {
        let quota = self.quota_for(tier);
        if current_hourly_calls >= quota.max_api_calls_per_hour {
            QuotaDecision::Exceeded {
                dimension: "api_calls_per_hour".to_string(),
                current: current_hourly_calls,
                limit: quota.max_api_calls_per_hour,
            }
        } else {
            QuotaDecision::Allow
        }
    }
}

impl Default for QuotaEnforcer {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_within_limits() {
        let enforcer = QuotaEnforcer::with_defaults();
        let decision = enforcer.check_events(TenantTier::Free, 50_000, 1);
        assert_eq!(decision, QuotaDecision::Allow);
    }

    #[test]
    fn exceed_event_quota() {
        let enforcer = QuotaEnforcer::with_defaults();
        let decision = enforcer.check_events(TenantTier::Free, 100_000, 1);
        assert!(matches!(decision, QuotaDecision::Exceeded { .. }));
        if let QuotaDecision::Exceeded {
            dimension,
            current,
            limit,
        } = decision
        {
            assert_eq!(dimension, "events_per_month");
            assert_eq!(current, 100_000);
            assert_eq!(limit, 100_000);
        }
    }

    #[test]
    fn pro_tier_higher_limits() {
        let enforcer = QuotaEnforcer::with_defaults();
        // 100k events is fine for pro (limit is 10M)
        let decision = enforcer.check_events(TenantTier::Pro, 100_000, 1);
        assert_eq!(decision, QuotaDecision::Allow);
    }

    #[test]
    fn enterprise_unlimited() {
        let enforcer = QuotaEnforcer::with_defaults();
        let decision = enforcer.check_events(TenantTier::Enterprise, u64::MAX - 1, 1);
        assert_eq!(decision, QuotaDecision::Allow);
    }

    #[test]
    fn exceed_storage_quota() {
        let enforcer = QuotaEnforcer::with_defaults();
        // Free tier: 1 GB limit
        let decision =
            enforcer.check_storage(TenantTier::Free, 1_073_741_824, 1);
        assert!(matches!(decision, QuotaDecision::Exceeded { .. }));
    }

    #[test]
    fn exceed_session_quota() {
        let enforcer = QuotaEnforcer::with_defaults();
        // Free tier: 10 session limit
        let decision = enforcer.check_sessions(TenantTier::Free, 10);
        assert!(matches!(decision, QuotaDecision::Exceeded { .. }));
    }

    #[test]
    fn custom_overrides() {
        let overrides = TenantQuotaOverrides {
            free: Some(TenantQuota {
                max_events_per_month: 500,
                max_storage_bytes: 1_000,
                max_sessions: 2,
                max_api_calls_per_hour: 100,
            }),
            pro: None,
            enterprise: None,
        };
        let enforcer = QuotaEnforcer::new(overrides);
        let decision = enforcer.check_events(TenantTier::Free, 500, 1);
        assert!(matches!(decision, QuotaDecision::Exceeded { .. }));

        // Pro still uses built-in defaults
        let decision = enforcer.check_events(TenantTier::Pro, 500, 1);
        assert_eq!(decision, QuotaDecision::Allow);
    }

    #[test]
    fn check_api_calls_exceeded() {
        let enforcer = QuotaEnforcer::with_defaults();
        // Free tier: 1000 calls/hour
        let decision = enforcer.check_api_calls(TenantTier::Free, 1_000);
        assert!(matches!(decision, QuotaDecision::Exceeded { .. }));
    }

    #[test]
    fn decision_is_allowed() {
        assert!(QuotaDecision::Allow.is_allowed());
        assert!(!QuotaDecision::Exceeded {
            dimension: "x".into(),
            current: 0,
            limit: 0,
        }
        .is_allowed());
    }
}
