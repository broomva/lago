//! Multi-tenant namespace isolation types and quota configuration.
//!
//! Provides tiered isolation for Lago's managed service:
//! - **Shared (Tier 1)**: session prefix namespacing within a shared journal
//! - **Dedicated (Tier 2)**: separate redb + blob store per tenant
//!
//! Quota enforcement is config-driven per tier.

use serde::{Deserialize, Serialize};

/// Tenant isolation tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantTier {
    /// Shared infrastructure: all tenants share one journal + blob store.
    /// Sessions are namespaced with `{tenant_id}:` prefix.
    Free,
    /// Standard shared infrastructure with higher quotas.
    Pro,
    /// Dedicated infrastructure: separate redb + blob store per tenant.
    /// Optional per-tenant encryption at rest.
    Enterprise,
}

impl TenantTier {
    /// Parse a tier from a string (case-insensitive).
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "pro" => Self::Pro,
            "enterprise" => Self::Enterprise,
            _ => Self::Free,
        }
    }
}

impl Default for TenantTier {
    fn default() -> Self {
        Self::Free
    }
}

impl std::fmt::Display for TenantTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Free => write!(f, "free"),
            Self::Pro => write!(f, "pro"),
            Self::Enterprise => write!(f, "enterprise"),
        }
    }
}

/// Resource quotas for a tenant tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantQuota {
    /// Maximum events ingested per calendar month.
    pub max_events_per_month: u64,
    /// Maximum total uncompressed storage bytes.
    pub max_storage_bytes: u64,
    /// Maximum number of sessions a tenant can create.
    pub max_sessions: u64,
    /// Maximum API calls per hour.
    pub max_api_calls_per_hour: u64,
}

impl TenantQuota {
    /// Default quotas for the free tier.
    pub fn free() -> Self {
        Self {
            max_events_per_month: 100_000,
            max_storage_bytes: 1_073_741_824, // 1 GB
            max_sessions: 10,
            max_api_calls_per_hour: 1_000,
        }
    }

    /// Default quotas for the pro tier.
    pub fn pro() -> Self {
        Self {
            max_events_per_month: 10_000_000,
            max_storage_bytes: 107_374_182_400, // 100 GB
            max_sessions: 100,
            max_api_calls_per_hour: 50_000,
        }
    }

    /// Default quotas for the enterprise tier (effectively unlimited).
    pub fn enterprise() -> Self {
        Self {
            max_events_per_month: u64::MAX,
            max_storage_bytes: u64::MAX,
            max_sessions: u64::MAX,
            max_api_calls_per_hour: u64::MAX,
        }
    }

    /// Get the default quota for a given tier.
    pub fn for_tier(tier: TenantTier) -> Self {
        match tier {
            TenantTier::Free => Self::free(),
            TenantTier::Pro => Self::pro(),
            TenantTier::Enterprise => Self::enterprise(),
        }
    }
}

/// Per-tenant encryption configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantEncryptionConfig {
    /// Whether encryption is enabled for this tenant's blobs.
    pub enabled: bool,
    /// KMS key reference (opaque string — could be AWS KMS ARN, Vault path, etc.).
    /// When set, blobs are encrypted with AES-256-GCM using a data key
    /// derived from this master key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kms_key_ref: Option<String>,
}

impl Default for TenantEncryptionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            kms_key_ref: None,
        }
    }
}

/// Multi-tenant isolation configuration for the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantIsolationConfig {
    /// Enable multi-tenant mode. When false, the system operates in
    /// single-tenant mode (backward-compatible).
    #[serde(default)]
    pub enabled: bool,

    /// Override quotas per tier (merged on top of built-in defaults).
    #[serde(default)]
    pub quotas: TenantQuotaOverrides,

    /// Enable per-tenant blob encryption (requires enterprise tier).
    #[serde(default)]
    pub encryption: TenantEncryptionConfig,
}

impl Default for TenantIsolationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            quotas: TenantQuotaOverrides::default(),
            encryption: TenantEncryptionConfig::default(),
        }
    }
}

/// Optional quota overrides per tier in the config file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TenantQuotaOverrides {
    #[serde(default)]
    pub free: Option<TenantQuota>,
    #[serde(default)]
    pub pro: Option<TenantQuota>,
    #[serde(default)]
    pub enterprise: Option<TenantQuota>,
}

impl TenantQuotaOverrides {
    /// Resolve the effective quota for a tier: config override > built-in default.
    pub fn resolve(&self, tier: TenantTier) -> TenantQuota {
        match tier {
            TenantTier::Free => self.free.clone().unwrap_or_else(TenantQuota::free),
            TenantTier::Pro => self.pro.clone().unwrap_or_else(TenantQuota::pro),
            TenantTier::Enterprise => {
                self.enterprise
                    .clone()
                    .unwrap_or_else(TenantQuota::enterprise)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_from_str_loose() {
        assert_eq!(TenantTier::from_str_loose("free"), TenantTier::Free);
        assert_eq!(TenantTier::from_str_loose("Free"), TenantTier::Free);
        assert_eq!(TenantTier::from_str_loose("pro"), TenantTier::Pro);
        assert_eq!(TenantTier::from_str_loose("PRO"), TenantTier::Pro);
        assert_eq!(
            TenantTier::from_str_loose("enterprise"),
            TenantTier::Enterprise
        );
        assert_eq!(TenantTier::from_str_loose("unknown"), TenantTier::Free);
    }

    #[test]
    fn tier_display() {
        assert_eq!(TenantTier::Free.to_string(), "free");
        assert_eq!(TenantTier::Pro.to_string(), "pro");
        assert_eq!(TenantTier::Enterprise.to_string(), "enterprise");
    }

    #[test]
    fn quota_defaults() {
        let free = TenantQuota::free();
        assert_eq!(free.max_events_per_month, 100_000);
        assert_eq!(free.max_storage_bytes, 1_073_741_824);
        assert_eq!(free.max_sessions, 10);

        let pro = TenantQuota::pro();
        assert_eq!(pro.max_events_per_month, 10_000_000);
        assert_eq!(pro.max_sessions, 100);

        let ent = TenantQuota::enterprise();
        assert_eq!(ent.max_events_per_month, u64::MAX);
    }

    #[test]
    fn quota_for_tier() {
        let q = TenantQuota::for_tier(TenantTier::Pro);
        assert_eq!(q.max_events_per_month, 10_000_000);
    }

    #[test]
    fn quota_overrides_resolve() {
        let overrides = TenantQuotaOverrides {
            free: Some(TenantQuota {
                max_events_per_month: 50_000,
                max_storage_bytes: 500_000_000,
                max_sessions: 5,
                max_api_calls_per_hour: 500,
            }),
            pro: None,
            enterprise: None,
        };
        let free = overrides.resolve(TenantTier::Free);
        assert_eq!(free.max_events_per_month, 50_000);

        // Pro falls back to built-in default
        let pro = overrides.resolve(TenantTier::Pro);
        assert_eq!(pro.max_events_per_month, 10_000_000);
    }

    #[test]
    fn tenant_isolation_config_default() {
        let config = TenantIsolationConfig::default();
        assert!(!config.enabled);
        assert!(!config.encryption.enabled);
    }

    #[test]
    fn tenant_tier_serde_roundtrip() {
        let tier = TenantTier::Enterprise;
        let json = serde_json::to_string(&tier).unwrap();
        assert_eq!(json, "\"enterprise\"");
        let back: TenantTier = serde_json::from_str(&json).unwrap();
        assert_eq!(back, tier);
    }

    #[test]
    fn quota_serde_roundtrip() {
        let quota = TenantQuota::pro();
        let json = serde_json::to_string(&quota).unwrap();
        let back: TenantQuota = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_events_per_month, quota.max_events_per_month);
        assert_eq!(back.max_storage_bytes, quota.max_storage_bytes);
    }

    #[test]
    fn encryption_config_default() {
        let config = TenantEncryptionConfig::default();
        assert!(!config.enabled);
        assert!(config.kms_key_ref.is_none());
    }
}
