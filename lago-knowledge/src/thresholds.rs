//! Tunable knowledge calibration thresholds and parameter bounds.

use thiserror::Error;

use crate::search::HybridSearchConfig;

/// Inclusive numeric bounds plus mutation step for a tunable parameter.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NumericBound<T> {
    pub min: T,
    pub max: T,
    pub step: T,
}

/// Full mutation surface for knowledge retrieval, evaluation, and regulation.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct KnowledgeThresholdArtifact {
    /// BM25 term saturation.
    pub bm25_k1: f64,
    /// BM25 document-length normalization.
    pub bm25_b: f64,
    /// Exact keyword/title/tag match boost.
    pub hybrid_keyword_boost: f64,
    /// Graph proximity boost.
    pub hybrid_graph_boost: f64,
    /// Minimum acceptable knowledge health score.
    pub health_threshold: f32,
    /// Observation count before compaction advisory.
    pub max_obs_before_compact: u32,
    /// Maximum milliseconds before knowledge index staleness advisory.
    pub stale_index_ms: u64,
    /// Freshness window before retrieved knowledge is considered stale.
    pub freshness_stale_secs: u64,
    /// Wake-up context assembly budget.
    pub wakeup_token_budget: usize,
}

/// Hard bounds used by the future proposer and by validation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KnowledgeThresholdBounds {
    pub bm25_k1: NumericBound<f64>,
    pub bm25_b: NumericBound<f64>,
    pub hybrid_keyword_boost: NumericBound<f64>,
    pub hybrid_graph_boost: NumericBound<f64>,
    pub health_threshold: NumericBound<f32>,
    pub max_obs_before_compact: NumericBound<u32>,
    pub stale_index_ms: NumericBound<u64>,
    pub freshness_stale_secs: NumericBound<u64>,
    pub wakeup_token_budget: NumericBound<usize>,
}

#[derive(Debug, Clone, Error)]
#[error("invalid knowledge threshold artifact: {issues:?}")]
pub struct ThresholdValidationError {
    pub issues: Vec<String>,
}

impl Default for KnowledgeThresholdArtifact {
    fn default() -> Self {
        Self {
            bm25_k1: 1.2,
            bm25_b: 0.75,
            hybrid_keyword_boost: 0.30,
            hybrid_graph_boost: 0.15,
            health_threshold: 0.70,
            max_obs_before_compact: 50,
            stale_index_ms: 3_600_000,
            freshness_stale_secs: 3_600,
            wakeup_token_budget: 600,
        }
    }
}

impl KnowledgeThresholdArtifact {
    pub const fn bounds() -> KnowledgeThresholdBounds {
        KnowledgeThresholdBounds {
            bm25_k1: NumericBound {
                min: 0.5,
                max: 3.0,
                step: 0.1,
            },
            bm25_b: NumericBound {
                min: 0.0,
                max: 1.0,
                step: 0.05,
            },
            hybrid_keyword_boost: NumericBound {
                min: 0.0,
                max: 1.0,
                step: 0.05,
            },
            hybrid_graph_boost: NumericBound {
                min: 0.0,
                max: 0.5,
                step: 0.05,
            },
            health_threshold: NumericBound {
                min: 0.3,
                max: 0.95,
                step: 0.05,
            },
            max_obs_before_compact: NumericBound {
                min: 10,
                max: 200,
                step: 10,
            },
            stale_index_ms: NumericBound {
                min: 300_000,
                max: 86_400_000,
                step: 300_000,
            },
            freshness_stale_secs: NumericBound {
                min: 300,
                max: 86_400,
                step: 300,
            },
            wakeup_token_budget: NumericBound {
                min: 200,
                max: 2_000,
                step: 100,
            },
        }
    }

    /// Validate that every parameter stays within its hard bounds and step grid.
    pub fn validate(&self) -> Result<(), ThresholdValidationError> {
        let bounds = Self::bounds();
        let mut issues = Vec::new();

        validate_f64("bm25_k1", self.bm25_k1, bounds.bm25_k1, &mut issues);
        validate_f64("bm25_b", self.bm25_b, bounds.bm25_b, &mut issues);
        validate_f64(
            "hybrid_keyword_boost",
            self.hybrid_keyword_boost,
            bounds.hybrid_keyword_boost,
            &mut issues,
        );
        validate_f64(
            "hybrid_graph_boost",
            self.hybrid_graph_boost,
            bounds.hybrid_graph_boost,
            &mut issues,
        );
        validate_f32(
            "health_threshold",
            self.health_threshold,
            bounds.health_threshold,
            &mut issues,
        );
        validate_u32(
            "max_obs_before_compact",
            self.max_obs_before_compact,
            bounds.max_obs_before_compact,
            &mut issues,
        );
        validate_u64(
            "stale_index_ms",
            self.stale_index_ms,
            bounds.stale_index_ms,
            &mut issues,
        );
        validate_u64(
            "freshness_stale_secs",
            self.freshness_stale_secs,
            bounds.freshness_stale_secs,
            &mut issues,
        );
        validate_usize(
            "wakeup_token_budget",
            self.wakeup_token_budget,
            bounds.wakeup_token_budget,
            &mut issues,
        );

        if issues.is_empty() {
            Ok(())
        } else {
            Err(ThresholdValidationError { issues })
        }
    }

    /// Translate the artifact into the live search configuration surface.
    pub fn to_search_config(&self, max_results: usize) -> HybridSearchConfig {
        HybridSearchConfig {
            keyword_boost: self.hybrid_keyword_boost,
            graph_boost: self.hybrid_graph_boost,
            max_results,
            temporal_boost: false,
            bm25_k1: self.bm25_k1,
            bm25_b: self.bm25_b,
        }
    }
}

fn validate_f64(name: &str, value: f64, bound: NumericBound<f64>, issues: &mut Vec<String>) {
    if value < bound.min || value > bound.max {
        issues.push(format!(
            "{name} out of range: {value} not in [{}, {}]",
            bound.min, bound.max
        ));
        return;
    }

    let steps = (value - bound.min) / bound.step;
    if (steps - steps.round()).abs() > 1e-9 {
        issues.push(format!(
            "{name} must align to step {} from minimum {}",
            bound.step, bound.min
        ));
    }
}

fn validate_f32(name: &str, value: f32, bound: NumericBound<f32>, issues: &mut Vec<String>) {
    if value < bound.min || value > bound.max {
        issues.push(format!(
            "{name} out of range: {value} not in [{}, {}]",
            bound.min, bound.max
        ));
        return;
    }

    let steps = (value - bound.min) / bound.step;
    if (steps - steps.round()).abs() > 1e-6 {
        issues.push(format!(
            "{name} must align to step {} from minimum {}",
            bound.step, bound.min
        ));
    }
}

fn validate_u32(name: &str, value: u32, bound: NumericBound<u32>, issues: &mut Vec<String>) {
    if value < bound.min || value > bound.max {
        issues.push(format!(
            "{name} out of range: {value} not in [{}, {}]",
            bound.min, bound.max
        ));
        return;
    }

    if !(value - bound.min).is_multiple_of(bound.step) {
        issues.push(format!(
            "{name} must align to step {} from minimum {}",
            bound.step, bound.min
        ));
    }
}

fn validate_u64(name: &str, value: u64, bound: NumericBound<u64>, issues: &mut Vec<String>) {
    if value < bound.min || value > bound.max {
        issues.push(format!(
            "{name} out of range: {value} not in [{}, {}]",
            bound.min, bound.max
        ));
        return;
    }

    if !(value - bound.min).is_multiple_of(bound.step) {
        issues.push(format!(
            "{name} must align to step {} from minimum {}",
            bound.step, bound.min
        ));
    }
}

fn validate_usize(name: &str, value: usize, bound: NumericBound<usize>, issues: &mut Vec<String>) {
    if value < bound.min || value > bound.max {
        issues.push(format!(
            "{name} out of range: {value} not in [{}, {}]",
            bound.min, bound.max
        ));
        return;
    }

    if !(value - bound.min).is_multiple_of(bound.step) {
        issues.push(format!(
            "{name} must align to step {} from minimum {}",
            bound.step, bound.min
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_artifact_matches_design_defaults() {
        let artifact = KnowledgeThresholdArtifact::default();
        assert_eq!(artifact.bm25_k1, 1.2);
        assert_eq!(artifact.bm25_b, 0.75);
        assert_eq!(artifact.hybrid_keyword_boost, 0.30);
        assert_eq!(artifact.hybrid_graph_boost, 0.15);
        assert_eq!(artifact.health_threshold, 0.70);
        assert_eq!(artifact.max_obs_before_compact, 50);
        assert_eq!(artifact.stale_index_ms, 3_600_000);
        assert_eq!(artifact.freshness_stale_secs, 3_600);
        assert_eq!(artifact.wakeup_token_budget, 600);
    }

    #[test]
    fn default_artifact_validates() {
        KnowledgeThresholdArtifact::default().validate().unwrap();
    }

    #[test]
    fn validation_rejects_out_of_range_values() {
        let mut artifact = KnowledgeThresholdArtifact::default();
        artifact.bm25_k1 = 3.2;
        artifact.health_threshold = 0.2;

        let err = artifact.validate().unwrap_err();
        assert_eq!(err.issues.len(), 2);
        assert!(err.issues[0].contains("bm25_k1"));
        assert!(err.issues[1].contains("health_threshold"));
    }

    #[test]
    fn validation_rejects_non_step_aligned_values() {
        let mut artifact = KnowledgeThresholdArtifact::default();
        artifact.hybrid_keyword_boost = 0.33;
        artifact.max_obs_before_compact = 55;

        let err = artifact.validate().unwrap_err();
        assert_eq!(err.issues.len(), 2);
        assert!(err.issues[0].contains("hybrid_keyword_boost"));
        assert!(err.issues[1].contains("max_obs_before_compact"));
    }

    #[test]
    fn to_search_config_copies_search_knobs() {
        let artifact = KnowledgeThresholdArtifact {
            bm25_k1: 1.6,
            bm25_b: 0.55,
            hybrid_keyword_boost: 0.4,
            hybrid_graph_boost: 0.2,
            ..KnowledgeThresholdArtifact::default()
        };

        let config = artifact.to_search_config(7);
        assert_eq!(config.max_results, 7);
        assert_eq!(config.keyword_boost, 0.4);
        assert_eq!(config.graph_boost, 0.2);
        assert_eq!(config.bm25_k1, 1.6);
        assert_eq!(config.bm25_b, 0.55);
    }
}
