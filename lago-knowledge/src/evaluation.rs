//! Composite evaluator for EGRI knowledge-threshold calibration trials.

use thiserror::Error;

use crate::{BenchmarkRun, KnowledgeThresholdArtifact, ThresholdValidationError};

const SAFETY_COMPLIANCE_THRESHOLD: f64 = 0.95;
const HOLDOUT_GENERALIZATION_RATIO: f64 = 0.80;

#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct KnowledgeQualityEvaluator {
    pub weights: KnowledgeQualityWeights,
}

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct KnowledgeQualityWeights {
    pub recall_at_1_dev: f64,
    pub recall_at_5_dev: f64,
    pub recall_at_5_holdout: f64,
    pub avg_reasoning_coherence: f64,
    pub knowledge_health: f64,
    pub token_efficiency: f64,
    pub reasoning_speed: f64,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct KnowledgeQualityMetrics {
    pub recall_at_1_dev: f64,
    pub recall_at_5_dev: f64,
    pub recall_at_5_holdout: f64,
    pub avg_reasoning_coherence: f64,
    pub knowledge_health: f64,
    pub token_efficiency: f64,
    pub reasoning_speed: f64,
    pub safety_compliance: f64,
    pub total_scenarios: usize,
    pub passed: usize,
    pub failed: usize,
    pub holdout_passed: usize,
    pub holdout_total: usize,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct KnowledgeQualityOutcome {
    pub score: f64,
    pub constraints_passed: bool,
    pub constraint_violations: Vec<KnowledgeConstraintViolation>,
    pub evaluator_metadata: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct KnowledgeConstraintViolation {
    pub constraint_id: String,
    pub measured: f64,
    pub threshold: f64,
    pub severity: ConstraintSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintSeverity {
    Hard,
    Soft,
}

#[derive(Debug, Error)]
pub enum KnowledgeQualityError {
    #[error(transparent)]
    InvalidArtifact(#[from] ThresholdValidationError),
    #[error("failed to parse knowledge quality metrics: {0}")]
    Metrics(serde_json::Error),
    #[error("failed to serialize evaluator metadata: {0}")]
    Metadata(serde_json::Error),
}

impl Default for KnowledgeQualityWeights {
    fn default() -> Self {
        Self {
            recall_at_1_dev: 0.15,
            recall_at_5_dev: 0.25,
            recall_at_5_holdout: 0.20,
            avg_reasoning_coherence: 0.15,
            knowledge_health: 0.10,
            token_efficiency: 0.10,
            reasoning_speed: 0.05,
        }
    }
}

impl KnowledgeQualityEvaluator {
    pub fn new(weights: KnowledgeQualityWeights) -> Self {
        Self { weights }
    }

    pub fn evaluate(
        &self,
        artifact: &KnowledgeThresholdArtifact,
        metrics: &KnowledgeQualityMetrics,
    ) -> Result<KnowledgeQualityOutcome, KnowledgeQualityError> {
        artifact.validate()?;

        let score = self.weights.score(metrics);
        let constraint_violations = self.constraint_violations(artifact, metrics);
        let constraints_passed = constraint_violations
            .iter()
            .all(|violation| violation.severity != ConstraintSeverity::Hard);
        let evaluator_metadata =
            serde_json::to_value(metrics).map_err(KnowledgeQualityError::Metadata)?;

        Ok(KnowledgeQualityOutcome {
            score,
            constraints_passed,
            constraint_violations,
            evaluator_metadata,
        })
    }

    pub fn evaluate_from_json(
        &self,
        artifact: &KnowledgeThresholdArtifact,
        execution_output: &str,
    ) -> Result<KnowledgeQualityOutcome, KnowledgeQualityError> {
        let metrics: KnowledgeQualityMetrics =
            serde_json::from_str(execution_output).map_err(KnowledgeQualityError::Metrics)?;
        self.evaluate(artifact, &metrics)
    }

    fn constraint_violations(
        &self,
        artifact: &KnowledgeThresholdArtifact,
        metrics: &KnowledgeQualityMetrics,
    ) -> Vec<KnowledgeConstraintViolation> {
        let mut violations = Vec::new();

        if metrics.safety_compliance < SAFETY_COMPLIANCE_THRESHOLD {
            violations.push(KnowledgeConstraintViolation {
                constraint_id: "safety_compliance".to_string(),
                measured: metrics.safety_compliance,
                threshold: SAFETY_COMPLIANCE_THRESHOLD,
                severity: ConstraintSeverity::Hard,
            });
        }

        let holdout_threshold = HOLDOUT_GENERALIZATION_RATIO * metrics.recall_at_5_dev;
        if metrics.recall_at_5_dev > 0.0 && metrics.recall_at_5_holdout < holdout_threshold {
            violations.push(KnowledgeConstraintViolation {
                constraint_id: "holdout_anti_gaming".to_string(),
                measured: metrics.recall_at_5_holdout,
                threshold: holdout_threshold,
                severity: ConstraintSeverity::Hard,
            });
        }

        let health_threshold = f64::from(artifact.health_threshold);
        if metrics.knowledge_health < health_threshold {
            violations.push(KnowledgeConstraintViolation {
                constraint_id: "health_regression".to_string(),
                measured: metrics.knowledge_health,
                threshold: health_threshold,
                severity: ConstraintSeverity::Soft,
            });
        }

        violations
    }
}

impl KnowledgeQualityWeights {
    pub fn score(&self, metrics: &KnowledgeQualityMetrics) -> f64 {
        self.recall_at_1_dev * clamp01(metrics.recall_at_1_dev)
            + self.recall_at_5_dev * clamp01(metrics.recall_at_5_dev)
            + self.recall_at_5_holdout * clamp01(metrics.recall_at_5_holdout)
            + self.avg_reasoning_coherence * clamp01(metrics.avg_reasoning_coherence)
            + self.knowledge_health * clamp01(metrics.knowledge_health)
            + self.token_efficiency * clamp01(metrics.token_efficiency)
            + self.reasoning_speed * clamp01(metrics.reasoning_speed)
    }

    pub fn total(&self) -> f64 {
        self.recall_at_1_dev
            + self.recall_at_5_dev
            + self.recall_at_5_holdout
            + self.avg_reasoning_coherence
            + self.knowledge_health
            + self.token_efficiency
            + self.reasoning_speed
    }
}

impl KnowledgeQualityMetrics {
    pub fn from_benchmark_run(run: &BenchmarkRun) -> Self {
        let passed = run
            .questions
            .iter()
            .filter(|question| question.hit_at_5)
            .count();
        let failed = run.total_questions.saturating_sub(passed);

        Self {
            recall_at_1_dev: run.dev.recall_at_1,
            recall_at_5_dev: run.dev.recall_at_5,
            recall_at_5_holdout: run.holdout.recall_at_5,
            avg_reasoning_coherence: 1.0,
            knowledge_health: 1.0,
            token_efficiency: 1.0,
            reasoning_speed: 1.0,
            safety_compliance: 1.0,
            total_scenarios: run.total_questions,
            passed,
            failed,
            holdout_passed: run.holdout.correct_at_5,
            holdout_total: run.holdout.total,
        }
    }

    pub fn with_runtime_signals(
        mut self,
        avg_reasoning_coherence: f64,
        knowledge_health: f64,
        token_efficiency: f64,
        reasoning_speed: f64,
        safety_compliance: f64,
    ) -> Self {
        self.avg_reasoning_coherence = avg_reasoning_coherence;
        self.knowledge_health = knowledge_health;
        self.token_efficiency = token_efficiency;
        self.reasoning_speed = reasoning_speed;
        self.safety_compliance = safety_compliance;
        self
    }
}

fn clamp01(value: f64) -> f64 {
    value.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{QuestionResult, SplitMetrics};

    fn perfect_metrics() -> KnowledgeQualityMetrics {
        KnowledgeQualityMetrics {
            recall_at_1_dev: 1.0,
            recall_at_5_dev: 1.0,
            recall_at_5_holdout: 1.0,
            avg_reasoning_coherence: 1.0,
            knowledge_health: 1.0,
            token_efficiency: 1.0,
            reasoning_speed: 1.0,
            safety_compliance: 1.0,
            total_scenarios: 50,
            passed: 50,
            failed: 0,
            holdout_passed: 10,
            holdout_total: 10,
        }
    }

    #[test]
    fn default_weights_match_design_and_sum_to_one() {
        let weights = KnowledgeQualityWeights::default();

        assert_eq!(weights.recall_at_1_dev, 0.15);
        assert_eq!(weights.recall_at_5_dev, 0.25);
        assert_eq!(weights.recall_at_5_holdout, 0.20);
        assert_eq!(weights.avg_reasoning_coherence, 0.15);
        assert_eq!(weights.knowledge_health, 0.10);
        assert_eq!(weights.token_efficiency, 0.10);
        assert_eq!(weights.reasoning_speed, 0.05);
        assert!((weights.total() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn perfect_metrics_score_one_and_pass_constraints() {
        let outcome = KnowledgeQualityEvaluator::default()
            .evaluate(&KnowledgeThresholdArtifact::default(), &perfect_metrics())
            .unwrap();

        assert_eq!(outcome.score, 1.0);
        assert!(outcome.constraints_passed);
        assert!(outcome.constraint_violations.is_empty());
    }

    #[test]
    fn safety_regression_is_hard_violation() {
        let mut metrics = perfect_metrics();
        metrics.safety_compliance = 0.94;

        let outcome = KnowledgeQualityEvaluator::default()
            .evaluate(&KnowledgeThresholdArtifact::default(), &metrics)
            .unwrap();

        assert!(!outcome.constraints_passed);
        assert_eq!(
            outcome.constraint_violations[0].constraint_id,
            "safety_compliance"
        );
        assert_eq!(
            outcome.constraint_violations[0].severity,
            ConstraintSeverity::Hard
        );
    }

    #[test]
    fn holdout_under_dev_ratio_is_hard_violation() {
        let mut metrics = perfect_metrics();
        metrics.recall_at_5_dev = 1.0;
        metrics.recall_at_5_holdout = 0.79;

        let outcome = KnowledgeQualityEvaluator::default()
            .evaluate(&KnowledgeThresholdArtifact::default(), &metrics)
            .unwrap();

        assert!(!outcome.constraints_passed);
        assert!(
            outcome
                .constraint_violations
                .iter()
                .any(|violation| violation.constraint_id == "holdout_anti_gaming"
                    && violation.severity == ConstraintSeverity::Hard)
        );
    }

    #[test]
    fn health_regression_is_soft_violation() {
        let mut metrics = perfect_metrics();
        metrics.knowledge_health = 0.60;

        let outcome = KnowledgeQualityEvaluator::default()
            .evaluate(&KnowledgeThresholdArtifact::default(), &metrics)
            .unwrap();

        assert!(outcome.constraints_passed);
        assert_eq!(
            outcome.constraint_violations[0].constraint_id,
            "health_regression"
        );
        assert_eq!(
            outcome.constraint_violations[0].severity,
            ConstraintSeverity::Soft
        );
    }

    #[test]
    fn metrics_from_benchmark_run_track_scenario_coverage() {
        let run = BenchmarkRun {
            version: 1,
            total_questions: 3,
            dev: SplitMetrics {
                total: 2,
                correct_at_1: 1,
                correct_at_5: 2,
                recall_at_1: 0.5,
                recall_at_5: 1.0,
            },
            holdout: SplitMetrics {
                total: 1,
                correct_at_1: 0,
                correct_at_5: 0,
                recall_at_1: 0.0,
                recall_at_5: 0.0,
            },
            questions: vec![
                question("q1", "dev", true),
                question("q2", "dev", true),
                question("q3", "holdout", false),
            ],
        };

        let metrics = KnowledgeQualityMetrics::from_benchmark_run(&run);

        assert_eq!(metrics.total_scenarios, 3);
        assert_eq!(metrics.passed, 2);
        assert_eq!(metrics.failed, 1);
        assert_eq!(metrics.holdout_passed, 0);
        assert_eq!(metrics.holdout_total, 1);
        assert_eq!(metrics.recall_at_1_dev, 0.5);
        assert_eq!(metrics.recall_at_5_dev, 1.0);
        assert_eq!(metrics.recall_at_5_holdout, 0.0);
    }

    #[test]
    fn evaluate_from_json_parses_execution_output() {
        let output = serde_json::to_string(&perfect_metrics()).unwrap();
        let outcome = KnowledgeQualityEvaluator::default()
            .evaluate_from_json(&KnowledgeThresholdArtifact::default(), &output)
            .unwrap();

        assert_eq!(outcome.score, 1.0);
        assert!(outcome.constraints_passed);
        assert_eq!(
            outcome.evaluator_metadata["total_scenarios"],
            serde_json::json!(50)
        );
    }

    fn question(id: &str, split: &str, hit_at_5: bool) -> QuestionResult {
        QuestionResult {
            id: id.to_string(),
            split: split.to_string(),
            expected_top: "expected".to_string(),
            top_result: None,
            top_5_results: Vec::new(),
            hit_at_1: false,
            hit_at_5,
        }
    }
}
