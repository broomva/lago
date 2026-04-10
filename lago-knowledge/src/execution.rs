//! Trial execution substrate for EGRI knowledge-threshold calibration.

use std::time::Instant;

use thiserror::Error;

use crate::{
    BenchmarkError, BenchmarkRun, KnowledgeBenchmark, KnowledgeIndex, KnowledgeQualityError,
    KnowledgeQualityEvaluator, KnowledgeQualityMetrics, KnowledgeQualityOutcome,
    KnowledgeThresholdArtifact, ThresholdValidationError,
};

/// Deterministic executor that applies one threshold artifact to the knowledge
/// benchmark plant and scores the resulting metrics with an immutable evaluator.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct KnowledgeTrialExecutor {
    pub evaluator: KnowledgeQualityEvaluator,
}

/// Per-trial execution settings supplied by the calibration loop.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct KnowledgeTrialConfig {
    pub trial_id: String,
    pub max_results: usize,
    pub runtime_signals: KnowledgeRuntimeSignals,
}

/// Runtime metrics collected from Arcan/Nous/Vigil around a trial.
///
/// The local executor defaults these to neutral values so retrieval calibration
/// can run deterministically before live runtime collection is attached.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct KnowledgeRuntimeSignals {
    pub avg_reasoning_coherence: f64,
    pub knowledge_health: f64,
    pub token_efficiency: f64,
    pub reasoning_speed: f64,
    pub safety_compliance: f64,
}

/// Complete output of a calibration trial.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct KnowledgeTrialExecution {
    pub trial_id: String,
    pub artifact: KnowledgeThresholdArtifact,
    pub benchmark_run: BenchmarkRun,
    pub metrics: KnowledgeQualityMetrics,
    pub outcome: KnowledgeQualityOutcome,
    /// JSON metrics payload accepted by `KnowledgeQualityEvaluator::evaluate_from_json`.
    pub execution_output: String,
    pub duration_ms: u64,
}

#[derive(Debug, Error)]
pub enum KnowledgeTrialError {
    #[error(transparent)]
    InvalidArtifact(#[from] ThresholdValidationError),
    #[error(transparent)]
    Benchmark(#[from] BenchmarkError),
    #[error(transparent)]
    Evaluate(#[from] KnowledgeQualityError),
    #[error("failed to serialize trial metrics: {0}")]
    Serialize(serde_json::Error),
}

impl Default for KnowledgeTrialConfig {
    fn default() -> Self {
        Self {
            trial_id: "local-trial".to_string(),
            max_results: 5,
            runtime_signals: KnowledgeRuntimeSignals::default(),
        }
    }
}

impl Default for KnowledgeRuntimeSignals {
    fn default() -> Self {
        Self {
            avg_reasoning_coherence: 1.0,
            knowledge_health: 1.0,
            token_efficiency: 1.0,
            reasoning_speed: 1.0,
            safety_compliance: 1.0,
        }
    }
}

impl KnowledgeTrialExecutor {
    pub fn new(evaluator: KnowledgeQualityEvaluator) -> Self {
        Self { evaluator }
    }

    pub fn execute(
        &self,
        artifact: &KnowledgeThresholdArtifact,
        benchmark: &KnowledgeBenchmark,
        index: &KnowledgeIndex,
        config: &KnowledgeTrialConfig,
    ) -> Result<KnowledgeTrialExecution, KnowledgeTrialError> {
        artifact.validate()?;

        let started = Instant::now();
        let search_config = artifact.to_search_config(config.max_results);
        let benchmark_run = benchmark.run(index, &search_config)?;
        let metrics = KnowledgeQualityMetrics::from_benchmark_run(&benchmark_run)
            .with_runtime_signals(
                config.runtime_signals.avg_reasoning_coherence,
                config.runtime_signals.knowledge_health,
                config.runtime_signals.token_efficiency,
                config.runtime_signals.reasoning_speed,
                config.runtime_signals.safety_compliance,
            );
        let execution_output =
            serde_json::to_string(&metrics).map_err(KnowledgeTrialError::Serialize)?;
        let outcome = self
            .evaluator
            .evaluate_from_json(artifact, &execution_output)?;

        Ok(KnowledgeTrialExecution {
            trial_id: config.trial_id.clone(),
            artifact: artifact.clone(),
            benchmark_run,
            metrics,
            outcome,
            execution_output,
            duration_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        })
    }
}

#[cfg(test)]
mod tests {
    use lago_core::ManifestEntry;
    use lago_store::BlobStore;
    use tempfile::TempDir;

    use super::*;

    fn build_index(files: &[(&str, &str)]) -> (TempDir, KnowledgeIndex) {
        let tmp = TempDir::new().unwrap();
        let store = BlobStore::open(tmp.path()).unwrap();
        let mut entries = Vec::new();

        for (path, content) in files {
            let hash = store.put(content.as_bytes()).unwrap();
            entries.push(ManifestEntry {
                path: path.to_string(),
                blob_hash: hash,
                size_bytes: content.len() as u64,
                content_type: Some("text/markdown".to_string()),
                updated_at: 0,
            });
        }

        let index = KnowledgeIndex::build(&entries, &store).unwrap();
        (tmp, index)
    }

    fn sample_benchmark() -> KnowledgeBenchmark {
        serde_json::from_str(
            r#"{
              "version": 1,
              "description": "sample",
              "generated_from": "tests",
              "questions": [
                {
                  "id": "q001",
                  "query": "event persistence",
                  "expected_top": "journal",
                  "expected_any_5": [],
                  "category": "concept",
                  "difficulty": "easy"
                },
                {
                  "id": "q002",
                  "query": "tool execution",
                  "expected_top": "praxis",
                  "expected_any_5": [],
                  "category": "tool",
                  "difficulty": "easy"
                }
              ],
              "holdout_split": {
                "dev": "q001-q001",
                "holdout": "q002-q002",
                "description": "split"
              }
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn trial_executor_runs_benchmark_and_scores_metrics() {
        let (_tmp, index) = build_index(&[
            (
                "/journal.md",
                "# Journal\n\nHandles event persistence and replay.",
            ),
            ("/praxis.md", "# Praxis\n\nCanonical tool execution engine."),
        ]);
        let execution = KnowledgeTrialExecutor::default()
            .execute(
                &KnowledgeThresholdArtifact::default(),
                &sample_benchmark(),
                &index,
                &KnowledgeTrialConfig {
                    trial_id: "trial-001".to_string(),
                    ..KnowledgeTrialConfig::default()
                },
            )
            .unwrap();

        assert_eq!(execution.trial_id, "trial-001");
        assert_eq!(execution.benchmark_run.total_questions, 2);
        assert_eq!(execution.metrics.passed, 2);
        assert_eq!(execution.metrics.failed, 0);
        assert_eq!(execution.outcome.score, 1.0);
        assert!(execution.outcome.constraints_passed);
    }

    #[test]
    fn execution_output_round_trips_through_evaluator() {
        let (_tmp, index) = build_index(&[
            (
                "/journal.md",
                "# Journal\n\nHandles event persistence and replay.",
            ),
            ("/praxis.md", "# Praxis\n\nCanonical tool execution engine."),
        ]);
        let artifact = KnowledgeThresholdArtifact::default();
        let execution = KnowledgeTrialExecutor::default()
            .execute(
                &artifact,
                &sample_benchmark(),
                &index,
                &KnowledgeTrialConfig::default(),
            )
            .unwrap();

        let outcome = KnowledgeQualityEvaluator::default()
            .evaluate_from_json(&artifact, &execution.execution_output)
            .unwrap();
        assert_eq!(outcome, execution.outcome);
    }

    #[test]
    fn runtime_signals_feed_constraint_outcome() {
        let (_tmp, index) = build_index(&[
            (
                "/journal.md",
                "# Journal\n\nHandles event persistence and replay.",
            ),
            ("/praxis.md", "# Praxis\n\nCanonical tool execution engine."),
        ]);
        let execution = KnowledgeTrialExecutor::default()
            .execute(
                &KnowledgeThresholdArtifact::default(),
                &sample_benchmark(),
                &index,
                &KnowledgeTrialConfig {
                    runtime_signals: KnowledgeRuntimeSignals {
                        safety_compliance: 0.90,
                        ..KnowledgeRuntimeSignals::default()
                    },
                    ..KnowledgeTrialConfig::default()
                },
            )
            .unwrap();

        assert_eq!(execution.metrics.safety_compliance, 0.90);
        assert!(!execution.outcome.constraints_passed);
        assert!(
            execution
                .outcome
                .constraint_violations
                .iter()
                .any(|violation| violation.constraint_id == "safety_compliance")
        );
    }

    #[test]
    fn invalid_artifact_fails_before_trial_execution() {
        let (_tmp, index) = build_index(&[
            (
                "/journal.md",
                "# Journal\n\nHandles event persistence and replay.",
            ),
            ("/praxis.md", "# Praxis\n\nCanonical tool execution engine."),
        ]);
        let artifact = KnowledgeThresholdArtifact {
            bm25_k1: 10.0,
            ..KnowledgeThresholdArtifact::default()
        };
        let err = KnowledgeTrialExecutor::default()
            .execute(
                &artifact,
                &sample_benchmark(),
                &index,
                &KnowledgeTrialConfig::default(),
            )
            .unwrap_err();

        assert!(matches!(err, KnowledgeTrialError::InvalidArtifact(_)));
    }
}
