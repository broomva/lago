//! Campaign-level EGRI loop for knowledge-threshold calibration.
//!
//! The lower-level modules are intentionally pure and narrow:
//! thresholds propose bounded artifacts, execution measures a single trial,
//! evaluation scores immutable metrics, and promotion writes approved winners.
//! This module wires those primitives into one bounded calibration campaign
//! without depending on a live Arcan daemon. Real Arcan-backed runners and
//! deterministic mock runners implement the same [`KnowledgeTrialRunner`]
//! seam.

use std::path::Path;

use thiserror::Error;

use crate::{
    KnowledgeBenchmark, KnowledgeIndex, KnowledgePromotionError, KnowledgePromotionRecord,
    KnowledgePromotionRequest, KnowledgeRuntimeSignals, KnowledgeThresholdArtifact,
    KnowledgeThresholdProposal, KnowledgeThresholdProposer, KnowledgeTrialConfig,
    KnowledgeTrialError, KnowledgeTrialExecution, KnowledgeTrialExecutor, ThresholdProposalContext,
    ThresholdProposalError, ThresholdTrialOutcome, promote_to_lago_toml,
};

/// Trial execution contract used by the calibration campaign.
///
/// `KnowledgeTrialExecutor` provides the deterministic local implementation.
/// Future Arcan-backed executors can run the same benchmark through agent
/// sessions while preserving the immutable evaluator and promotion gates.
pub trait KnowledgeTrialRunner {
    fn execute_trial(
        &self,
        artifact: &KnowledgeThresholdArtifact,
        benchmark: &KnowledgeBenchmark,
        index: &KnowledgeIndex,
        config: &KnowledgeTrialConfig,
    ) -> Result<KnowledgeTrialExecution, KnowledgeTrialError>;
}

/// Campaign settings for a bounded EGRI calibration run.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct KnowledgeCalibrationConfig {
    /// Number of proposed artifacts to evaluate, excluding the baseline trial.
    pub max_trials: usize,
    /// Search result count used by each trial.
    pub max_results: usize,
    /// Minimum score delta required to replace the incumbent artifact.
    pub min_score_delta: f64,
    /// Stable prefix used for generated trial identifiers.
    pub trial_id_prefix: String,
    /// Runtime signals collected around each trial.
    pub runtime_signals: KnowledgeRuntimeSignals,
}

/// One proposed artifact and its measured outcome.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct KnowledgeCalibrationTrialRecord {
    pub trial_number: usize,
    pub proposal: KnowledgeThresholdProposal,
    pub execution: KnowledgeTrialExecution,
    /// Score delta against the incumbent before this trial was evaluated.
    pub score_delta: f64,
    /// Whether this trial replaced the incumbent artifact.
    pub accepted_as_incumbent: bool,
}

/// Complete campaign report, suitable for persistence in a Lago event ledger.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct KnowledgeCalibrationReport {
    pub baseline: KnowledgeTrialExecution,
    pub trials: Vec<KnowledgeCalibrationTrialRecord>,
    pub best_trial_id: String,
    pub best_score: f64,
    pub baseline_score: f64,
    pub promotion_record: Option<KnowledgePromotionRecord>,
}

/// Bounded campaign controller.
#[derive(Debug, Clone)]
pub struct KnowledgeCalibrationCampaign<R = KnowledgeTrialExecutor> {
    pub proposer: KnowledgeThresholdProposer,
    pub runner: R,
    pub config: KnowledgeCalibrationConfig,
}

#[derive(Debug, Error)]
pub enum KnowledgeCalibrationError {
    #[error("invalid calibration campaign config: {0}")]
    InvalidConfig(String),
    #[error(transparent)]
    Propose(#[from] ThresholdProposalError),
    #[error(transparent)]
    Execute(#[from] KnowledgeTrialError),
    #[error(transparent)]
    Promote(#[from] KnowledgePromotionError),
}

impl Default for KnowledgeCalibrationConfig {
    fn default() -> Self {
        Self {
            max_trials: 20,
            max_results: 5,
            min_score_delta: 0.001,
            trial_id_prefix: "knowledge-calibration".to_string(),
            runtime_signals: KnowledgeRuntimeSignals::default(),
        }
    }
}

impl Default for KnowledgeCalibrationCampaign<KnowledgeTrialExecutor> {
    fn default() -> Self {
        Self {
            proposer: KnowledgeThresholdProposer::default(),
            runner: KnowledgeTrialExecutor::default(),
            config: KnowledgeCalibrationConfig::default(),
        }
    }
}

impl<R> KnowledgeCalibrationCampaign<R> {
    pub fn new(
        proposer: KnowledgeThresholdProposer,
        runner: R,
        config: KnowledgeCalibrationConfig,
    ) -> Self {
        Self {
            proposer,
            runner,
            config,
        }
    }
}

impl<R> KnowledgeCalibrationCampaign<R>
where
    R: KnowledgeTrialRunner,
{
    /// Run a full calibration campaign.
    ///
    /// If `promotion_path` is provided, the best qualifying artifact is written
    /// to that `lago.toml` path. If no trial beats the baseline by
    /// `min_score_delta`, no promotion is written and the report still records
    /// every attempted trial.
    pub fn run(
        &self,
        baseline_artifact: &KnowledgeThresholdArtifact,
        benchmark: &KnowledgeBenchmark,
        index: &KnowledgeIndex,
        promotion_path: Option<&Path>,
    ) -> Result<KnowledgeCalibrationReport, KnowledgeCalibrationError> {
        self.validate_config()?;

        let baseline = self.runner.execute_trial(
            baseline_artifact,
            benchmark,
            index,
            &KnowledgeTrialConfig {
                trial_id: format!("{}-baseline", self.config.trial_id_prefix),
                max_results: self.config.max_results,
                runtime_signals: self.config.runtime_signals,
            },
        )?;
        let baseline_score = baseline.outcome.score;
        let mut incumbent = baseline.clone();
        let mut context = ThresholdProposalContext::default();
        let mut trials = Vec::with_capacity(self.config.max_trials);

        for trial_number in 1..=self.config.max_trials {
            let proposal = self.proposer.propose(&incumbent.artifact, &context)?;
            let execution = self.runner.execute_trial(
                &proposal.artifact,
                benchmark,
                index,
                &KnowledgeTrialConfig {
                    trial_id: format!("{}-{trial_number:03}", self.config.trial_id_prefix),
                    max_results: self.config.max_results,
                    runtime_signals: self.config.runtime_signals,
                },
            )?;

            let score_delta = execution.outcome.score - incumbent.outcome.score;
            let constraints_passed = execution.outcome.constraints_passed;
            let accepted_as_incumbent =
                constraints_passed && score_delta > self.config.min_score_delta;

            context.trials.push(ThresholdTrialOutcome {
                artifact: execution.artifact.clone(),
                score_delta,
                constraints_passed,
            });

            trials.push(KnowledgeCalibrationTrialRecord {
                trial_number,
                proposal,
                execution: execution.clone(),
                score_delta,
                accepted_as_incumbent,
            });

            if accepted_as_incumbent {
                incumbent = execution;
            }
        }

        let best_score = incumbent.outcome.score;
        let promotion_record = if best_score - baseline_score > self.config.min_score_delta
            && incumbent.outcome.constraints_passed
        {
            promotion_path
                .map(|path| {
                    let request = KnowledgePromotionRequest::new(
                        incumbent.artifact.clone(),
                        incumbent.trial_id.clone(),
                        baseline_score,
                        best_score,
                    );
                    promote_to_lago_toml(path, &request)
                })
                .transpose()?
        } else {
            None
        };

        Ok(KnowledgeCalibrationReport {
            baseline,
            trials,
            best_trial_id: incumbent.trial_id,
            best_score,
            baseline_score,
            promotion_record,
        })
    }

    fn validate_config(&self) -> Result<(), KnowledgeCalibrationError> {
        if self.config.max_trials == 0 {
            return Err(KnowledgeCalibrationError::InvalidConfig(
                "max_trials must be greater than zero".to_string(),
            ));
        }
        if self.config.max_results == 0 {
            return Err(KnowledgeCalibrationError::InvalidConfig(
                "max_results must be greater than zero".to_string(),
            ));
        }
        if self.config.trial_id_prefix.trim().is_empty() {
            return Err(KnowledgeCalibrationError::InvalidConfig(
                "trial_id_prefix must not be empty".to_string(),
            ));
        }
        if !self.config.min_score_delta.is_finite() || self.config.min_score_delta < 0.0 {
            return Err(KnowledgeCalibrationError::InvalidConfig(
                "min_score_delta must be finite and non-negative".to_string(),
            ));
        }

        Ok(())
    }
}

impl KnowledgeCalibrationReport {
    pub fn score_progression(&self) -> Vec<f64> {
        std::iter::once(self.baseline.outcome.score)
            .chain(
                self.trials
                    .iter()
                    .map(|trial| trial.execution.outcome.score),
            )
            .collect()
    }

    pub fn promoted(&self) -> bool {
        self.promotion_record.is_some()
    }
}

impl KnowledgeTrialRunner for KnowledgeTrialExecutor {
    fn execute_trial(
        &self,
        artifact: &KnowledgeThresholdArtifact,
        benchmark: &KnowledgeBenchmark,
        index: &KnowledgeIndex,
        config: &KnowledgeTrialConfig,
    ) -> Result<KnowledgeTrialExecution, KnowledgeTrialError> {
        self.execute(artifact, benchmark, index, config)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use lago_core::ManifestEntry;
    use lago_store::BlobStore;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        BenchmarkRun, KnowledgeQualityMetrics, KnowledgeQualityOutcome, QuestionResult,
        SplitMetrics,
    };

    struct MockArcanRunner {
        calls: Cell<usize>,
    }

    impl MockArcanRunner {
        fn new() -> Self {
            Self {
                calls: Cell::new(0),
            }
        }
    }

    impl KnowledgeTrialRunner for MockArcanRunner {
        fn execute_trial(
            &self,
            artifact: &KnowledgeThresholdArtifact,
            benchmark: &KnowledgeBenchmark,
            _index: &KnowledgeIndex,
            config: &KnowledgeTrialConfig,
        ) -> Result<KnowledgeTrialExecution, KnowledgeTrialError> {
            let call = self.calls.get();
            self.calls.set(call + 1);

            let score = if call == 0 {
                0.70
            } else {
                (0.70 + (call as f64 * 0.01)).min(0.95)
            };
            let benchmark_run = benchmark_run(benchmark.version, score);
            let metrics = KnowledgeQualityMetrics {
                recall_at_1_dev: score,
                recall_at_5_dev: score,
                recall_at_5_holdout: score,
                avg_reasoning_coherence: score,
                knowledge_health: 1.0,
                token_efficiency: 1.0,
                reasoning_speed: 1.0,
                safety_compliance: 1.0,
                total_scenarios: 2,
                passed: 2,
                failed: 0,
                holdout_passed: 1,
                holdout_total: 1,
            };
            let execution_output =
                serde_json::to_string(&metrics).map_err(KnowledgeTrialError::Serialize)?;
            let outcome = KnowledgeQualityOutcome {
                score,
                constraints_passed: true,
                constraint_violations: Vec::new(),
                evaluator_metadata: serde_json::to_value(&metrics)
                    .map_err(crate::KnowledgeQualityError::Metadata)?,
            };

            Ok(KnowledgeTrialExecution {
                trial_id: config.trial_id.clone(),
                artifact: artifact.clone(),
                benchmark_run,
                metrics,
                outcome,
                execution_output,
                duration_ms: 1,
            })
        }
    }

    fn build_index() -> (TempDir, KnowledgeIndex) {
        let tmp = TempDir::new().unwrap();
        let store = BlobStore::open(tmp.path()).unwrap();
        let mut entries = Vec::new();

        for (path, content) in [
            (
                "/journal.md",
                "# Journal\n\nHandles event persistence and replay.",
            ),
            ("/praxis.md", "# Praxis\n\nCanonical tool execution engine."),
        ] {
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

    fn benchmark() -> KnowledgeBenchmark {
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

    fn benchmark_run(version: u32, score: f64) -> BenchmarkRun {
        BenchmarkRun {
            version,
            total_questions: 2,
            dev: SplitMetrics {
                total: 1,
                correct_at_1: usize::from(score >= 0.75),
                correct_at_5: 1,
                recall_at_1: score,
                recall_at_5: score,
            },
            holdout: SplitMetrics {
                total: 1,
                correct_at_1: usize::from(score >= 0.80),
                correct_at_5: 1,
                recall_at_1: score,
                recall_at_5: score,
            },
            questions: vec![
                question("q001", "dev", score >= 0.75),
                question("q002", "holdout", score >= 0.80),
            ],
        }
    }

    fn question(id: &str, split: &str, hit_at_1: bool) -> QuestionResult {
        QuestionResult {
            id: id.to_string(),
            split: split.to_string(),
            expected_top: "expected".to_string(),
            top_result: Some("expected".to_string()),
            top_5_results: vec!["expected".to_string()],
            hit_at_1,
            hit_at_5: true,
        }
    }

    #[test]
    fn full_mock_arcan_campaign_runs_20_trials_and_promotes_best_artifact() {
        let tmp = TempDir::new().unwrap();
        let config_path = tmp.path().join("lago.toml");
        let (_index_tmp, index) = build_index();
        let campaign = KnowledgeCalibrationCampaign::new(
            KnowledgeThresholdProposer::default(),
            MockArcanRunner::new(),
            KnowledgeCalibrationConfig::default(),
        );

        let report = campaign
            .run(
                &KnowledgeThresholdArtifact::default(),
                &benchmark(),
                &index,
                Some(&config_path),
            )
            .unwrap();

        assert_eq!(report.trials.len(), 20);
        assert_eq!(report.baseline_score, 0.70);
        assert!(report.best_score > report.baseline_score);
        assert_eq!(report.best_trial_id, "knowledge-calibration-020");
        assert!(report.promoted());

        let progression = report.score_progression();
        assert_eq!(progression.len(), 21);
        assert!(progression.windows(2).all(|scores| scores[1] > scores[0]));

        let record = report.promotion_record.unwrap();
        assert_eq!(record.trial_id, "knowledge-calibration-020");
        assert_eq!(record.version, "v1");
        assert_eq!(record.baseline_score, 0.70);
        assert!(record.promoted_score > record.baseline_score);

        let contents = std::fs::read_to_string(config_path).unwrap();
        assert!(contents.contains("[knowledge]"));
        assert!(contents.contains("trial_id = \"knowledge-calibration-020\""));
    }

    #[test]
    fn campaign_reports_without_promotion_when_no_trial_improves_baseline() {
        let (_index_tmp, index) = build_index();
        let campaign = KnowledgeCalibrationCampaign::new(
            KnowledgeThresholdProposer::default(),
            MockArcanRunner::new(),
            KnowledgeCalibrationConfig {
                min_score_delta: 1.0,
                ..KnowledgeCalibrationConfig::default()
            },
        );

        let report = campaign
            .run(
                &KnowledgeThresholdArtifact::default(),
                &benchmark(),
                &index,
                None,
            )
            .unwrap();

        assert_eq!(report.trials.len(), 20);
        assert!(!report.promoted());
        assert_eq!(report.best_trial_id, "knowledge-calibration-baseline");
    }

    #[test]
    fn campaign_rejects_invalid_config() {
        let (_index_tmp, index) = build_index();
        let campaign = KnowledgeCalibrationCampaign::new(
            KnowledgeThresholdProposer::default(),
            MockArcanRunner::new(),
            KnowledgeCalibrationConfig {
                max_trials: 0,
                ..KnowledgeCalibrationConfig::default()
            },
        );

        let err = campaign
            .run(
                &KnowledgeThresholdArtifact::default(),
                &benchmark(),
                &index,
                None,
            )
            .unwrap_err();

        assert!(matches!(err, KnowledgeCalibrationError::InvalidConfig(_)));
    }
}
