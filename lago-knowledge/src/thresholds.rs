//! Tunable knowledge calibration thresholds and parameter bounds.

use std::fmt;

use thiserror::Error;

use crate::search::HybridSearchConfig;

const STAGNATION_TRIALS: usize = 5;
const DEAD_END_FAILURES: usize = 3;

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

#[derive(Debug, Clone, Error)]
pub enum ThresholdProposalError {
    #[error(transparent)]
    InvalidCurrent(#[from] ThresholdValidationError),
    #[error("unable to generate a viable threshold proposal after {attempts} attempts")]
    NoViableProposal { attempts: usize },
}

/// Deterministic proposer for bounded EGRI threshold mutations.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct KnowledgeThresholdProposer {
    pub config: ThresholdProposalConfig,
}

/// Controls proposal determinism and mutation expansion policy.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ThresholdProposalConfig {
    /// Stable seed used to make proposal order reproducible across runs.
    pub seed: u64,
    /// Maximum attempts before failing closed.
    pub max_attempts: usize,
    /// Largest absolute step delta before stagnation is detected.
    pub initial_max_step_delta: u8,
    /// Largest absolute step delta after five non-improving trials.
    pub expanded_max_step_delta: u8,
    /// Minimum score delta that counts as improvement.
    pub min_improvement: f64,
}

/// Trial memory supplied by the calibration executor.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ThresholdProposalContext {
    pub trials: Vec<ThresholdTrialOutcome>,
    pub inherited_insights: Vec<ThresholdInsight>,
}

/// Compact outcome summary for stagnation and dead-end detection.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ThresholdTrialOutcome {
    pub artifact: KnowledgeThresholdArtifact,
    pub score_delta: f64,
    pub constraints_passed: bool,
}

/// Cross-run knowledge that restricts already-known bad regions.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ThresholdInsight {
    pub parameter: ThresholdParameter,
    pub avoid_min: Option<ThresholdValue>,
    pub avoid_max: Option<ThresholdValue>,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct KnowledgeThresholdProposal {
    pub artifact: KnowledgeThresholdArtifact,
    pub strategy: ProposalStrategy,
    pub changes: Vec<ThresholdChange>,
    pub stagnation_detected: bool,
    pub rationale: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdParameter {
    Bm25K1,
    Bm25B,
    HybridKeywordBoost,
    HybridGraphBoost,
    HealthThreshold,
    MaxObsBeforeCompact,
    StaleIndexMs,
    FreshnessStaleSecs,
    WakeupTokenBudget,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "value")]
pub enum ThresholdValue {
    F64(f64),
    F32(f32),
    U32(u32),
    U64(u64),
    Usize(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStrategy {
    SingleParameterPerturbation,
    CorrelatedMutation,
    HistoryGuided,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ThresholdChange {
    pub parameter: ThresholdParameter,
    pub before: ThresholdValue,
    pub after: ThresholdValue,
    pub step_delta: i8,
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

impl Default for ThresholdProposalConfig {
    fn default() -> Self {
        Self {
            seed: 0xA10_5EED,
            max_attempts: 64,
            initial_max_step_delta: 2,
            expanded_max_step_delta: 4,
            min_improvement: 0.0,
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

impl KnowledgeThresholdProposer {
    pub fn new(config: ThresholdProposalConfig) -> Self {
        Self { config }
    }

    /// Produce one bounded candidate artifact without executing or promoting it.
    pub fn propose(
        &self,
        current: &KnowledgeThresholdArtifact,
        context: &ThresholdProposalContext,
    ) -> Result<KnowledgeThresholdProposal, ThresholdProposalError> {
        current.validate()?;

        let stagnation_detected = context.is_stagnated(self.config.min_improvement);
        let max_delta = if stagnation_detected {
            self.config.expanded_max_step_delta
        } else {
            self.config.initial_max_step_delta
        }
        .max(1);
        let surface = if stagnation_detected {
            ThresholdParameter::all()
        } else {
            ThresholdParameter::retrieval_surface()
        };
        let mut rng = ProposalRng::new(
            self.config.seed
                ^ stable_artifact_seed(current)
                ^ (context.trials.len() as u64).rotate_left(17),
        );

        for _ in 0..self.config.max_attempts {
            let strategy = choose_strategy(&mut rng);
            let (artifact, changes) = propose_with_strategy(
                current,
                context,
                surface,
                max_delta,
                self.config.min_improvement,
                strategy,
                &mut rng,
            );
            if changes.is_empty() || artifact.validate().is_err() {
                continue;
            }
            if changes.iter().any(|change| {
                context.is_dead_end(change.parameter, &change.after, self.config.min_improvement)
                    || context.is_rejected_by_insight(change.parameter, &change.after)
            }) {
                continue;
            }

            let rationale = match strategy {
                ProposalStrategy::SingleParameterPerturbation => {
                    "bounded single-parameter perturbation".to_string()
                }
                ProposalStrategy::CorrelatedMutation => {
                    "bounded correlated mutation across coupled thresholds".to_string()
                }
                ProposalStrategy::HistoryGuided => {
                    "history-guided mutation avoiding inherited and observed dead ends".to_string()
                }
            };

            return Ok(KnowledgeThresholdProposal {
                artifact,
                strategy,
                changes,
                stagnation_detected,
                rationale,
            });
        }

        Err(ThresholdProposalError::NoViableProposal {
            attempts: self.config.max_attempts,
        })
    }
}

impl ThresholdProposalContext {
    pub fn is_stagnated(&self, min_improvement: f64) -> bool {
        if self.trials.len() < STAGNATION_TRIALS {
            return false;
        }

        self.trials
            .iter()
            .rev()
            .take(STAGNATION_TRIALS)
            .all(|trial| trial.is_failure(min_improvement))
    }

    pub fn is_dead_end(
        &self,
        parameter: ThresholdParameter,
        value: &ThresholdValue,
        min_improvement: f64,
    ) -> bool {
        self.trials
            .iter()
            .filter(|trial| trial.is_failure(min_improvement))
            .filter(|trial| parameter.value(&trial.artifact) == *value)
            .take(DEAD_END_FAILURES)
            .count()
            >= DEAD_END_FAILURES
    }

    pub fn is_rejected_by_insight(
        &self,
        parameter: ThresholdParameter,
        value: &ThresholdValue,
    ) -> bool {
        self.inherited_insights
            .iter()
            .any(|insight| insight.rejects(parameter, value))
    }
}

impl ThresholdTrialOutcome {
    fn is_failure(&self, min_improvement: f64) -> bool {
        !self.constraints_passed || self.score_delta <= min_improvement
    }
}

impl ThresholdInsight {
    fn rejects(&self, parameter: ThresholdParameter, value: &ThresholdValue) -> bool {
        if self.parameter != parameter {
            return false;
        }

        let above_min = self
            .avoid_min
            .as_ref()
            .is_none_or(|min| threshold_value_cmp(value, min).is_some_and(|ord| ord.is_ge()));
        let below_max = self
            .avoid_max
            .as_ref()
            .is_none_or(|max| threshold_value_cmp(value, max).is_some_and(|ord| ord.is_le()));
        above_min && below_max
    }
}

impl ThresholdParameter {
    pub const fn all() -> &'static [Self] {
        &[
            Self::Bm25K1,
            Self::Bm25B,
            Self::HybridKeywordBoost,
            Self::HybridGraphBoost,
            Self::HealthThreshold,
            Self::MaxObsBeforeCompact,
            Self::StaleIndexMs,
            Self::FreshnessStaleSecs,
            Self::WakeupTokenBudget,
        ]
    }

    pub const fn retrieval_surface() -> &'static [Self] {
        &[
            Self::Bm25K1,
            Self::Bm25B,
            Self::HybridKeywordBoost,
            Self::HybridGraphBoost,
            Self::FreshnessStaleSecs,
            Self::WakeupTokenBudget,
        ]
    }

    pub fn value(self, artifact: &KnowledgeThresholdArtifact) -> ThresholdValue {
        match self {
            Self::Bm25K1 => ThresholdValue::F64(artifact.bm25_k1),
            Self::Bm25B => ThresholdValue::F64(artifact.bm25_b),
            Self::HybridKeywordBoost => ThresholdValue::F64(artifact.hybrid_keyword_boost),
            Self::HybridGraphBoost => ThresholdValue::F64(artifact.hybrid_graph_boost),
            Self::HealthThreshold => ThresholdValue::F32(artifact.health_threshold),
            Self::MaxObsBeforeCompact => ThresholdValue::U32(artifact.max_obs_before_compact),
            Self::StaleIndexMs => ThresholdValue::U64(artifact.stale_index_ms),
            Self::FreshnessStaleSecs => ThresholdValue::U64(artifact.freshness_stale_secs),
            Self::WakeupTokenBudget => ThresholdValue::Usize(artifact.wakeup_token_budget),
        }
    }
}

impl fmt::Display for ThresholdParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Bm25K1 => "bm25_k1",
            Self::Bm25B => "bm25_b",
            Self::HybridKeywordBoost => "hybrid_keyword_boost",
            Self::HybridGraphBoost => "hybrid_graph_boost",
            Self::HealthThreshold => "health_threshold",
            Self::MaxObsBeforeCompact => "max_obs_before_compact",
            Self::StaleIndexMs => "stale_index_ms",
            Self::FreshnessStaleSecs => "freshness_stale_secs",
            Self::WakeupTokenBudget => "wakeup_token_budget",
        };
        f.write_str(name)
    }
}

impl fmt::Display for ThresholdValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::F64(value) => write!(f, "{value:.6}"),
            Self::F32(value) => write!(f, "{value:.6}"),
            Self::U32(value) => write!(f, "{value}"),
            Self::U64(value) => write!(f, "{value}"),
            Self::Usize(value) => write!(f, "{value}"),
        }
    }
}

fn propose_with_strategy(
    current: &KnowledgeThresholdArtifact,
    context: &ThresholdProposalContext,
    surface: &[ThresholdParameter],
    max_delta: u8,
    min_improvement: f64,
    strategy: ProposalStrategy,
    rng: &mut ProposalRng,
) -> (KnowledgeThresholdArtifact, Vec<ThresholdChange>) {
    match strategy {
        ProposalStrategy::SingleParameterPerturbation => {
            let parameter = surface[rng.choose_index(surface.len())];
            let delta = rng.choose_step_delta(max_delta);
            apply_changes(current, &[(parameter, delta)])
        }
        ProposalStrategy::CorrelatedMutation => {
            let group = correlated_group(surface, rng);
            apply_changes(current, &group)
        }
        ProposalStrategy::HistoryGuided => {
            let parameter = guided_parameter(current, context, surface, min_improvement)
                .unwrap_or_else(|| surface[rng.choose_index(surface.len())]);
            let direction = guided_direction(current, context, parameter, min_improvement)
                .unwrap_or_else(|| if rng.next_bool() { 1 } else { -1 });
            apply_changes(
                current,
                &[(parameter, direction * i8::try_from(max_delta).unwrap_or(1))],
            )
        }
    }
}

fn choose_strategy(rng: &mut ProposalRng) -> ProposalStrategy {
    match rng.next_percent() {
        0..=59 => ProposalStrategy::SingleParameterPerturbation,
        60..=89 => ProposalStrategy::CorrelatedMutation,
        _ => ProposalStrategy::HistoryGuided,
    }
}

fn correlated_group(
    surface: &[ThresholdParameter],
    rng: &mut ProposalRng,
) -> Vec<(ThresholdParameter, i8)> {
    let groups: &[&[(ThresholdParameter, i8)]] = &[
        &[
            (ThresholdParameter::Bm25K1, 1),
            (ThresholdParameter::Bm25B, -1),
        ],
        &[
            (ThresholdParameter::HybridKeywordBoost, 1),
            (ThresholdParameter::HybridGraphBoost, 1),
        ],
        &[
            (ThresholdParameter::FreshnessStaleSecs, -1),
            (ThresholdParameter::WakeupTokenBudget, 1),
        ],
        &[
            (ThresholdParameter::HealthThreshold, 1),
            (ThresholdParameter::MaxObsBeforeCompact, -1),
        ],
    ];
    let available: Vec<&[(ThresholdParameter, i8)]> = groups
        .iter()
        .copied()
        .filter(|group| {
            group
                .iter()
                .all(|(parameter, _)| surface.contains(parameter))
        })
        .collect();
    let group = available[rng.choose_index(available.len())];
    let direction = if rng.next_bool() { 1 } else { -1 };
    group
        .iter()
        .map(|(parameter, delta)| (*parameter, delta * direction))
        .collect()
}

fn guided_parameter(
    current: &KnowledgeThresholdArtifact,
    context: &ThresholdProposalContext,
    surface: &[ThresholdParameter],
    min_improvement: f64,
) -> Option<ThresholdParameter> {
    surface.iter().copied().find(|parameter| {
        let value = parameter.value(current);
        context.is_dead_end(*parameter, &value, min_improvement)
            || context.is_rejected_by_insight(*parameter, &value)
    })
}

fn guided_direction(
    current: &KnowledgeThresholdArtifact,
    context: &ThresholdProposalContext,
    parameter: ThresholdParameter,
    min_improvement: f64,
) -> Option<i8> {
    let current_value = parameter.value(current);
    if context.is_rejected_by_insight(parameter, &current_value) {
        return Some(1);
    }

    let failed_values: Vec<ThresholdValue> = context
        .trials
        .iter()
        .filter(|trial| trial.is_failure(min_improvement))
        .map(|trial| parameter.value(&trial.artifact))
        .collect();
    if failed_values.is_empty() {
        return None;
    }

    let failed_average = average_threshold_value(&failed_values)?;
    let current_numeric = threshold_value_as_f64(&current_value)?;
    if current_numeric >= failed_average {
        Some(1)
    } else {
        Some(-1)
    }
}

fn apply_changes(
    current: &KnowledgeThresholdArtifact,
    changes: &[(ThresholdParameter, i8)],
) -> (KnowledgeThresholdArtifact, Vec<ThresholdChange>) {
    let mut artifact = current.clone();
    let mut applied = Vec::new();

    for (parameter, step_delta) in changes {
        let before = parameter.value(&artifact);
        mutate_parameter(&mut artifact, *parameter, *step_delta);
        let after = parameter.value(&artifact);
        if before != after {
            applied.push(ThresholdChange {
                parameter: *parameter,
                before,
                after,
                step_delta: *step_delta,
            });
        }
    }

    (artifact, applied)
}

fn mutate_parameter(
    artifact: &mut KnowledgeThresholdArtifact,
    parameter: ThresholdParameter,
    delta: i8,
) {
    let bounds = KnowledgeThresholdArtifact::bounds();
    match parameter {
        ThresholdParameter::Bm25K1 => {
            artifact.bm25_k1 = mutate_f64(artifact.bm25_k1, bounds.bm25_k1, delta)
        }
        ThresholdParameter::Bm25B => {
            artifact.bm25_b = mutate_f64(artifact.bm25_b, bounds.bm25_b, delta)
        }
        ThresholdParameter::HybridKeywordBoost => {
            artifact.hybrid_keyword_boost = mutate_f64(
                artifact.hybrid_keyword_boost,
                bounds.hybrid_keyword_boost,
                delta,
            )
        }
        ThresholdParameter::HybridGraphBoost => {
            artifact.hybrid_graph_boost = mutate_f64(
                artifact.hybrid_graph_boost,
                bounds.hybrid_graph_boost,
                delta,
            )
        }
        ThresholdParameter::HealthThreshold => {
            artifact.health_threshold =
                mutate_f32(artifact.health_threshold, bounds.health_threshold, delta)
        }
        ThresholdParameter::MaxObsBeforeCompact => {
            artifact.max_obs_before_compact = mutate_u32(
                artifact.max_obs_before_compact,
                bounds.max_obs_before_compact,
                delta,
            )
        }
        ThresholdParameter::StaleIndexMs => {
            artifact.stale_index_ms =
                mutate_u64(artifact.stale_index_ms, bounds.stale_index_ms, delta)
        }
        ThresholdParameter::FreshnessStaleSecs => {
            artifact.freshness_stale_secs = mutate_u64(
                artifact.freshness_stale_secs,
                bounds.freshness_stale_secs,
                delta,
            )
        }
        ThresholdParameter::WakeupTokenBudget => {
            artifact.wakeup_token_budget = mutate_usize(
                artifact.wakeup_token_budget,
                bounds.wakeup_token_budget,
                delta,
            )
        }
    }
}

fn mutate_f64(value: f64, bound: NumericBound<f64>, delta: i8) -> f64 {
    let max_steps = ((bound.max - bound.min) / bound.step).round() as i64;
    let current_steps = ((value - bound.min) / bound.step).round() as i64;
    let next_steps = (current_steps + i64::from(delta)).clamp(0, max_steps);
    round_f64(bound.min + bound.step * next_steps as f64)
}

fn mutate_f32(value: f32, bound: NumericBound<f32>, delta: i8) -> f32 {
    let max_steps = ((bound.max - bound.min) / bound.step).round() as i64;
    let current_steps = ((value - bound.min) / bound.step).round() as i64;
    let next_steps = (current_steps + i64::from(delta)).clamp(0, max_steps);
    round_f32(bound.min + bound.step * next_steps as f32)
}

fn mutate_u32(value: u32, bound: NumericBound<u32>, delta: i8) -> u32 {
    let max_steps = ((bound.max - bound.min) / bound.step) as i64;
    let current_steps = ((value - bound.min) / bound.step) as i64;
    let next_steps = (current_steps + i64::from(delta)).clamp(0, max_steps);
    bound.min + bound.step * next_steps as u32
}

fn mutate_u64(value: u64, bound: NumericBound<u64>, delta: i8) -> u64 {
    let max_steps = ((bound.max - bound.min) / bound.step) as i64;
    let current_steps = ((value - bound.min) / bound.step) as i64;
    let next_steps = (current_steps + i64::from(delta)).clamp(0, max_steps);
    bound.min + bound.step * next_steps as u64
}

fn mutate_usize(value: usize, bound: NumericBound<usize>, delta: i8) -> usize {
    let max_steps = ((bound.max - bound.min) / bound.step) as i64;
    let current_steps = ((value - bound.min) / bound.step) as i64;
    let next_steps = (current_steps + i64::from(delta)).clamp(0, max_steps);
    bound.min + bound.step * next_steps as usize
}

fn round_f64(value: f64) -> f64 {
    (value * 1_000_000.0).round() / 1_000_000.0
}

fn round_f32(value: f32) -> f32 {
    (value * 1_000_000.0).round() / 1_000_000.0
}

fn threshold_value_cmp(
    left: &ThresholdValue,
    right: &ThresholdValue,
) -> Option<std::cmp::Ordering> {
    match (threshold_value_as_f64(left), threshold_value_as_f64(right)) {
        (Some(left), Some(right)) => left.partial_cmp(&right),
        _ => None,
    }
}

fn threshold_value_as_f64(value: &ThresholdValue) -> Option<f64> {
    match value {
        ThresholdValue::F64(value) => Some(*value),
        ThresholdValue::F32(value) => Some(f64::from(*value)),
        ThresholdValue::U32(value) => Some(f64::from(*value)),
        ThresholdValue::U64(value) => Some(*value as f64),
        ThresholdValue::Usize(value) => Some(*value as f64),
    }
}

fn average_threshold_value(values: &[ThresholdValue]) -> Option<f64> {
    let mut total = 0.0;
    for value in values {
        total += threshold_value_as_f64(value)?;
    }
    Some(total / values.len() as f64)
}

fn stable_artifact_seed(artifact: &KnowledgeThresholdArtifact) -> u64 {
    artifact.bm25_k1.to_bits()
        ^ artifact.bm25_b.to_bits().rotate_left(7)
        ^ artifact.hybrid_keyword_boost.to_bits().rotate_left(13)
        ^ artifact.hybrid_graph_boost.to_bits().rotate_left(19)
        ^ u64::from(artifact.health_threshold.to_bits()).rotate_left(23)
        ^ u64::from(artifact.max_obs_before_compact).rotate_left(29)
        ^ artifact.stale_index_ms.rotate_left(31)
        ^ artifact.freshness_stale_secs.rotate_left(37)
        ^ (artifact.wakeup_token_budget as u64).rotate_left(43)
}

struct ProposalRng {
    state: u64,
}

impl ProposalRng {
    fn new(seed: u64) -> Self {
        Self { state: seed.max(1) }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.state
    }

    fn next_percent(&mut self) -> u8 {
        (self.next_u64() % 100) as u8
    }

    fn next_bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    fn choose_index(&mut self, len: usize) -> usize {
        debug_assert!(len > 0);
        (self.next_u64() as usize) % len
    }

    fn choose_step_delta(&mut self, max_abs: u8) -> i8 {
        let max_abs = max_abs.max(1);
        let magnitude = (self.next_u64() % u64::from(max_abs) + 1) as i8;
        if self.next_bool() {
            magnitude
        } else {
            -magnitude
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
        let artifact = KnowledgeThresholdArtifact {
            bm25_k1: 3.2,
            health_threshold: 0.2,
            ..KnowledgeThresholdArtifact::default()
        };

        let err = artifact.validate().unwrap_err();
        assert_eq!(err.issues.len(), 2);
        assert!(err.issues[0].contains("bm25_k1"));
        assert!(err.issues[1].contains("health_threshold"));
    }

    #[test]
    fn validation_rejects_non_step_aligned_values() {
        let artifact = KnowledgeThresholdArtifact {
            hybrid_keyword_boost: 0.33,
            max_obs_before_compact: 55,
            ..KnowledgeThresholdArtifact::default()
        };

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

    #[test]
    fn proposer_generates_valid_deterministic_bounded_candidate() {
        let proposer = KnowledgeThresholdProposer::new(ThresholdProposalConfig {
            seed: 42,
            ..ThresholdProposalConfig::default()
        });
        let context = ThresholdProposalContext::default();
        let current = KnowledgeThresholdArtifact::default();

        let first = proposer.propose(&current, &context).unwrap();
        let second = proposer.propose(&current, &context).unwrap();

        assert_eq!(first, second);
        assert!(!first.changes.is_empty());
        first.artifact.validate().unwrap();
        assert_ne!(first.artifact, current);
    }

    #[test]
    fn context_detects_stagnation_after_five_non_improving_trials() {
        let context = ThresholdProposalContext {
            trials: (0..5)
                .map(|_| ThresholdTrialOutcome {
                    artifact: KnowledgeThresholdArtifact::default(),
                    score_delta: 0.0,
                    constraints_passed: true,
                })
                .collect(),
            inherited_insights: Vec::new(),
        };

        assert!(context.is_stagnated(0.0));
    }

    #[test]
    fn context_does_not_stagnate_when_recent_trial_improves() {
        let mut trials: Vec<ThresholdTrialOutcome> = (0..4)
            .map(|_| ThresholdTrialOutcome {
                artifact: KnowledgeThresholdArtifact::default(),
                score_delta: 0.0,
                constraints_passed: true,
            })
            .collect();
        trials.push(ThresholdTrialOutcome {
            artifact: KnowledgeThresholdArtifact::default(),
            score_delta: 0.01,
            constraints_passed: true,
        });
        let context = ThresholdProposalContext {
            trials,
            inherited_insights: Vec::new(),
        };

        assert!(!context.is_stagnated(0.0));
    }

    #[test]
    fn context_marks_repeated_failed_regions_as_dead_ends() {
        let failed = KnowledgeThresholdArtifact {
            bm25_k1: 0.8,
            ..KnowledgeThresholdArtifact::default()
        };
        let context = ThresholdProposalContext {
            trials: (0..3)
                .map(|_| ThresholdTrialOutcome {
                    artifact: failed.clone(),
                    score_delta: -0.05,
                    constraints_passed: true,
                })
                .collect(),
            inherited_insights: Vec::new(),
        };

        assert!(context.is_dead_end(ThresholdParameter::Bm25K1, &ThresholdValue::F64(0.8), 0.0));
        assert!(!context.is_dead_end(ThresholdParameter::Bm25K1, &ThresholdValue::F64(0.9), 0.0));
    }

    #[test]
    fn inherited_insight_rejects_avoided_range() {
        let context = ThresholdProposalContext {
            trials: Vec::new(),
            inherited_insights: vec![ThresholdInsight {
                parameter: ThresholdParameter::Bm25K1,
                avoid_min: Some(ThresholdValue::F64(0.5)),
                avoid_max: Some(ThresholdValue::F64(0.8)),
                rationale: "low k1 underperformed on prior campaigns".to_string(),
            }],
        };

        assert!(
            context.is_rejected_by_insight(ThresholdParameter::Bm25K1, &ThresholdValue::F64(0.7))
        );
        assert!(
            !context.is_rejected_by_insight(ThresholdParameter::Bm25K1, &ThresholdValue::F64(1.2))
        );
    }

    #[test]
    fn stagnation_expands_proposer_surface_to_regulation_thresholds() {
        let proposer = KnowledgeThresholdProposer::new(ThresholdProposalConfig {
            seed: 3,
            max_attempts: 128,
            ..ThresholdProposalConfig::default()
        });
        let context = ThresholdProposalContext {
            trials: (0..5)
                .map(|_| ThresholdTrialOutcome {
                    artifact: KnowledgeThresholdArtifact::default(),
                    score_delta: 0.0,
                    constraints_passed: true,
                })
                .collect(),
            inherited_insights: Vec::new(),
        };

        let proposal = proposer
            .propose(&KnowledgeThresholdArtifact::default(), &context)
            .unwrap();

        assert!(proposal.stagnation_detected);
        proposal.artifact.validate().unwrap();
    }
}
