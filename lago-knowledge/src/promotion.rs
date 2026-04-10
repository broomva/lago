//! Promotion pipeline for EGRI knowledge-threshold calibration.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use chrono::{SecondsFormat, Utc};
use lago_core::{
    BranchId, EventEnvelope, EventId, EventPayload, Journal, LagoResult, SeqNo, SessionId,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use crate::{KnowledgeThresholdArtifact, ThresholdValidationError};

pub const KNOWLEDGE_PROMOTED_EVENT_TYPE: &str = "egri.knowledge.promoted";

const ARTIFACT_PARAMETERS: &[&str] = &[
    "bm25_k1",
    "bm25_b",
    "hybrid_keyword_boost",
    "hybrid_graph_boost",
    "health_threshold",
    "max_obs_before_compact",
    "stale_index_ms",
    "freshness_stale_secs",
    "wakeup_token_budget",
];

/// Promotion request accepted after the immutable evaluator approves a trial.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KnowledgePromotionRequest {
    pub artifact: KnowledgeThresholdArtifact,
    pub trial_id: String,
    pub baseline_score: f64,
    pub promoted_score: f64,
    pub promoted_at: String,
}

/// Concrete `[knowledge]` section persisted in `lago.toml`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PromotedKnowledgeConfig {
    pub bm25_k1: f64,
    pub bm25_b: f64,
    pub hybrid_keyword_boost: f64,
    pub hybrid_graph_boost: f64,
    pub health_threshold: f32,
    pub max_obs_before_compact: u32,
    pub stale_index_ms: u64,
    pub freshness_stale_secs: u64,
    pub wakeup_token_budget: usize,
    pub version: String,
    pub promoted_at: String,
    pub trial_id: String,
    pub baseline_score: f64,
    pub promoted_score: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_target: Option<String>,
}

/// Result of a successful promotion write.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KnowledgePromotionRecord {
    pub config_path: String,
    pub artifact: KnowledgeThresholdArtifact,
    pub version: String,
    pub rollback_target: Option<String>,
    pub promoted_at: String,
    pub trial_id: String,
    pub baseline_score: f64,
    pub promoted_score: f64,
    pub parameters_changed: Vec<String>,
}

#[derive(Debug, Error)]
pub enum KnowledgePromotionError {
    #[error(transparent)]
    InvalidArtifact(#[from] ThresholdValidationError),
    #[error("invalid promotion request: {0}")]
    InvalidRequest(String),
    #[error("failed to read config file {path}: {source}")]
    ReadConfig {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write config file {path}: {source}")]
    WriteConfig {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to create config directory {path}: {source}")]
    CreateConfigDir {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config file {path}: {source}")]
    ParseConfig {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("failed to serialize knowledge config: {0}")]
    SerializeConfig(#[from] toml::ser::Error),
    #[error("invalid promoted knowledge version: {0}")]
    InvalidVersion(String),
    #[error("knowledge config lock poisoned for {0}")]
    LockPoisoned(String),
}

#[derive(Debug, Clone, Default, Deserialize)]
struct KnowledgeConfigFile {
    knowledge: Option<toml::Value>,
}

impl KnowledgePromotionRequest {
    pub fn new(
        artifact: KnowledgeThresholdArtifact,
        trial_id: impl Into<String>,
        baseline_score: f64,
        promoted_score: f64,
    ) -> Self {
        Self {
            artifact,
            trial_id: trial_id.into(),
            baseline_score,
            promoted_score,
            promoted_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        }
    }

    pub fn with_promoted_at(mut self, promoted_at: impl Into<String>) -> Self {
        self.promoted_at = promoted_at.into();
        self
    }

    fn validate(&self) -> Result<(), KnowledgePromotionError> {
        self.artifact.validate()?;

        if self.trial_id.trim().is_empty() {
            return Err(KnowledgePromotionError::InvalidRequest(
                "trial_id must not be empty".to_string(),
            ));
        }
        if self.promoted_at.trim().is_empty() {
            return Err(KnowledgePromotionError::InvalidRequest(
                "promoted_at must not be empty".to_string(),
            ));
        }
        if !self.baseline_score.is_finite() || !self.promoted_score.is_finite() {
            return Err(KnowledgePromotionError::InvalidRequest(
                "baseline_score and promoted_score must be finite".to_string(),
            ));
        }

        Ok(())
    }
}

impl PromotedKnowledgeConfig {
    pub fn artifact(&self) -> KnowledgeThresholdArtifact {
        KnowledgeThresholdArtifact {
            bm25_k1: self.bm25_k1,
            bm25_b: self.bm25_b,
            hybrid_keyword_boost: self.hybrid_keyword_boost,
            hybrid_graph_boost: self.hybrid_graph_boost,
            health_threshold: self.health_threshold,
            max_obs_before_compact: self.max_obs_before_compact,
            stale_index_ms: self.stale_index_ms,
            freshness_stale_secs: self.freshness_stale_secs,
            wakeup_token_budget: self.wakeup_token_budget,
        }
    }

    fn from_request(
        request: &KnowledgePromotionRequest,
        version: String,
        rollback_target: Option<String>,
    ) -> Self {
        Self {
            bm25_k1: request.artifact.bm25_k1,
            bm25_b: request.artifact.bm25_b,
            hybrid_keyword_boost: request.artifact.hybrid_keyword_boost,
            hybrid_graph_boost: request.artifact.hybrid_graph_boost,
            health_threshold: request.artifact.health_threshold,
            max_obs_before_compact: request.artifact.max_obs_before_compact,
            stale_index_ms: request.artifact.stale_index_ms,
            freshness_stale_secs: request.artifact.freshness_stale_secs,
            wakeup_token_budget: request.artifact.wakeup_token_budget,
            version,
            promoted_at: request.promoted_at.clone(),
            trial_id: request.trial_id.clone(),
            baseline_score: request.baseline_score,
            promoted_score: request.promoted_score,
            rollback_target,
        }
    }
}

impl KnowledgePromotionRecord {
    pub fn event_data(&self) -> serde_json::Value {
        json!({
            "trial_id": self.trial_id,
            "version": self.version,
            "rollback_target": self.rollback_target,
            "baseline_score": self.baseline_score,
            "promoted_score": self.promoted_score,
            "parameters_changed": self.parameters_changed,
            "promoted_at": self.promoted_at,
            "config_path": self.config_path,
            "artifact": self.artifact,
        })
    }

    pub fn event_payload(&self) -> EventPayload {
        EventPayload::Custom {
            event_type: KNOWLEDGE_PROMOTED_EVENT_TYPE.to_string(),
            data: self.event_data(),
        }
    }

    pub fn event_envelope(&self, session_id: SessionId, branch_id: BranchId) -> EventEnvelope {
        EventEnvelope {
            event_id: EventId::new(),
            session_id,
            branch_id,
            run_id: None,
            seq: 0,
            timestamp: EventEnvelope::now_micros(),
            parent_id: None,
            payload: self.event_payload(),
            metadata: HashMap::from([
                (
                    "egri.artifact".to_string(),
                    "knowledge_thresholds".to_string(),
                ),
                ("egri.event".to_string(), "promotion".to_string()),
                ("egri.version".to_string(), self.version.clone()),
                ("egri.trial_id".to_string(), self.trial_id.clone()),
            ]),
            schema_version: 1,
        }
    }
}

pub fn load_promoted_knowledge_config(
    path: &Path,
) -> Result<Option<PromotedKnowledgeConfig>, KnowledgePromotionError> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(KnowledgePromotionError::ReadConfig {
                path: path.display().to_string(),
                source,
            });
        }
    };

    parse_promoted_knowledge_config(path, &contents)
}

pub fn promote_to_lago_toml(
    path: &Path,
    request: &KnowledgePromotionRequest,
) -> Result<KnowledgePromotionRecord, KnowledgePromotionError> {
    request.validate()?;

    let lock = promotion_lock(path)?;
    let _guard = lock
        .lock()
        .map_err(|_| KnowledgePromotionError::LockPoisoned(path.display().to_string()))?;

    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(source) => {
            return Err(KnowledgePromotionError::ReadConfig {
                path: path.display().to_string(),
                source,
            });
        }
    };

    let previous = parse_promoted_knowledge_config(path, &contents)?;
    let rollback_target = previous.as_ref().map(|config| config.version.clone());
    let version = next_version(rollback_target.as_deref())?;
    let promoted_config =
        PromotedKnowledgeConfig::from_request(request, version.clone(), rollback_target.clone());
    let section = render_knowledge_section(&promoted_config)?;
    let updated = replace_knowledge_section(&contents, &section);

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|source| {
            KnowledgePromotionError::CreateConfigDir {
                path: parent.display().to_string(),
                source,
            }
        })?;
    }

    let temp_path = promotion_temp_path(path);
    std::fs::write(&temp_path, updated).map_err(|source| KnowledgePromotionError::WriteConfig {
        path: temp_path.display().to_string(),
        source,
    })?;
    std::fs::rename(&temp_path, path).map_err(|source| KnowledgePromotionError::WriteConfig {
        path: path.display().to_string(),
        source,
    })?;

    Ok(KnowledgePromotionRecord {
        config_path: path.display().to_string(),
        artifact: request.artifact.clone(),
        version,
        rollback_target,
        promoted_at: request.promoted_at.clone(),
        trial_id: request.trial_id.clone(),
        baseline_score: request.baseline_score,
        promoted_score: request.promoted_score,
        parameters_changed: parameters_changed(previous.as_ref(), &request.artifact),
    })
}

pub async fn publish_promotion_event(
    journal: &dyn Journal,
    session_id: SessionId,
    branch_id: BranchId,
    record: &KnowledgePromotionRecord,
) -> LagoResult<SeqNo> {
    journal
        .append(record.event_envelope(session_id, branch_id))
        .await
}

fn parse_promoted_knowledge_config(
    path: &Path,
    contents: &str,
) -> Result<Option<PromotedKnowledgeConfig>, KnowledgePromotionError> {
    let parsed: KnowledgeConfigFile =
        toml::from_str(contents).map_err(|source| KnowledgePromotionError::ParseConfig {
            path: path.display().to_string(),
            source,
        })?;
    let Some(knowledge) = parsed.knowledge else {
        return Ok(None);
    };
    if !has_promotion_metadata(&knowledge) {
        return Ok(None);
    }
    knowledge
        .try_into()
        .map(Some)
        .map_err(|source| KnowledgePromotionError::ParseConfig {
            path: path.display().to_string(),
            source,
        })
}

fn has_promotion_metadata(value: &toml::Value) -> bool {
    let Some(table) = value.as_table() else {
        return false;
    };
    [
        "version",
        "promoted_at",
        "trial_id",
        "baseline_score",
        "promoted_score",
        "rollback_target",
    ]
    .iter()
    .any(|key| table.contains_key(*key))
}

fn promotion_locks() -> &'static Mutex<HashMap<PathBuf, Arc<Mutex<()>>>> {
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();
    LOCKS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn promotion_lock(path: &Path) -> Result<Arc<Mutex<()>>, KnowledgePromotionError> {
    let key = promotion_lock_key(path)?;
    let mut locks = promotion_locks()
        .lock()
        .map_err(|_| KnowledgePromotionError::LockPoisoned(path.display().to_string()))?;
    Ok(locks
        .entry(key)
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone())
}

fn promotion_lock_key(path: &Path) -> Result<PathBuf, KnowledgePromotionError> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|source| KnowledgePromotionError::ReadConfig {
                path: path.display().to_string(),
                source,
            })
    }
}

fn promotion_temp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("lago.toml");
    let temp_name = format!(".{file_name}.{}.tmp", EventId::new());
    path.with_file_name(temp_name)
}

fn render_knowledge_section(
    config: &PromotedKnowledgeConfig,
) -> Result<String, KnowledgePromotionError> {
    let mut section = String::from("[knowledge]\n");
    section.push_str(&toml::to_string_pretty(config)?);
    if !section.ends_with('\n') {
        section.push('\n');
    }
    Ok(section)
}

fn replace_knowledge_section(contents: &str, section: &str) -> String {
    let lines: Vec<&str> = contents.lines().collect();
    let Some(start) = lines.iter().position(|line| line.trim() == "[knowledge]") else {
        let trimmed = contents.trim_end();
        if trimmed.is_empty() {
            return section.to_string();
        }
        return format!("{trimmed}\n\n{section}");
    };

    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, line)| is_toml_table_header(line))
        .map(|(idx, _)| idx)
        .unwrap_or(lines.len());

    let mut output = String::new();
    if start > 0 {
        output.push_str(&lines[..start].join("\n"));
        output.push_str("\n\n");
    }
    output.push_str(section);
    if end < lines.len() {
        output.push('\n');
        output.push_str(&lines[end..].join("\n"));
        output.push('\n');
    }
    output
}

fn is_toml_table_header(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with('[') && trimmed.ends_with(']') && !trimmed.starts_with('#')
}

fn next_version(previous: Option<&str>) -> Result<String, KnowledgePromotionError> {
    match previous {
        None => Ok("v1".to_string()),
        Some(version) => {
            let numeric = version
                .strip_prefix('v')
                .ok_or_else(|| KnowledgePromotionError::InvalidVersion(version.to_string()))?;
            let value = numeric
                .parse::<u64>()
                .map_err(|_| KnowledgePromotionError::InvalidVersion(version.to_string()))?;
            Ok(format!("v{}", value + 1))
        }
    }
}

fn parameters_changed(
    previous: Option<&PromotedKnowledgeConfig>,
    artifact: &KnowledgeThresholdArtifact,
) -> Vec<String> {
    let Some(previous) = previous else {
        return ARTIFACT_PARAMETERS
            .iter()
            .map(|name| (*name).to_string())
            .collect();
    };
    let old = previous.artifact();
    let mut changed = Vec::new();

    push_changed(&mut changed, "bm25_k1", old.bm25_k1, artifact.bm25_k1);
    push_changed(&mut changed, "bm25_b", old.bm25_b, artifact.bm25_b);
    push_changed(
        &mut changed,
        "hybrid_keyword_boost",
        old.hybrid_keyword_boost,
        artifact.hybrid_keyword_boost,
    );
    push_changed(
        &mut changed,
        "hybrid_graph_boost",
        old.hybrid_graph_boost,
        artifact.hybrid_graph_boost,
    );
    if old.health_threshold != artifact.health_threshold {
        changed.push("health_threshold".to_string());
    }
    if old.max_obs_before_compact != artifact.max_obs_before_compact {
        changed.push("max_obs_before_compact".to_string());
    }
    if old.stale_index_ms != artifact.stale_index_ms {
        changed.push("stale_index_ms".to_string());
    }
    if old.freshness_stale_secs != artifact.freshness_stale_secs {
        changed.push("freshness_stale_secs".to_string());
    }
    if old.wakeup_token_budget != artifact.wakeup_token_budget {
        changed.push("wakeup_token_budget".to_string());
    }
    changed
}

fn push_changed(changed: &mut Vec<String>, name: &str, old: f64, new: f64) {
    if (old - new).abs() > f64::EPSILON {
        changed.push(name.to_string());
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn request() -> KnowledgePromotionRequest {
        KnowledgePromotionRequest::new(
            KnowledgeThresholdArtifact::default(),
            "trial-042",
            0.72,
            0.85,
        )
        .with_promoted_at("2026-04-08T12:00:00Z")
    }

    #[test]
    fn first_promotion_writes_knowledge_section() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("lago.toml");

        let record = promote_to_lago_toml(&path, &request()).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        let loaded = load_promoted_knowledge_config(&path).unwrap().unwrap();

        assert_eq!(record.version, "v1");
        assert_eq!(record.rollback_target, None);
        assert_eq!(loaded.version, "v1");
        assert_eq!(loaded.trial_id, "trial-042");
        assert_eq!(loaded.promoted_score, 0.85);
        assert!(contents.contains("[knowledge]"));
        assert!(contents.contains("bm25_k1 = 1.2"));
    }

    #[test]
    fn subsequent_promotion_increments_version_and_tracks_changes() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("lago.toml");
        promote_to_lago_toml(&path, &request()).unwrap();

        let artifact = KnowledgeThresholdArtifact {
            hybrid_keyword_boost: 0.35,
            ..KnowledgeThresholdArtifact::default()
        };
        let second = KnowledgePromotionRequest::new(artifact, "trial-043", 0.85, 0.88)
            .with_promoted_at("2026-04-09T12:00:00Z");
        let record = promote_to_lago_toml(&path, &second).unwrap();
        let loaded = load_promoted_knowledge_config(&path).unwrap().unwrap();

        assert_eq!(record.version, "v2");
        assert_eq!(record.rollback_target.as_deref(), Some("v1"));
        assert_eq!(record.parameters_changed, vec!["hybrid_keyword_boost"]);
        assert_eq!(loaded.version, "v2");
        assert_eq!(loaded.rollback_target.as_deref(), Some("v1"));
    }

    #[test]
    fn promotion_preserves_other_toml_sections() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("lago.toml");
        std::fs::write(
            &path,
            "# Lago config\nhttp_port = 8080\n\n[auth]\n# keep me\n",
        )
        .unwrap();

        promote_to_lago_toml(&path, &request()).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();

        assert!(contents.contains("# Lago config"));
        assert!(contents.contains("http_port = 8080"));
        assert!(contents.contains("[auth]"));
        assert!(contents.contains("# keep me"));
        assert!(contents.contains("[knowledge]"));
    }

    #[test]
    fn promotion_replaces_existing_knowledge_section_only() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("lago.toml");
        std::fs::write(
            &path,
            "http_port = 8080\n\n[knowledge]\nversion = \"v1\"\ntrial_id = \"old\"\nbm25_k1 = 1.2\nbm25_b = 0.75\nhybrid_keyword_boost = 0.3\nhybrid_graph_boost = 0.15\nhealth_threshold = 0.7\nmax_obs_before_compact = 50\nstale_index_ms = 3600000\nfreshness_stale_secs = 3600\nwakeup_token_budget = 600\npromoted_at = \"old\"\nbaseline_score = 0.1\npromoted_score = 0.2\n\n[auth]\n",
        )
        .unwrap();

        promote_to_lago_toml(&path, &request()).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();

        assert_eq!(contents.matches("[knowledge]").count(), 1);
        assert!(!contents.contains("trial_id = \"old\""));
        assert!(contents.contains("trial_id = \"trial-042\""));
        assert!(contents.contains("[auth]"));
    }

    #[test]
    fn promotion_treats_unversioned_knowledge_section_as_baseline() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("lago.toml");
        std::fs::write(
            &path,
            "[knowledge]\nbm25_k1 = 1.4\nbm25_b = 0.7\n\n[auth]\n",
        )
        .unwrap();

        assert_eq!(load_promoted_knowledge_config(&path).unwrap(), None);

        let record = promote_to_lago_toml(&path, &request()).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();

        assert_eq!(record.version, "v1");
        assert_eq!(record.rollback_target, None);
        assert!(!contents.contains("bm25_k1 = 1.4"));
        assert!(contents.contains("trial_id = \"trial-042\""));
        assert!(contents.contains("[auth]"));
    }

    #[test]
    fn promotion_event_payload_matches_contract() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("lago.toml");
        let record = promote_to_lago_toml(&path, &request()).unwrap();
        let payload = record.event_payload();

        match payload {
            EventPayload::Custom { event_type, data } => {
                assert_eq!(event_type, KNOWLEDGE_PROMOTED_EVENT_TYPE);
                assert_eq!(data["trial_id"], "trial-042");
                assert_eq!(data["version"], "v1");
                assert_eq!(data["promoted_score"], 0.85);
                assert!(data["parameters_changed"].as_array().unwrap().len() >= 9);
            }
            other => panic!("expected custom promotion event, got {other:?}"),
        }
    }

    #[test]
    fn invalid_request_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("lago.toml");
        let bad = KnowledgePromotionRequest::new(
            KnowledgeThresholdArtifact::default(),
            "",
            f64::NAN,
            0.85,
        );

        let err = promote_to_lago_toml(&path, &bad).unwrap_err();
        assert!(matches!(err, KnowledgePromotionError::InvalidRequest(_)));
    }
}
