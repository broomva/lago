//! Cognitive memory types for the Lago Cognitive Storage layer.
//!
//! These types model agent memory as structured units (MemCubes) organized
//! into cognitive tiers, following the MemOS research paradigm where each
//! memory unit carries content, metadata, causal links, and lifecycle state.

use serde::{Deserialize, Serialize};

/// Memory tier classification — how the knowledge was formed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryTier {
    /// Working memory — current session context, ephemeral.
    Working,
    /// Episodic memory — specific experiences and conversations.
    Episodic,
    /// Semantic memory — extracted facts, patterns, knowledge.
    Semantic,
    /// Procedural memory — tested approaches, recipes, workflows.
    Procedural,
    /// Meta memory — EGRI evaluations, self-metrics, introspection.
    Meta,
}

/// Cognition phase that produced this memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CognitionKind {
    /// Observation — raw sensory input or environment reading.
    Perceive,
    /// Deliberation — weighing options, reasoning.
    Deliberate,
    /// Decision — committing to a course of action.
    Decide,
    /// Action — executing a decision (tool use, code generation).
    Act,
    /// Verification — checking an outcome against expectations.
    Verify,
    /// Reflection — post-hoc analysis of what happened and why.
    Reflect,
    /// Consolidation — synthesizing multiple memories into a pattern.
    Consolidate,
    /// Governance — meta-level policy or strategy adjustment.
    Govern,
}

/// Resolution status for contradictions between MemCubes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ConflictResolution {
    /// Contradiction has not been resolved.
    Unresolved,
    /// This cube has been superseded by another.
    Superseded { by: String },
    /// Both claims coexist; the reason explains why.
    Coexist { reason: String },
}

/// A MemCube is the fundamental unit of cognitive memory.
///
/// Each MemCube carries natural-language content, cognition metadata,
/// importance/confidence scores, causal links, and lifecycle state.
/// MemCubes are storage-agnostic — they can be persisted in Lance,
/// redb, or plain files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemCube {
    /// Unique identifier (typically a ULID).
    pub id: String,

    /// Memory tier classification.
    pub tier: MemoryTier,

    /// Cognition phase that produced this memory.
    pub kind: CognitionKind,

    /// Natural language content of the memory.
    pub content: String,

    /// Source identifier (e.g., "filesystem", "lance", "session:XYZ").
    pub source: String,

    /// Importance score (0.0 to 1.0), updated by access patterns.
    pub importance: f32,

    /// Confidence score (0.0 to 1.0), how certain the information is.
    pub confidence: f32,

    /// Decay rate — how fast relevance fades without access.
    pub decay_rate: f32,

    /// IDs of memories that caused this one.
    pub caused_by: Vec<String>,

    /// IDs of memories this one led to.
    pub leads_to: Vec<String>,

    /// IDs of decisions this memory serves as evidence for.
    pub evidence_for: Vec<String>,

    /// Creation timestamp (microseconds since epoch).
    pub created_at: u64,

    /// Last access timestamp (microseconds since epoch).
    pub last_accessed: u64,

    /// Number of times this memory has been accessed.
    pub access_count: u32,

    /// Session that created this memory (if applicable).
    pub session_id: Option<String>,

    /// Validity start time (microseconds since epoch). None = always valid.
    #[serde(default)]
    pub valid_from: Option<u64>,

    /// Validity end time (microseconds since epoch). None = no expiry.
    #[serde(default)]
    pub valid_to: Option<u64>,

    /// ID of the MemCube that supersedes this one.
    #[serde(default)]
    pub superseded_by: Option<String>,

    /// IDs of MemCubes with conflicting claims.
    #[serde(default)]
    pub contradicts: Vec<String>,

    /// Resolution status for contradictions.
    #[serde(default)]
    pub contradiction_status: Option<ConflictResolution>,
}

impl MemCube {
    /// Create a new MemCube with sensible defaults.
    pub fn new(
        tier: MemoryTier,
        kind: CognitionKind,
        content: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        let now = now_micros();
        Self {
            id: ulid::Ulid::new().to_string(),
            tier,
            kind,
            content: content.into(),
            source: source.into(),
            importance: 0.5,
            confidence: 0.5,
            decay_rate: 0.01,
            caused_by: Vec::new(),
            leads_to: Vec::new(),
            evidence_for: Vec::new(),
            created_at: now,
            last_accessed: now,
            access_count: 0,
            session_id: None,
            valid_from: None,
            valid_to: None,
            superseded_by: None,
            contradicts: Vec::new(),
            contradiction_status: None,
        }
    }

    /// Compute current relevance factoring importance and time decay.
    ///
    /// Returns a value in \[0, 1\] representing how relevant this memory
    /// is right now, combining its importance with exponential time decay.
    /// Returns 0.0 if the cube has expired (`valid_to` is set and past).
    pub fn relevance(&self) -> f32 {
        if self.is_expired() {
            return 0.0;
        }
        let now = now_micros();
        let age_hours = (now.saturating_sub(self.last_accessed)) as f64 / 3_600_000_000.0;
        let decay = (-self.decay_rate as f64 * age_hours).exp() as f32;
        self.importance * decay
    }

    /// Whether this cube has expired (valid_to is set and in the past).
    pub fn is_expired(&self) -> bool {
        self.valid_to.is_some_and(|t| now_micros() > t)
    }

    /// Whether this cube is currently valid (within its validity window).
    ///
    /// A cube is valid if the current time is at or after `valid_from`
    /// (if set) and at or before `valid_to` (if set).
    pub fn is_valid(&self) -> bool {
        let now = now_micros();
        let after_start = self.valid_from.is_none_or(|t| now >= t);
        let before_end = self.valid_to.is_none_or(|t| now <= t);
        after_start && before_end
    }

    /// Record an access, updating last_accessed and access_count.
    pub fn touch(&mut self) {
        self.last_accessed = now_micros();
        self.access_count = self.access_count.saturating_add(1);
    }
}

/// Select top-k MemCubes fitting within a token budget.
///
/// Filters expired/not-yet-valid cubes, scores by relevance, and greedily
/// selects cubes until the budget is exhausted. Smaller cubes may still
/// be selected even after a large one is skipped.
pub fn assemble(cubes: &[MemCube], token_budget: usize) -> Vec<&MemCube> {
    let mut valid: Vec<&MemCube> = cubes.iter().filter(|c| c.is_valid()).collect();
    valid.sort_by(|a, b| {
        b.relevance()
            .partial_cmp(&a.relevance())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut selected = Vec::new();
    let mut tokens_used = 0;
    for cube in valid {
        let est_tokens = cube.content.len() / 4; // rough estimate: ~4 chars per token
        if tokens_used + est_tokens > token_budget {
            continue; // try smaller cubes
        }
        tokens_used += est_tokens;
        selected.push(cube);
    }
    selected
}

fn now_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memcube_new_defaults() {
        let cube = MemCube::new(
            MemoryTier::Semantic,
            CognitionKind::Consolidate,
            "Rust is a systems language",
            "test",
        );
        assert_eq!(cube.tier, MemoryTier::Semantic);
        assert_eq!(cube.kind, CognitionKind::Consolidate);
        assert_eq!(cube.content, "Rust is a systems language");
        assert!((cube.importance - 0.5).abs() < f32::EPSILON);
        assert!((cube.confidence - 0.5).abs() < f32::EPSILON);
        assert_eq!(cube.access_count, 0);
        assert!(cube.caused_by.is_empty());
    }

    #[test]
    fn memcube_relevance_fresh() {
        let cube = MemCube::new(MemoryTier::Episodic, CognitionKind::Perceive, "obs", "t");
        // Just created, relevance should be close to importance
        let rel = cube.relevance();
        assert!(
            rel > 0.4,
            "relevance should be near importance for fresh memory: {rel}"
        );
    }

    #[test]
    fn memcube_touch_increments() {
        let mut cube = MemCube::new(MemoryTier::Procedural, CognitionKind::Act, "approach", "t");
        let before = cube.last_accessed;
        cube.touch();
        assert_eq!(cube.access_count, 1);
        assert!(cube.last_accessed >= before);
    }

    #[test]
    fn memory_tier_serde_roundtrip() {
        for tier in [
            MemoryTier::Working,
            MemoryTier::Episodic,
            MemoryTier::Semantic,
            MemoryTier::Procedural,
            MemoryTier::Meta,
        ] {
            let json = serde_json::to_string(&tier).unwrap();
            let back: MemoryTier = serde_json::from_str(&json).unwrap();
            assert_eq!(tier, back);
        }
    }

    #[test]
    fn cognition_kind_serde_roundtrip() {
        for kind in [
            CognitionKind::Perceive,
            CognitionKind::Deliberate,
            CognitionKind::Decide,
            CognitionKind::Act,
            CognitionKind::Verify,
            CognitionKind::Reflect,
            CognitionKind::Consolidate,
            CognitionKind::Govern,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: CognitionKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn memcube_full_serde_roundtrip() {
        let mut cube = MemCube::new(
            MemoryTier::Meta,
            CognitionKind::Reflect,
            "self-evaluation note",
            "egri",
        );
        cube.caused_by = vec!["A".into()];
        cube.leads_to = vec!["B".into()];
        cube.session_id = Some("SESS001".into());

        let json = serde_json::to_string(&cube).unwrap();
        let back: MemCube = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tier, MemoryTier::Meta);
        assert_eq!(back.kind, CognitionKind::Reflect);
        assert_eq!(back.content, "self-evaluation note");
        assert_eq!(back.caused_by, vec!["A"]);
        assert_eq!(back.session_id, Some("SESS001".into()));
    }

    #[test]
    fn unique_ids() {
        let a = MemCube::new(MemoryTier::Working, CognitionKind::Perceive, "a", "t");
        let b = MemCube::new(MemoryTier::Working, CognitionKind::Perceive, "b", "t");
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn temporal_fields_default_none() {
        let cube = MemCube::new(MemoryTier::Semantic, CognitionKind::Consolidate, "x", "t");
        assert!(cube.valid_from.is_none());
        assert!(cube.valid_to.is_none());
        assert!(cube.superseded_by.is_none());
        assert!(cube.contradicts.is_empty());
        assert!(cube.contradiction_status.is_none());
    }

    #[test]
    fn expired_cube_relevance_zero() {
        let mut cube = MemCube::new(MemoryTier::Semantic, CognitionKind::Consolidate, "old", "t");
        // Set valid_to to 1 microsecond since epoch (i.e., far in the past)
        cube.valid_to = Some(1);
        assert!(cube.is_expired());
        assert!((cube.relevance() - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn not_yet_valid_cube() {
        let mut cube = MemCube::new(
            MemoryTier::Semantic,
            CognitionKind::Consolidate,
            "future",
            "t",
        );
        // Set valid_from to far future
        cube.valid_from = Some(u64::MAX);
        assert!(!cube.is_valid());
        assert!(!cube.is_expired()); // not expired, just not yet valid
    }

    #[test]
    fn valid_cube_within_window() {
        let now = now_micros();
        let mut cube = MemCube::new(
            MemoryTier::Semantic,
            CognitionKind::Consolidate,
            "current",
            "t",
        );
        cube.valid_from = Some(now.saturating_sub(1_000_000)); // 1 second ago
        cube.valid_to = Some(now.saturating_add(60_000_000)); // 60 seconds from now
        assert!(cube.is_valid());
        assert!(!cube.is_expired());
    }

    #[test]
    fn serde_roundtrip_with_temporal_fields() {
        let mut cube = MemCube::new(MemoryTier::Meta, CognitionKind::Reflect, "temporal", "test");
        cube.valid_from = Some(1000);
        cube.valid_to = Some(2000);
        cube.superseded_by = Some("CUBE_002".into());
        cube.contradicts = vec!["CUBE_003".into()];
        cube.contradiction_status = Some(ConflictResolution::Superseded {
            by: "CUBE_002".into(),
        });

        let json = serde_json::to_string(&cube).unwrap();
        let back: MemCube = serde_json::from_str(&json).unwrap();
        assert_eq!(back.valid_from, Some(1000));
        assert_eq!(back.valid_to, Some(2000));
        assert_eq!(back.superseded_by, Some("CUBE_002".into()));
        assert_eq!(back.contradicts, vec!["CUBE_003"]);
        assert_eq!(
            back.contradiction_status,
            Some(ConflictResolution::Superseded {
                by: "CUBE_002".into()
            })
        );
    }

    #[test]
    fn serde_backwards_compat_without_temporal_fields() {
        // Old JSON without the new fields should deserialize fine
        let old_json = r#"{
            "id": "TEST001",
            "tier": "semantic",
            "kind": "consolidate",
            "content": "old format",
            "source": "test",
            "importance": 0.5,
            "confidence": 0.5,
            "decay_rate": 0.01,
            "caused_by": [],
            "leads_to": [],
            "evidence_for": [],
            "created_at": 1000,
            "last_accessed": 1000,
            "access_count": 0,
            "session_id": null
        }"#;

        let cube: MemCube = serde_json::from_str(old_json).unwrap();
        assert!(cube.valid_from.is_none());
        assert!(cube.valid_to.is_none());
        assert!(cube.superseded_by.is_none());
        assert!(cube.contradicts.is_empty());
        assert!(cube.contradiction_status.is_none());
    }

    #[test]
    fn conflict_resolution_serde_roundtrip() {
        for res in [
            ConflictResolution::Unresolved,
            ConflictResolution::Superseded { by: "X".into() },
            ConflictResolution::Coexist {
                reason: "both valid in different contexts".into(),
            },
        ] {
            let json = serde_json::to_string(&res).unwrap();
            let back: ConflictResolution = serde_json::from_str(&json).unwrap();
            assert_eq!(res, back);
        }
    }

    #[test]
    fn assemble_respects_budget() {
        let mut cubes = vec![
            MemCube::new(
                MemoryTier::Semantic,
                CognitionKind::Consolidate,
                "a".repeat(400),
                "t",
            ), // ~100 tokens
            MemCube::new(
                MemoryTier::Semantic,
                CognitionKind::Consolidate,
                "b".repeat(400),
                "t",
            ), // ~100 tokens
            MemCube::new(
                MemoryTier::Semantic,
                CognitionKind::Consolidate,
                "c".repeat(400),
                "t",
            ), // ~100 tokens
        ];
        // Make them all equally relevant
        for c in &mut cubes {
            c.importance = 0.8;
        }

        let selected = assemble(&cubes, 200); // room for ~2 cubes
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn assemble_filters_expired() {
        let mut cubes = vec![
            MemCube::new(
                MemoryTier::Semantic,
                CognitionKind::Consolidate,
                "valid content",
                "t",
            ),
            MemCube::new(
                MemoryTier::Semantic,
                CognitionKind::Consolidate,
                "expired content",
                "t",
            ),
        ];
        cubes[1].valid_to = Some(1); // expired

        let selected = assemble(&cubes, 10000);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].content, "valid content");
    }

    #[test]
    fn assemble_filters_not_yet_valid() {
        let mut cubes = vec![
            MemCube::new(
                MemoryTier::Semantic,
                CognitionKind::Consolidate,
                "now content",
                "t",
            ),
            MemCube::new(
                MemoryTier::Semantic,
                CognitionKind::Consolidate,
                "future content",
                "t",
            ),
        ];
        cubes[1].valid_from = Some(u64::MAX); // not yet valid

        let selected = assemble(&cubes, 10000);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].content, "now content");
    }

    #[test]
    fn assemble_empty_input() {
        let cubes: Vec<MemCube> = Vec::new();
        let selected = assemble(&cubes, 10000);
        assert!(selected.is_empty());
    }

    #[test]
    fn assemble_skips_large_selects_small() {
        let mut cubes = vec![
            MemCube::new(
                MemoryTier::Semantic,
                CognitionKind::Consolidate,
                "x".repeat(2000),
                "t",
            ), // ~500 tokens
            MemCube::new(
                MemoryTier::Semantic,
                CognitionKind::Consolidate,
                "small",
                "t",
            ), // ~1 token
        ];
        // Make the large one more relevant so it's tried first
        cubes[0].importance = 0.9;
        cubes[1].importance = 0.1;

        // Budget only fits the small one
        let selected = assemble(&cubes, 10);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].content, "small");
    }
}
