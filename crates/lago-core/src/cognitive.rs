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
        }
    }

    /// Compute current relevance factoring importance and time decay.
    ///
    /// Returns a value in \[0, 1\] representing how relevant this memory
    /// is right now, combining its importance with exponential time decay.
    pub fn relevance(&self) -> f32 {
        let now = now_micros();
        let age_hours = (now.saturating_sub(self.last_accessed)) as f64 / 3_600_000_000.0;
        let decay = (-self.decay_rate as f64 * age_hours).exp() as f32;
        self.importance * decay
    }

    /// Record an access, updating last_accessed and access_count.
    pub fn touch(&mut self) {
        self.last_accessed = now_micros();
        self.access_count = self.access_count.saturating_add(1);
    }
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
}
