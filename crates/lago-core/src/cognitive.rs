//! Cognitive memory types for the AI-native storage layer.
//!
//! These types model agent cognition as structured data:
//! - `MemoryTier` — which memory layer (episodic, semantic, procedural, meta)
//! - `CognitionKind` — what type of cognitive event (perceive, decide, act, etc.)
//! - `MemCube` — the fundamental memory unit with content, embedding, and metadata

use serde::{Deserialize, Serialize};

/// Memory tiers — biological memory model for agents.
///
/// Each tier has different retention, retrieval, and consolidation strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryTier {
    /// Working memory — current context window (transient)
    Working,
    /// Episodic memory — what happened (full conversations, tool calls)
    Episodic,
    /// Semantic memory — what I know (facts, patterns, rules)
    Semantic,
    /// Procedural memory — how to do things (tested approaches, workflows)
    Procedural,
    /// Meta memory — memory about memory (EGRI evaluations, self-metrics)
    Meta,
}

/// Cognition types — maps to the aiOS 8-phase tick lifecycle.
///
/// Each agent action produces a cognitive event of one of these types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CognitionKind {
    /// What I observed (file content, user message, tool output)
    Perceive,
    /// What I considered (alternatives, trade-offs)
    Deliberate,
    /// What I chose and why (action + rationale)
    Decide,
    /// What I did (tool call, edit, command)
    Act,
    /// Did it work? (success, error, feedback)
    Verify,
    /// What did I learn? (pattern, insight)
    Reflect,
    /// Pattern extracted (episodic → semantic consolidation)
    Consolidate,
    /// Rule updated (policy, governance change)
    Govern,
}

/// The fundamental memory unit — a container for cognitive content.
///
/// Inspired by MemOS's MemCube concept: each memory unit carries
/// content, metadata, and causal links. MemCubes can be cloned,
/// merged, branched, and versioned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemCube {
    /// Unique identifier (ULID)
    pub id: String,

    /// Which memory tier this belongs to
    pub tier: MemoryTier,

    /// What type of cognitive event created this
    pub kind: CognitionKind,

    /// Natural language content
    pub content: String,

    /// Semantic embedding vector (optional, computed asynchronously)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub embedding: Vec<f32>,

    /// Type-specific structured data
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub structured: serde_json::Value,

    // --- Causal links ---
    /// What led to this memory (parent event IDs)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caused_by: Vec<String>,

    /// What this memory caused (child event IDs)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub leads_to: Vec<String>,

    /// What decisions this memory supports as evidence
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_for: Vec<String>,

    // --- Memory lifecycle metadata ---
    /// How important is this memory (0.0–1.0, updated by access patterns)
    #[serde(default = "default_importance")]
    pub importance: f32,

    /// How confident are we in this memory (0.0–1.0)
    #[serde(default = "default_confidence")]
    pub confidence: f32,

    /// How fast relevance decays (higher = faster decay)
    #[serde(default = "default_decay_rate")]
    pub decay_rate: f32,

    /// When this memory was created (microseconds since epoch)
    pub created_at: u64,

    /// When this memory was last accessed
    #[serde(default)]
    pub last_accessed: u64,

    /// How many times this memory has been retrieved
    #[serde(default)]
    pub access_count: u32,

    /// Session that created this memory
    pub session_id: String,
}

fn default_importance() -> f32 {
    0.5
}

fn default_confidence() -> f32 {
    0.8
}

fn default_decay_rate() -> f32 {
    0.01
}

impl MemCube {
    /// Create a new MemCube with the given content.
    pub fn new(
        tier: MemoryTier,
        kind: CognitionKind,
        content: impl Into<String>,
        session_id: impl Into<String>,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        Self {
            id: crate::id::EventId::new().to_string(),
            tier,
            kind,
            content: content.into(),
            embedding: Vec::new(),
            structured: serde_json::Value::Null,
            caused_by: Vec::new(),
            leads_to: Vec::new(),
            evidence_for: Vec::new(),
            importance: default_importance(),
            confidence: default_confidence(),
            decay_rate: default_decay_rate(),
            created_at: now,
            last_accessed: now,
            access_count: 0,
            session_id: session_id.into(),
        }
    }

    /// Record an access (retrieval) — strengthens the memory.
    pub fn record_access(&mut self) {
        self.access_count += 1;
        self.last_accessed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        // Synaptic potentiation: importance increases with access
        self.importance = (self.importance + 0.05).min(1.0);
    }

    /// Calculate current relevance score (importance x recency decay).
    pub fn relevance(&self) -> f32 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        let age_hours = (now.saturating_sub(self.last_accessed)) as f64 / 3_600_000_000.0;
        let decay = (-self.decay_rate as f64 * age_hours).exp() as f32;
        self.importance * decay
    }

    /// Check if this memory should be pruned (relevance below threshold).
    pub fn should_prune(&self, threshold: f32) -> bool {
        self.relevance() < threshold
    }
}

impl std::fmt::Display for MemoryTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Working => write!(f, "working"),
            Self::Episodic => write!(f, "episodic"),
            Self::Semantic => write!(f, "semantic"),
            Self::Procedural => write!(f, "procedural"),
            Self::Meta => write!(f, "meta"),
        }
    }
}

impl std::fmt::Display for CognitionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Perceive => write!(f, "perceive"),
            Self::Deliberate => write!(f, "deliberate"),
            Self::Decide => write!(f, "decide"),
            Self::Act => write!(f, "act"),
            Self::Verify => write!(f, "verify"),
            Self::Reflect => write!(f, "reflect"),
            Self::Consolidate => write!(f, "consolidate"),
            Self::Govern => write!(f, "govern"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memcube_creation() {
        let mc = MemCube::new(
            MemoryTier::Episodic,
            CognitionKind::Act,
            "Ran bash: ls",
            "session-1",
        );
        assert_eq!(mc.tier, MemoryTier::Episodic);
        assert_eq!(mc.kind, CognitionKind::Act);
        assert!(mc.content.contains("ls"));
        assert!(mc.importance > 0.0);
    }

    #[test]
    fn test_access_strengthens_memory() {
        let mut mc = MemCube::new(
            MemoryTier::Semantic,
            CognitionKind::Reflect,
            "Pattern: always read before edit",
            "s1",
        );
        let initial = mc.importance;
        mc.record_access();
        assert!(mc.importance > initial);
        assert_eq!(mc.access_count, 1);
    }

    #[test]
    fn test_relevance_decays_with_importance() {
        let mc = MemCube::new(
            MemoryTier::Episodic,
            CognitionKind::Perceive,
            "Old fact",
            "s1",
        );
        let relevance = mc.relevance();
        // Fresh memory should have high relevance
        assert!(relevance > 0.4);
    }

    #[test]
    fn test_prune_low_relevance() {
        let mut mc = MemCube::new(
            MemoryTier::Episodic,
            CognitionKind::Perceive,
            "Unimportant",
            "s1",
        );
        mc.importance = 0.01;
        assert!(mc.should_prune(0.1));
    }

    #[test]
    fn test_serde_roundtrip() {
        let mc = MemCube::new(
            MemoryTier::Procedural,
            CognitionKind::Decide,
            "Use arcan shell",
            "s1",
        );
        let json = serde_json::to_string(&mc).unwrap();
        let restored: MemCube = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.tier, mc.tier);
        assert_eq!(restored.kind, mc.kind);
        assert_eq!(restored.content, mc.content);
    }

    #[test]
    fn test_memory_tier_display() {
        assert_eq!(MemoryTier::Episodic.to_string(), "episodic");
        assert_eq!(MemoryTier::Procedural.to_string(), "procedural");
    }

    #[test]
    fn test_cognition_kind_display() {
        assert_eq!(CognitionKind::Perceive.to_string(), "perceive");
        assert_eq!(CognitionKind::Govern.to_string(), "govern");
    }

    #[test]
    fn test_causal_links() {
        let mut mc = MemCube::new(
            MemoryTier::Semantic,
            CognitionKind::Decide,
            "Decision X",
            "s1",
        );
        mc.caused_by.push("evidence-1".to_string());
        mc.leads_to.push("action-1".to_string());
        mc.evidence_for.push("outcome-1".to_string());

        assert_eq!(mc.caused_by.len(), 1);
        assert_eq!(mc.leads_to.len(), 1);
        assert_eq!(mc.evidence_for.len(), 1);
    }
}
