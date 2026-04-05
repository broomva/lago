//! Format MemCubes as natural language for LLM context windows.
//!
//! Each memory tier and cognition kind produces a different natural-language
//! framing so the LLM can distinguish between past experiences, proven
//! approaches, extracted knowledge, and self-evaluations.

use lago_core::cognitive::{CognitionKind, MemCube, MemoryTier};

/// A formatted section ready for inclusion in a context window.
pub struct FormattedSection {
    /// Section name (e.g., "Proven Approach", "Past Experience (action)").
    pub name: String,
    /// Natural language content formatted for the LLM.
    pub content: String,
}

/// Format a MemCube as a natural-language section for LLM context.
pub fn format_memory(memory: &MemCube) -> FormattedSection {
    let name = match memory.tier {
        MemoryTier::Episodic => format!("Past Experience ({})", kind_label(memory.kind)),
        MemoryTier::Semantic => "Knowledge".to_string(),
        MemoryTier::Procedural => "Proven Approach".to_string(),
        MemoryTier::Meta => "Self-Evaluation".to_string(),
        MemoryTier::Working => "Current Context".to_string(),
    };

    let content = match memory.tier {
        MemoryTier::Episodic => format!(
            "In a previous session, you {}:\n{}",
            kind_verb(memory.kind),
            memory.content
        ),
        MemoryTier::Semantic => memory.content.clone(),
        MemoryTier::Procedural => format!(
            "A tested approach (confidence: {:.0}%): {}",
            memory.confidence * 100.0,
            memory.content
        ),
        MemoryTier::Meta => format!("Self-evaluation note: {}", memory.content),
        MemoryTier::Working => memory.content.clone(),
    };

    FormattedSection { name, content }
}

/// Human-readable label for a cognition kind (used in section headers).
fn kind_label(kind: CognitionKind) -> &'static str {
    match kind {
        CognitionKind::Perceive => "observation",
        CognitionKind::Deliberate => "deliberation",
        CognitionKind::Decide => "decision",
        CognitionKind::Act => "action",
        CognitionKind::Verify => "verification",
        CognitionKind::Reflect => "reflection",
        CognitionKind::Consolidate => "consolidation",
        CognitionKind::Govern => "governance",
    }
}

/// Past-tense verb for a cognition kind (used in episodic formatting).
fn kind_verb(kind: CognitionKind) -> &'static str {
    match kind {
        CognitionKind::Perceive => "observed",
        CognitionKind::Deliberate => "considered",
        CognitionKind::Decide => "decided",
        CognitionKind::Act => "performed",
        CognitionKind::Verify => "verified",
        CognitionKind::Reflect => "reflected",
        CognitionKind::Consolidate => "consolidated",
        CognitionKind::Govern => "governed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_episodic() {
        let cube = MemCube::new(
            MemoryTier::Episodic,
            CognitionKind::Act,
            "refactored the database module",
            "test",
        );
        let section = format_memory(&cube);
        assert_eq!(section.name, "Past Experience (action)");
        assert!(
            section
                .content
                .starts_with("In a previous session, you performed:")
        );
        assert!(section.content.contains("refactored the database module"));
    }

    #[test]
    fn test_format_semantic() {
        let cube = MemCube::new(
            MemoryTier::Semantic,
            CognitionKind::Consolidate,
            "Rust uses ownership for memory safety",
            "test",
        );
        let section = format_memory(&cube);
        assert_eq!(section.name, "Knowledge");
        assert_eq!(section.content, "Rust uses ownership for memory safety");
    }

    #[test]
    fn test_format_procedural() {
        let mut cube = MemCube::new(
            MemoryTier::Procedural,
            CognitionKind::Consolidate,
            "Use spawn_blocking for redb operations",
            "test",
        );
        cube.confidence = 0.95;
        let section = format_memory(&cube);
        assert_eq!(section.name, "Proven Approach");
        assert!(section.content.contains("confidence: 95%"));
        assert!(
            section
                .content
                .contains("Use spawn_blocking for redb operations")
        );
    }

    #[test]
    fn test_format_meta() {
        let cube = MemCube::new(
            MemoryTier::Meta,
            CognitionKind::Reflect,
            "Context was too broad last time, narrow the focus",
            "test",
        );
        let section = format_memory(&cube);
        assert_eq!(section.name, "Self-Evaluation");
        assert!(section.content.starts_with("Self-evaluation note:"));
    }

    #[test]
    fn test_format_working() {
        let cube = MemCube::new(
            MemoryTier::Working,
            CognitionKind::Perceive,
            "Current file: main.rs, line 42",
            "test",
        );
        let section = format_memory(&cube);
        assert_eq!(section.name, "Current Context");
        assert_eq!(section.content, "Current file: main.rs, line 42");
    }

    #[test]
    fn test_format_all_episodic_kinds() {
        let kinds = [
            (CognitionKind::Perceive, "observation", "observed"),
            (CognitionKind::Deliberate, "deliberation", "considered"),
            (CognitionKind::Decide, "decision", "decided"),
            (CognitionKind::Act, "action", "performed"),
            (CognitionKind::Verify, "verification", "verified"),
            (CognitionKind::Reflect, "reflection", "reflected"),
            (CognitionKind::Consolidate, "consolidation", "consolidated"),
            (CognitionKind::Govern, "governance", "governed"),
        ];

        for (kind, expected_label, expected_verb) in kinds {
            let cube = MemCube::new(MemoryTier::Episodic, kind, "test content", "test");
            let section = format_memory(&cube);
            assert!(
                section.name.contains(expected_label),
                "kind {kind:?}: expected label '{expected_label}' in '{}'",
                section.name
            );
            assert!(
                section.content.contains(expected_verb),
                "kind {kind:?}: expected verb '{expected_verb}' in '{}'",
                section.content
            );
        }
    }
}
