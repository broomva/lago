//! Relevance scoring for cognitive memories.
//!
//! Computes a 0-1 relevance score for each MemCube relative to a task
//! and compilation strategy. The score blends keyword overlap, recency
//! (importance x decay), raw importance, and a tier bonus.

use lago_core::cognitive::{MemCube, MemoryTier};

use crate::CompilationStrategy;

/// Score a memory's relevance for the current task.
///
/// Returns a value in \[0, 1\] representing how useful this memory
/// is for the given task under the chosen strategy.
pub fn score_memory(memory: &MemCube, task: &str, strategy: &CompilationStrategy) -> f32 {
    let keyword_score = keyword_overlap(task, &memory.content);
    let recency_score = memory.relevance(); // importance * decay
    let importance_score = memory.importance;
    let tier = tier_bonus(memory);

    match strategy {
        CompilationStrategy::Balanced => {
            0.35 * keyword_score + 0.30 * recency_score + 0.20 * importance_score + 0.15 * tier
        }
        CompilationStrategy::RecencyFirst => {
            0.15 * keyword_score + 0.55 * recency_score + 0.15 * importance_score + 0.15 * tier
        }
        CompilationStrategy::RelevanceFirst => {
            0.55 * keyword_score + 0.15 * recency_score + 0.15 * importance_score + 0.15 * tier
        }
        CompilationStrategy::Diverse => {
            // For diversity we would ideally use MMR against already-selected items.
            // Simplified: boost underrepresented tiers.
            0.30 * keyword_score + 0.25 * recency_score + 0.15 * importance_score + 0.30 * tier
        }
    }
}

/// Simple keyword overlap score (Jaccard-like).
///
/// Splits the task into words (length > 2), checks how many appear
/// in the memory content (case-insensitive). Returns 0-1.
pub(crate) fn keyword_overlap(task: &str, content: &str) -> f32 {
    let task_words: std::collections::HashSet<&str> = task
        .split_whitespace()
        .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
        .filter(|w| w.len() > 2)
        .collect();

    if task_words.is_empty() {
        return 0.0;
    }

    let content_lower = content.to_lowercase();
    let matches = task_words
        .iter()
        .filter(|w| content_lower.contains(&w.to_lowercase()))
        .count();

    matches as f32 / task_words.len() as f32
}

/// Tier bonus — procedural > semantic > meta > episodic > working.
///
/// Tested approaches (procedural) are most valuable for context,
/// followed by distilled knowledge (semantic).
fn tier_bonus(memory: &MemCube) -> f32 {
    match memory.tier {
        MemoryTier::Procedural => 0.8,
        MemoryTier::Semantic => 0.6,
        MemoryTier::Meta => 0.5,
        MemoryTier::Episodic => 0.3,
        MemoryTier::Working => 0.1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lago_core::cognitive::CognitionKind;

    #[test]
    fn test_keyword_overlap_full_match() {
        let score = keyword_overlap("Rust code guide", "Rust code compilation guide");
        // "Rust", "code", "guide" — all 3 match => 1.0
        assert!(score > 0.9, "expected high overlap, got {score}");
    }

    #[test]
    fn test_keyword_overlap_no_match() {
        let score = keyword_overlap("quantum physics", "Rust programming tutorial");
        assert!(score < 0.01, "expected no overlap, got {score}");
    }

    #[test]
    fn test_keyword_overlap_partial() {
        let score = keyword_overlap("build web server Rust", "Rust axum web framework");
        // "build" no, "web" yes, "server" no, "Rust" yes => 2/4 = 0.5
        assert!(
            (score - 0.5).abs() < 0.01,
            "expected ~0.5 overlap, got {score}"
        );
    }

    #[test]
    fn test_keyword_overlap_empty_task() {
        let score = keyword_overlap("", "anything");
        assert!(score.abs() < f32::EPSILON);
    }

    #[test]
    fn test_keyword_overlap_short_words_filtered() {
        // Words <= 2 chars are filtered out
        let score = keyword_overlap("is it ok", "is it ok");
        // "is" (2), "it" (2) filtered, "ok" (2) filtered => empty set => 0
        assert!(score.abs() < f32::EPSILON);
    }

    #[test]
    fn test_score_strategies_differ() {
        let mut cube = MemCube::new(
            MemoryTier::Procedural,
            CognitionKind::Act,
            "Deploy using cargo release",
            "test",
        );
        cube.importance = 0.9;

        let task = "deploy the application";

        let balanced = score_memory(&cube, task, &CompilationStrategy::Balanced);
        let recency = score_memory(&cube, task, &CompilationStrategy::RecencyFirst);
        let relevance = score_memory(&cube, task, &CompilationStrategy::RelevanceFirst);
        let diverse = score_memory(&cube, task, &CompilationStrategy::Diverse);

        // All should be positive
        assert!(balanced > 0.0);
        assert!(recency > 0.0);
        assert!(relevance > 0.0);
        assert!(diverse > 0.0);

        // Strategies should produce different scores (not all identical)
        let scores = [balanced, recency, relevance, diverse];
        let all_same = scores.windows(2).all(|w| (w[0] - w[1]).abs() < 0.001);
        assert!(
            !all_same,
            "different strategies should produce different scores: {scores:?}"
        );
    }

    #[test]
    fn test_tier_bonus_ordering() {
        let make = |tier| {
            let mut cube = MemCube::new(tier, CognitionKind::Consolidate, "content", "t");
            cube.importance = 0.5;
            cube.confidence = 0.5;
            cube
        };

        let proc_score = score_memory(
            &make(MemoryTier::Procedural),
            "task",
            &CompilationStrategy::Balanced,
        );
        let sem_score = score_memory(
            &make(MemoryTier::Semantic),
            "task",
            &CompilationStrategy::Balanced,
        );
        let epi_score = score_memory(
            &make(MemoryTier::Episodic),
            "task",
            &CompilationStrategy::Balanced,
        );

        // Procedural should score higher than semantic, which scores higher than episodic
        // when content and importance are equal (tier bonus is the differentiator)
        assert!(
            proc_score > sem_score,
            "procedural ({proc_score}) should beat semantic ({sem_score})"
        );
        assert!(
            sem_score > epi_score,
            "semantic ({sem_score}) should beat episodic ({epi_score})"
        );
    }
}
