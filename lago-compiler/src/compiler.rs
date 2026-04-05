//! The Context Compiler — assembles optimal LLM context windows.
//!
//! Given a task description, token budget, and a set of retrieved memories,
//! the compiler scores each memory for relevance, packs them into the budget
//! using a greedy knapsack, and produces an ordered set of context sections.

use lago_core::cognitive::{MemCube, MemoryTier};

use crate::{formatter, scorer};

/// Request to compile a context window.
#[derive(Debug, Clone)]
pub struct ContextRequest {
    /// What the agent is trying to do.
    pub task: String,
    /// Maximum tokens to fill.
    pub budget_tokens: usize,
    /// Which memory tiers to draw from (empty = all).
    pub tiers: Vec<MemoryTier>,
    /// Compilation strategy.
    pub strategy: CompilationStrategy,
    /// Additional fixed context (e.g., system prompt, CLAUDE.md).
    pub fixed_context: Option<String>,
    /// Fixed context token count (reserved from budget).
    pub fixed_context_tokens: usize,
}

/// Strategy for weighting relevance dimensions during compilation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompilationStrategy {
    /// Balance recency and relevance equally.
    Balanced,
    /// Prefer recent memories.
    RecencyFirst,
    /// Prefer semantically relevant memories.
    RelevanceFirst,
    /// Maximize diversity of context (MMR-style).
    Diverse,
}

/// The compiled context, ready for LLM consumption.
#[derive(Debug)]
pub struct CompiledContext {
    /// Ordered sections, highest relevance first.
    pub sections: Vec<ContextSection>,
    /// Total tokens used.
    pub tokens_used: usize,
    /// Tokens remaining in budget.
    pub tokens_remaining: usize,
    /// How many items were considered (above threshold).
    pub items_considered: usize,
    /// How many items were included in the context.
    pub items_included: usize,
    /// How many items were dropped (didn't fit or below threshold).
    pub items_dropped: usize,
}

impl CompiledContext {
    /// Render the compiled context as a single string.
    ///
    /// Concatenates all sections with headers and double newlines.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for section in &self.sections {
            if !out.is_empty() {
                out.push_str("\n\n");
            }
            out.push_str(&format!("## {}\n\n{}", section.name, section.content));
        }
        out
    }
}

/// A single section of the compiled context.
#[derive(Debug, Clone)]
pub struct ContextSection {
    /// Section name (e.g., "Relevant Past Experience").
    pub name: String,
    /// Natural language content.
    pub content: String,
    /// Source memory tier.
    pub tier: MemoryTier,
    /// Relevance score (0-1).
    pub relevance: f32,
    /// Estimated token count.
    pub tokens: usize,
}

/// The Context Compiler — assembles optimal context windows from MemCubes.
///
/// The compiler is stateless and storage-agnostic. It takes pre-retrieved
/// memories, scores them, and packs them into a budget-constrained context.
#[derive(Debug, Clone)]
pub struct ContextCompiler {
    /// Relevance threshold — items scoring below this are dropped.
    pub relevance_threshold: f32,
    /// Maximum items to consider per tier.
    pub max_items_per_tier: usize,
}

impl Default for ContextCompiler {
    fn default() -> Self {
        Self {
            relevance_threshold: 0.2,
            max_items_per_tier: 20,
        }
    }
}

impl ContextCompiler {
    /// Create a new ContextCompiler with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a ContextCompiler with custom thresholds.
    pub fn with_thresholds(relevance_threshold: f32, max_items_per_tier: usize) -> Self {
        Self {
            relevance_threshold,
            max_items_per_tier,
        }
    }

    /// Compile context from a set of retrieved MemCubes.
    ///
    /// 1. Score each memory for relevance
    /// 2. Filter out items below the relevance threshold
    /// 3. Sort by score (descending)
    /// 4. Greedily pack into the token budget
    /// 5. Format each selected memory as a context section
    pub fn compile(&self, request: &ContextRequest, memories: Vec<MemCube>) -> CompiledContext {
        let total_memories = memories.len();

        // 1. Score each memory and filter by threshold
        let mut scored: Vec<(MemCube, f32)> = memories
            .into_iter()
            .map(|m| {
                let score = scorer::score_memory(&m, &request.task, &request.strategy);
                (m, score)
            })
            .filter(|(_, score)| *score >= self.relevance_threshold)
            .collect();

        // 2. Sort by score descending
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // 3. Enforce per-tier limits
        let mut tier_counts = std::collections::HashMap::new();
        scored.retain(|(m, _)| {
            let count = tier_counts.entry(m.tier).or_insert(0usize);
            if *count >= self.max_items_per_tier {
                false
            } else {
                *count += 1;
                true
            }
        });

        let items_considered = scored.len();

        // 4. Pack into budget (greedy knapsack)
        let available_tokens = request
            .budget_tokens
            .saturating_sub(request.fixed_context_tokens);

        let mut sections = Vec::new();
        let mut tokens_used = 0;
        let mut items_included = 0;

        for (memory, score) in &scored {
            let formatted = formatter::format_memory(memory);
            let section_tokens = estimate_tokens(&formatted.content);

            if tokens_used + section_tokens > available_tokens {
                continue; // skip this item, doesn't fit
            }

            sections.push(ContextSection {
                name: formatted.name,
                content: formatted.content,
                tier: memory.tier,
                relevance: *score,
                tokens: section_tokens,
            });
            tokens_used += section_tokens;
            items_included += 1;
        }

        let items_dropped = total_memories - items_included;

        CompiledContext {
            sections,
            tokens_used,
            tokens_remaining: available_tokens.saturating_sub(tokens_used),
            items_considered,
            items_included,
            items_dropped,
        }
    }
}

/// Estimate token count for a string.
///
/// Uses the ~4 characters per token heuristic. This is a rough
/// approximation; production systems should use tiktoken or similar.
pub fn estimate_tokens(text: &str) -> usize {
    text.len().div_ceil(4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lago_core::cognitive::CognitionKind;

    fn make_request(task: &str, budget: usize) -> ContextRequest {
        ContextRequest {
            task: task.to_string(),
            budget_tokens: budget,
            tiers: vec![],
            strategy: CompilationStrategy::Balanced,
            fixed_context: None,
            fixed_context_tokens: 0,
        }
    }

    fn make_cube(tier: MemoryTier, content: &str, importance: f32) -> MemCube {
        let mut cube = MemCube::new(tier, CognitionKind::Consolidate, content, "test");
        cube.importance = importance;
        cube
    }

    #[test]
    fn test_compile_empty_memories() {
        let compiler = ContextCompiler::new();
        let request = make_request("build something", 1000);
        let result = compiler.compile(&request, vec![]);

        assert!(result.sections.is_empty());
        assert_eq!(result.tokens_used, 0);
        assert_eq!(result.items_considered, 0);
        assert_eq!(result.items_included, 0);
        assert_eq!(result.items_dropped, 0);
    }

    #[test]
    fn test_compile_with_budget() {
        let compiler = ContextCompiler::new();
        let request = make_request("Rust programming", 50); // very small budget

        let memories = vec![
            make_cube(
                MemoryTier::Semantic,
                "Rust is a systems programming language focused on safety",
                0.8,
            ),
            make_cube(
                MemoryTier::Semantic,
                "Rust has a unique ownership model that prevents data races at compile time through the borrow checker",
                0.7,
            ),
        ];

        let result = compiler.compile(&request, memories);

        // Budget is 50 tokens (~200 chars). At least one should fit.
        assert!(result.tokens_used <= 50, "should respect token budget");
        assert!(result.tokens_remaining <= 50);
        assert_eq!(result.tokens_used + result.tokens_remaining, 50);
    }

    #[test]
    fn test_compile_drops_low_relevance() {
        let compiler = ContextCompiler::with_thresholds(0.5, 20); // high threshold
        let request = make_request("quantum physics", 10000);

        let memories = vec![
            make_cube(
                MemoryTier::Working,
                "Unrelated working memory about groceries",
                0.1,
            ),
            make_cube(
                MemoryTier::Working,
                "Another unrelated note about weather",
                0.05,
            ),
        ];

        let result = compiler.compile(&request, memories);

        // Low importance + Working tier bonus (0.1) + no keyword match
        // Should all be below 0.5 threshold
        assert_eq!(
            result.items_included, 0,
            "low-relevance items should be dropped"
        );
    }

    #[test]
    fn test_compile_respects_fixed_context() {
        let compiler = ContextCompiler::new();
        let request = ContextRequest {
            task: "Rust programming".to_string(),
            budget_tokens: 100,
            tiers: vec![],
            strategy: CompilationStrategy::Balanced,
            fixed_context: Some("System prompt goes here".to_string()),
            fixed_context_tokens: 80, // reserve 80 of 100 tokens
        };

        let memories = vec![make_cube(
            MemoryTier::Semantic,
            "Rust is great for systems programming with zero-cost abstractions",
            0.9,
        )];

        let result = compiler.compile(&request, memories);

        // Only 20 tokens available (100 - 80). The content is ~16 tokens.
        // It might fit or not depending on formatting overhead.
        assert!(
            result.tokens_used <= 20,
            "should respect fixed_context_tokens reservation"
        );
    }

    #[test]
    fn test_compile_orders_by_relevance() {
        let compiler = ContextCompiler::new();
        let request = make_request("database optimization", 10000);

        let memories = vec![
            make_cube(MemoryTier::Episodic, "Had lunch at noon", 0.3),
            make_cube(
                MemoryTier::Procedural,
                "Use indexes for database optimization queries",
                0.9,
            ),
            make_cube(
                MemoryTier::Semantic,
                "Databases store structured data for optimization",
                0.7,
            ),
        ];

        let result = compiler.compile(&request, memories);

        // Should have sections ordered by relevance (highest first)
        if result.sections.len() >= 2 {
            for pair in result.sections.windows(2) {
                assert!(
                    pair[0].relevance >= pair[1].relevance,
                    "sections should be ordered by relevance: {} >= {}",
                    pair[0].relevance,
                    pair[1].relevance
                );
            }
        }
    }

    #[test]
    fn test_compile_stats_consistent() {
        let compiler = ContextCompiler::new();
        let request = make_request("Rust test", 10000);

        let memories = vec![
            make_cube(MemoryTier::Semantic, "Rust testing with cargo test", 0.8),
            make_cube(
                MemoryTier::Procedural,
                "Always run cargo test before committing",
                0.9,
            ),
            make_cube(
                MemoryTier::Episodic,
                "Wrote tests for the parser module",
                0.6,
            ),
        ];

        let n = memories.len();
        let result = compiler.compile(&request, memories);

        // items_included + items_dropped = total input
        assert_eq!(
            result.items_included + result.items_dropped,
            n,
            "included + dropped should equal total input"
        );
    }

    #[test]
    fn test_estimate_tokens() {
        assert_eq!(estimate_tokens(""), 0);
        assert_eq!(estimate_tokens("a"), 1); // (1+3)/4 = 1
        assert_eq!(estimate_tokens("abcd"), 1); // (4+3)/4 = 1
        assert_eq!(estimate_tokens("abcde"), 2); // (5+3)/4 = 2
        assert_eq!(estimate_tokens("Hello, world!"), 4); // (13+3)/4 = 4
    }

    #[test]
    fn test_compiled_context_render() {
        let ctx = CompiledContext {
            sections: vec![
                ContextSection {
                    name: "Knowledge".to_string(),
                    content: "Rust is fast".to_string(),
                    tier: MemoryTier::Semantic,
                    relevance: 0.9,
                    tokens: 3,
                },
                ContextSection {
                    name: "Proven Approach".to_string(),
                    content: "Use cargo test".to_string(),
                    tier: MemoryTier::Procedural,
                    relevance: 0.8,
                    tokens: 4,
                },
            ],
            tokens_used: 7,
            tokens_remaining: 93,
            items_considered: 2,
            items_included: 2,
            items_dropped: 0,
        };

        let rendered = ctx.render();
        assert!(rendered.contains("## Knowledge"));
        assert!(rendered.contains("Rust is fast"));
        assert!(rendered.contains("## Proven Approach"));
        assert!(rendered.contains("Use cargo test"));
    }

    #[test]
    fn test_default_compiler() {
        let compiler = ContextCompiler::default();
        assert!((compiler.relevance_threshold - 0.2).abs() < f32::EPSILON);
        assert_eq!(compiler.max_items_per_tier, 20);
    }
}
