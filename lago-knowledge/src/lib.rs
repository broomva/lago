//! # lago-knowledge
//!
//! Knowledge index engine for Lago — gives the persistence substrate the
//! ability to understand `.md` content: parse YAML frontmatter, extract
//! `[[wikilinks]]`, build an in-memory index, and perform scored search
//! with BFS graph traversal.
//!
//! ## Hybrid search
//!
//! [`KnowledgeIndex::search_hybrid`] combines BM25 scoring with keyword
//! and graph-proximity boosts for higher-quality retrieval.
//!
//! ## Lint engine
//!
//! [`KnowledgeIndex::lint`] detects structural issues: orphan pages,
//! broken wikilinks, contradictions, stale claims, and missing pages.
//!
//! ## Document ingestion
//!
//! The [`ingest`] module normalizes raw source documents (JSONL transcripts,
//! Obsidian markdown, plain text) into [`lago_core::cognitive::MemCube`]s
//! with PII redaction and noise filtering.

pub mod benchmark;
pub mod bm25;
pub mod evaluation;
pub mod execution;
mod frontmatter;
mod index;
pub mod ingest;
pub mod lint;
pub mod promotion;
mod search;
mod thresholds;
mod traversal;
mod wikilink;

pub use benchmark::{
    BenchmarkError, BenchmarkQuestion, BenchmarkRun, HoldoutSplit, KnowledgeBenchmark,
    QuestionResult, SplitMetrics,
};
pub use bm25::Bm25Index;
pub use evaluation::{
    ConstraintSeverity, KnowledgeConstraintViolation, KnowledgeQualityError,
    KnowledgeQualityEvaluator, KnowledgeQualityMetrics, KnowledgeQualityOutcome,
    KnowledgeQualityWeights,
};
pub use execution::{
    KnowledgeRuntimeSignals, KnowledgeTrialConfig, KnowledgeTrialError, KnowledgeTrialExecution,
    KnowledgeTrialExecutor,
};
pub use frontmatter::parse_frontmatter;
pub use index::{KnowledgeError, KnowledgeIndex, Note};
pub use ingest::{ChunkStrategy, IngestConfig, SourceFormat, detect_format, ingest_file};
pub use lint::{Contradiction, LintReport};
pub use promotion::{
    KNOWLEDGE_PROMOTED_EVENT_TYPE, KnowledgePromotionError, KnowledgePromotionRecord,
    KnowledgePromotionRequest, PromotedKnowledgeConfig, load_promoted_knowledge_config,
    promote_to_lago_toml, publish_promotion_event,
};
pub use search::{HybridSearchConfig, SearchResult};
pub use thresholds::{
    KnowledgeThresholdArtifact, KnowledgeThresholdBounds, KnowledgeThresholdProposal,
    KnowledgeThresholdProposer, NumericBound, ProposalStrategy, ThresholdChange, ThresholdInsight,
    ThresholdParameter, ThresholdProposalConfig, ThresholdProposalContext, ThresholdProposalError,
    ThresholdTrialOutcome, ThresholdValidationError, ThresholdValue,
};
pub use traversal::TraversalResult;
pub use wikilink::extract_wikilinks;
