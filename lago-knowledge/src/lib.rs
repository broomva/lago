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

pub mod bm25;
mod frontmatter;
mod index;
pub mod lint;
mod search;
mod traversal;
mod wikilink;

pub use bm25::Bm25Index;
pub use frontmatter::parse_frontmatter;
pub use index::{KnowledgeError, KnowledgeIndex, Note};
pub use lint::{Contradiction, LintReport};
pub use search::{HybridSearchConfig, SearchResult};
pub use traversal::TraversalResult;
pub use wikilink::extract_wikilinks;
