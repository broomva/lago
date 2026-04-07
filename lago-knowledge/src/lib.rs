//! # lago-knowledge
//!
//! Knowledge index engine for Lago — gives the persistence substrate the
//! ability to understand `.md` content: parse YAML frontmatter, extract
//! `[[wikilinks]]`, build an in-memory index, and perform scored search
//! with BFS graph traversal.

pub mod bm25;
mod frontmatter;
mod index;
mod search;
mod traversal;
mod wikilink;

pub use bm25::Bm25Index;
pub use frontmatter::parse_frontmatter;
pub use index::{KnowledgeError, KnowledgeIndex, Note};
pub use search::SearchResult;
pub use traversal::TraversalResult;
pub use wikilink::extract_wikilinks;
