//! # lago-compiler — Context Compiler
//!
//! Assembles optimal LLM context windows from the cognitive memory store.
//! The compiler is storage-agnostic: it takes `Vec<MemCube>` as input and
//! produces a budget-constrained, relevance-ordered context window.
//!
//! ## Architecture
//!
//! ```text
//! MemoryRetriever ──→ Vec<MemCube> ──→ ContextCompiler ──→ CompiledContext
//!                                        │
//!                                        ├── scorer (relevance scoring)
//!                                        └── formatter (LLM-friendly text)
//! ```
//!
//! The [`MemoryRetriever`] trait allows different backends (filesystem, Lance,
//! in-memory) to feed memories into the compiler. The compiler scores each
//! memory for relevance, packs them into the token budget using a greedy
//! knapsack, and formats them as natural language sections.

pub mod compiler;
pub mod formatter;
pub mod retriever;
pub mod scorer;

pub use compiler::{
    CompilationStrategy, CompiledContext, ContextCompiler, ContextRequest, ContextSection,
};
pub use retriever::{FilesystemRetriever, MemoryRetriever};
