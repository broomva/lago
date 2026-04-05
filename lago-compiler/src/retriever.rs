//! Memory retrieval interface and filesystem-based implementation.
//!
//! The [`MemoryRetriever`] trait abstracts memory lookup so the compiler
//! can work with any backend — filesystem, Lance, in-memory, etc.
//! [`FilesystemRetriever`] provides a Level 0 implementation that reads
//! `.md` files from a directory and creates MemCubes from them.

use lago_core::cognitive::{CognitionKind, MemCube, MemoryTier};

/// Trait for retrieving memories from a store.
///
/// Implemented by filesystem stores, Lance-backed stores, in-memory
/// stores, etc. The compiler calls this to get candidate memories
/// before scoring and packing them.
pub trait MemoryRetriever: Send + Sync {
    /// Retrieve memories relevant to the given query.
    ///
    /// # Arguments
    /// - `query` — the task or search string
    /// - `tiers` — which memory tiers to search (empty = all)
    /// - `limit` — maximum number of memories to return
    fn retrieve(&self, query: &str, tiers: &[MemoryTier], limit: usize) -> Vec<MemCube>;
}

/// Simple filesystem-based retriever (Level 0).
///
/// Reads `.md` files from a directory, performs basic keyword matching,
/// and creates MemCubes from the file contents. This is the simplest
/// possible retriever — suitable for bootstrapping before Lance is wired.
pub struct FilesystemRetriever {
    memory_dir: std::path::PathBuf,
}

impl FilesystemRetriever {
    /// Create a new filesystem retriever rooted at the given directory.
    pub fn new(memory_dir: impl Into<std::path::PathBuf>) -> Self {
        Self {
            memory_dir: memory_dir.into(),
        }
    }
}

impl MemoryRetriever for FilesystemRetriever {
    fn retrieve(&self, query: &str, _tiers: &[MemoryTier], limit: usize) -> Vec<MemCube> {
        let mut cubes = Vec::new();

        let entries = match std::fs::read_dir(&self.memory_dir) {
            Ok(entries) => entries,
            Err(_) => return cubes,
        };

        for entry in entries.flatten() {
            if cubes.len() >= limit {
                break;
            }

            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("md") {
                continue;
            }

            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let key = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();

            // Simple keyword matching: if query is empty, include all.
            // Otherwise require at least one word (len > 2) to match.
            let include = if query.is_empty() {
                true
            } else {
                let query_lower = query.to_lowercase();
                let content_lower = content.to_lowercase();
                query_lower
                    .split_whitespace()
                    .any(|w| w.len() > 2 && content_lower.contains(w))
            };

            if include {
                let mut cube = MemCube::new(
                    MemoryTier::Semantic,
                    CognitionKind::Consolidate,
                    content,
                    "filesystem",
                );
                cube.id = key;
                cubes.push(cube);
            }
        }

        cubes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filesystem_retriever_reads_md_files() {
        let dir = tempfile::tempdir().unwrap();

        // Write some test files
        std::fs::write(
            dir.path().join("rust-guide.md"),
            "Rust is a systems language",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("python-guide.md"),
            "Python is an interpreted language",
        )
        .unwrap();
        std::fs::write(dir.path().join("not-markdown.txt"), "This is not markdown").unwrap();

        let retriever = FilesystemRetriever::new(dir.path());

        // Empty query returns all .md files
        let results = retriever.retrieve("", &[], 100);
        assert_eq!(
            results.len(),
            2,
            "should find 2 .md files, got {}",
            results.len()
        );

        // All should be Semantic tier
        for cube in &results {
            assert_eq!(cube.tier, MemoryTier::Semantic);
            assert_eq!(cube.source, "filesystem");
        }
    }

    #[test]
    fn test_filesystem_retriever_keyword_filter() {
        let dir = tempfile::tempdir().unwrap();

        std::fs::write(dir.path().join("rust.md"), "Rust ownership and borrowing").unwrap();
        std::fs::write(dir.path().join("python.md"), "Python dynamic typing").unwrap();

        let retriever = FilesystemRetriever::new(dir.path());

        let results = retriever.retrieve("Rust ownership", &[], 100);
        assert_eq!(results.len(), 1);
        assert!(results[0].content.contains("Rust"));
    }

    #[test]
    fn test_filesystem_retriever_respects_limit() {
        let dir = tempfile::tempdir().unwrap();

        for i in 0..10 {
            std::fs::write(
                dir.path().join(format!("file{i}.md")),
                format!("content {i}"),
            )
            .unwrap();
        }

        let retriever = FilesystemRetriever::new(dir.path());
        let results = retriever.retrieve("", &[], 3);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_filesystem_retriever_nonexistent_dir() {
        let retriever = FilesystemRetriever::new("/nonexistent/path/that/does/not/exist");
        let results = retriever.retrieve("anything", &[], 100);
        assert!(results.is_empty());
    }

    #[test]
    fn test_filesystem_retriever_uses_filename_as_id() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("my-memory.md"), "some content").unwrap();

        let retriever = FilesystemRetriever::new(dir.path());
        let results = retriever.retrieve("", &[], 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "my-memory");
    }
}
