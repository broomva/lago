//! BFS graph traversal over wikilink edges.

use std::collections::{HashSet, VecDeque};

use serde::Serialize;

use crate::index::KnowledgeIndex;

/// A note returned from graph traversal, with its depth from the start.
#[derive(Debug, Clone, Serialize)]
pub struct TraversalResult {
    /// Relative path.
    pub path: String,
    /// Note name.
    pub name: String,
    /// Depth from the start note (0 = the start note itself).
    pub depth: usize,
    /// Outgoing wikilinks.
    pub links: Vec<String>,
}

impl KnowledgeIndex {
    /// BFS traversal from a starting note, up to `depth` hops and
    /// `max_notes` total results.
    ///
    /// The start note is resolved via wikilink resolution (name or path).
    /// Returns notes in BFS order with their depth from the start.
    pub fn traverse(&self, start: &str, depth: usize, max_notes: usize) -> Vec<TraversalResult> {
        let mut visited = HashSet::new();
        let mut results = Vec::new();
        let mut queue = VecDeque::new();

        // Resolve the start note
        let start_note = match self.resolve_wikilink(start) {
            Some(note) => note,
            None => return results,
        };

        queue.push_back((start_note.path.clone(), 0usize));

        while let Some((path, level)) = queue.pop_front() {
            if results.len() >= max_notes {
                break;
            }

            if !visited.insert(path.clone()) {
                continue;
            }

            let note = match self.notes.get(&path) {
                Some(n) => n,
                None => continue,
            };

            results.push(TraversalResult {
                path: note.path.clone(),
                name: note.name.clone(),
                depth: level,
                links: note.links.clone(),
            });

            // Enqueue linked notes if within depth
            if level < depth {
                for link_target in &note.links {
                    if let Some(linked_note) = self.resolve_wikilink(link_target)
                        && !visited.contains(&linked_note.path)
                    {
                        queue.push_back((linked_note.path.clone(), level + 1));
                    }
                }
            }
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use crate::index::KnowledgeIndex;
    use lago_core::ManifestEntry;
    use lago_store::BlobStore;
    use tempfile::TempDir;

    fn build_index(files: &[(&str, &str)]) -> (TempDir, KnowledgeIndex) {
        let tmp = TempDir::new().unwrap();
        let store = BlobStore::open(tmp.path()).unwrap();
        let mut entries = Vec::new();

        for (path, content) in files {
            let hash = store.put(content.as_bytes()).unwrap();
            entries.push(ManifestEntry {
                path: path.to_string(),
                blob_hash: hash,
                size_bytes: content.len() as u64,
                content_type: Some("text/markdown".to_string()),
                updated_at: 0,
            });
        }

        let index = KnowledgeIndex::build(&entries, &store).unwrap();
        (tmp, index)
    }

    #[test]
    fn linear_chain() {
        // A → B → C
        let (_tmp, index) = build_index(&[
            ("/a.md", "# A\n\nSee [[B]]."),
            ("/b.md", "# B\n\nSee [[C]]."),
            ("/c.md", "# C\n\nEnd."),
        ]);

        let results = index.traverse("A", 2, 10);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].name, "a");
        assert_eq!(results[0].depth, 0);
        assert_eq!(results[1].name, "b");
        assert_eq!(results[1].depth, 1);
        assert_eq!(results[2].name, "c");
        assert_eq!(results[2].depth, 2);
    }

    #[test]
    fn branching_graph() {
        // A → B, A → C
        let (_tmp, index) = build_index(&[
            ("/a.md", "# A\n\nSee [[B]] and [[C]]."),
            ("/b.md", "# B\n\nLeaf."),
            ("/c.md", "# C\n\nLeaf."),
        ]);

        let results = index.traverse("A", 1, 10);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].name, "a");
    }

    #[test]
    fn cycle_handling() {
        // A → B → A (cycle)
        let (_tmp, index) = build_index(&[
            ("/a.md", "# A\n\nSee [[B]]."),
            ("/b.md", "# B\n\nSee [[A]]."),
        ]);

        let results = index.traverse("A", 5, 10);
        assert_eq!(results.len(), 2); // Should not loop
    }

    #[test]
    fn max_depth_zero() {
        let (_tmp, index) =
            build_index(&[("/a.md", "# A\n\nSee [[B]]."), ("/b.md", "# B\n\nEnd.")]);

        let results = index.traverse("A", 0, 10);
        assert_eq!(results.len(), 1); // Only the start note
        assert_eq!(results[0].name, "a");
    }

    #[test]
    fn max_notes_limit() {
        let (_tmp, index) = build_index(&[
            ("/a.md", "# A\n\nSee [[B]] and [[C]] and [[D]]."),
            ("/b.md", "# B\n\nEnd."),
            ("/c.md", "# C\n\nEnd."),
            ("/d.md", "# D\n\nEnd."),
        ]);

        let results = index.traverse("A", 1, 2);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn missing_start_note() {
        let (_tmp, index) = build_index(&[("/a.md", "# A")]);
        let results = index.traverse("nonexistent", 1, 10);
        assert!(results.is_empty());
    }
}
