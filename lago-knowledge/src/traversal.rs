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
    /// Resolve a user-facing graph reference to a note.
    ///
    /// Accepts exact manifest paths (`/notes/foo.md`), relative paths
    /// (`notes/foo.md`), path stems (`notes/foo`), plain wikilink targets
    /// (`Foo`), and bracketed wikilinks (`[[Foo#heading]]`).
    pub fn resolve_note_ref(&self, target: &str) -> Option<&crate::index::Note> {
        let clean = target
            .trim()
            .trim_start_matches("[[")
            .trim_end_matches("]]")
            .split('#')
            .next()
            .unwrap_or(target)
            .trim();

        if clean.is_empty() {
            return None;
        }

        if let Some(note) = self.get_note(clean) {
            return Some(note);
        }

        if !clean.starts_with('/') {
            let absolute = format!("/{clean}");
            if let Some(note) = self.get_note(&absolute) {
                return Some(note);
            }
        }

        let without_md = clean.trim_end_matches(".md");
        self.resolve_wikilink(without_md.trim_start_matches('/'))
            .or_else(|| self.resolve_wikilink(without_md))
            .or_else(|| self.resolve_wikilink(clean))
    }

    /// Find all notes that link TO a given slug (reverse edges / backlinks).
    ///
    /// Iterates all notes and returns those whose outgoing wikilinks
    /// resolve to the target slug.
    pub fn backlinks(&self, slug: &str) -> Vec<&crate::index::Note> {
        // Resolve the target so we know its canonical path
        let target_path = match self.resolve_wikilink(slug) {
            Some(note) => note.path.clone(),
            None => return Vec::new(),
        };

        self.notes
            .values()
            .filter(|note| {
                // Skip the target note itself
                if note.path == target_path {
                    return false;
                }
                // Check if any of this note's links resolve to the target
                note.links.iter().any(|link| {
                    self.resolve_wikilink(link)
                        .is_some_and(|resolved| resolved.path == target_path)
                })
            })
            .collect()
    }

    /// Compute normalized graph distance between two notes.
    ///
    /// Returns a proximity score in \[0.0, 1.0\]:
    /// - `1.0` means the notes are the same
    /// - `0.5` means directly linked (distance 1)
    /// - `0.0` means disconnected (no path found)
    ///
    /// Formula: `1.0 / (1.0 + distance)`, or `0.0` if unreachable.
    /// Uses BFS through wikilink edges (forward only).
    pub fn graph_proximity(&self, a: &str, b: &str) -> f32 {
        let note_a = match self.resolve_wikilink(a) {
            Some(n) => n,
            None => return 0.0,
        };
        let note_b = match self.resolve_wikilink(b) {
            Some(n) => n,
            None => return 0.0,
        };

        // Same note
        if note_a.path == note_b.path {
            return 1.0;
        }

        let target_path = &note_b.path;

        // BFS from a
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back((note_a.path.clone(), 0usize));

        while let Some((path, dist)) = queue.pop_front() {
            if !visited.insert(path.clone()) {
                continue;
            }

            if let Some(note) = self.notes.get(&path) {
                for link in &note.links {
                    if let Some(linked) = self.resolve_wikilink(link) {
                        if linked.path == *target_path {
                            return 1.0 / (1.0 + (dist + 1) as f32);
                        }
                        if !visited.contains(&linked.path) {
                            queue.push_back((linked.path.clone(), dist + 1));
                        }
                    }
                }
            }
        }

        // Disconnected
        0.0
    }

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
        let start_note = match self.resolve_note_ref(start) {
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

    #[test]
    fn resolves_exact_path_and_bracketed_wikilink_refs() {
        let (_tmp, index) = build_index(&[
            ("/notes/a.md", "# A\n\nSee [[B#details]]."),
            ("/notes/b.md", "# B"),
        ]);

        assert_eq!(
            index
                .resolve_note_ref("/notes/a.md")
                .map(|note| note.path.as_str()),
            Some("/notes/a.md")
        );
        assert_eq!(
            index
                .resolve_note_ref("[[B#details]]")
                .map(|note| note.path.as_str()),
            Some("/notes/b.md")
        );
    }

    // --- backlinks tests ---

    #[test]
    fn backlinks_basic() {
        // B and C link to A
        let (_tmp, index) = build_index(&[
            ("/a.md", "# A\n\nTarget note."),
            ("/b.md", "# B\n\nSee [[A]]."),
            ("/c.md", "# C\n\nAlso see [[A]] and [[B]]."),
        ]);

        let mut bl: Vec<&str> = index
            .backlinks("A")
            .iter()
            .map(|n| n.name.as_str())
            .collect();
        bl.sort();
        assert_eq!(bl, vec!["b", "c"]);
    }

    #[test]
    fn backlinks_no_self_link() {
        // A links to itself — should not appear in backlinks
        let (_tmp, index) = build_index(&[
            ("/a.md", "# A\n\nSee [[A]]."),
            ("/b.md", "# B\n\nSee [[A]]."),
        ]);

        let bl: Vec<&str> = index
            .backlinks("A")
            .iter()
            .map(|n| n.name.as_str())
            .collect();
        assert_eq!(bl, vec!["b"]);
    }

    #[test]
    fn backlinks_missing_target() {
        let (_tmp, index) = build_index(&[("/a.md", "# A\n\nContent.")]);
        let bl = index.backlinks("nonexistent");
        assert!(bl.is_empty());
    }

    #[test]
    fn backlinks_no_incoming() {
        // A has no incoming links
        let (_tmp, index) =
            build_index(&[("/a.md", "# A\n\nSee [[B]]."), ("/b.md", "# B\n\nLeaf.")]);

        let bl = index.backlinks("A");
        assert!(bl.is_empty());
    }

    // --- graph_proximity tests ---

    #[test]
    fn proximity_same_note() {
        let (_tmp, index) = build_index(&[("/a.md", "# A\n\nContent.")]);
        let p = index.graph_proximity("A", "A");
        assert!((p - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn proximity_direct_link() {
        let (_tmp, index) =
            build_index(&[("/a.md", "# A\n\nSee [[B]]."), ("/b.md", "# B\n\nEnd.")]);

        let p = index.graph_proximity("A", "B");
        // Distance 1 → 1/(1+1) = 0.5
        assert!((p - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn proximity_two_hops() {
        // A → B → C
        let (_tmp, index) = build_index(&[
            ("/a.md", "# A\n\nSee [[B]]."),
            ("/b.md", "# B\n\nSee [[C]]."),
            ("/c.md", "# C\n\nEnd."),
        ]);

        let p = index.graph_proximity("A", "C");
        // Distance 2 → 1/(1+2) = 0.333...
        assert!((p - 1.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn proximity_disconnected() {
        let (_tmp, index) = build_index(&[
            ("/a.md", "# A\n\nIsolated."),
            ("/b.md", "# B\n\nAlso isolated."),
        ]);

        let p = index.graph_proximity("A", "B");
        assert!((p - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn proximity_missing_note() {
        let (_tmp, index) = build_index(&[("/a.md", "# A\n\nContent.")]);
        assert!((index.graph_proximity("A", "nonexistent") - 0.0).abs() < f32::EPSILON);
        assert!((index.graph_proximity("nonexistent", "A") - 0.0).abs() < f32::EPSILON);
    }
}
