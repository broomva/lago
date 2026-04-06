//! Scored search over the knowledge index.
//!
//! Scoring: +2 per query term match in note name, +1 per term match
//! in body, +1 per tag match. Excerpts are extracted from matching lines.

use serde::Serialize;

use crate::index::KnowledgeIndex;

/// A search result with relevance scoring.
#[derive(Debug, Clone, Serialize)]
pub struct SearchResult {
    /// Relative path in the manifest.
    pub path: String,
    /// Note name (filename without `.md`).
    pub name: String,
    /// Parsed YAML frontmatter.
    #[serde(with = "yaml_value_as_json")]
    pub frontmatter: serde_yaml::Value,
    /// Matching lines from the body (up to 5).
    pub excerpts: Vec<String>,
    /// Outgoing wikilinks.
    pub links: Vec<String>,
    /// Relevance score (higher is better).
    pub score: f64,
}

impl KnowledgeIndex {
    /// Search notes by query terms with scoring.
    ///
    /// Scoring:
    /// - +2 per term match in note name
    /// - +1 per term match in body text
    /// - +1 per tag match in frontmatter
    ///
    /// Returns results sorted by score descending, limited to `max_results`.
    pub fn search(&self, query: &str, max_results: usize) -> Vec<SearchResult> {
        let terms: Vec<String> = query
            .to_lowercase()
            .split_whitespace()
            .filter(|t| !t.is_empty())
            .map(String::from)
            .collect();

        if terms.is_empty() {
            return Vec::new();
        }

        let mut results: Vec<SearchResult> = Vec::new();

        for note in self.notes.values() {
            let name_lower = note.name.to_lowercase();
            let body_lower = note.body.to_lowercase();

            // Base score: count term matches in body
            let mut score: f64 = 0.0;
            for term in &terms {
                if body_lower.contains(term.as_str()) {
                    score += 1.0;
                }
            }

            // Must match at least one term somewhere
            let name_matches: f64 = terms
                .iter()
                .filter(|t| name_lower.contains(t.as_str()))
                .count() as f64;

            if score == 0.0 && name_matches == 0.0 {
                continue;
            }

            // Boost name matches
            score += name_matches * 2.0;

            // Boost tag matches
            if let Some(tags) = note.frontmatter.get("tags")
                && let Some(tag_seq) = tags.as_sequence()
            {
                for tag_val in tag_seq {
                    if let Some(tag_str) = tag_val.as_str() {
                        let tag_lower = tag_str.to_lowercase();
                        for term in &terms {
                            if tag_lower == *term {
                                score += 1.0;
                            }
                        }
                    }
                }
            }

            // Extract matching excerpt lines (up to 5)
            let mut excerpts = Vec::new();
            for line in note.body.lines() {
                if excerpts.len() >= 5 {
                    break;
                }
                let line_lower = line.to_lowercase();
                let trimmed = line.trim();
                if !trimmed.is_empty() && terms.iter().any(|t| line_lower.contains(t.as_str())) {
                    excerpts.push(trimmed.to_string());
                }
            }

            results.push(SearchResult {
                path: note.path.clone(),
                name: note.name.clone(),
                frontmatter: note.frontmatter.clone(),
                excerpts,
                links: note.links.clone(),
                score,
            });
        }

        // Sort by score descending
        results.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results.truncate(max_results);
        results
    }
}

/// Serde helper to serialize `serde_yaml::Value` as JSON-compatible values.
mod yaml_value_as_json {
    use serde::{Serialize, Serializer};

    pub fn serialize<S>(value: &serde_yaml::Value, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let json_value = yaml_to_json(value);
        json_value.serialize(serializer)
    }

    fn yaml_to_json(value: &serde_yaml::Value) -> serde_json::Value {
        match value {
            serde_yaml::Value::Null => serde_json::Value::Null,
            serde_yaml::Value::Bool(b) => serde_json::Value::Bool(*b),
            serde_yaml::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    serde_json::Value::Number(i.into())
                } else if let Some(f) = n.as_f64() {
                    serde_json::json!(f)
                } else {
                    serde_json::Value::Null
                }
            }
            serde_yaml::Value::String(s) => serde_json::Value::String(s.clone()),
            serde_yaml::Value::Sequence(seq) => {
                serde_json::Value::Array(seq.iter().map(yaml_to_json).collect())
            }
            serde_yaml::Value::Mapping(map) => {
                let mut obj = serde_json::Map::new();
                for (k, v) in map {
                    let key = match k {
                        serde_yaml::Value::String(s) => s.clone(),
                        _ => format!("{k:?}"),
                    };
                    obj.insert(key, yaml_to_json(v));
                }
                serde_json::Value::Object(obj)
            }
            serde_yaml::Value::Tagged(tagged) => yaml_to_json(&tagged.value),
        }
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
    fn search_by_name() {
        let (_tmp, index) = build_index(&[
            ("/architecture.md", "# Architecture\n\nSystem design docs."),
            ("/readme.md", "# Readme\n\nGeneral info."),
        ]);

        let results = index.search("architecture", 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "architecture");
        assert!(results[0].score > 0.0);
    }

    #[test]
    fn search_by_body() {
        let (_tmp, index) = build_index(&[
            (
                "/note.md",
                "# Note\n\nThis talks about consciousness and awareness.",
            ),
            ("/other.md", "# Other\n\nNothing relevant here."),
        ]);

        let results = index.search("consciousness", 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "note");
    }

    #[test]
    fn search_name_boost() {
        let (_tmp, index) = build_index(&[
            ("/lago.md", "# Lago\n\nPersistence."),
            ("/other.md", "# Other\n\nMentions lago in the body."),
        ]);

        let results = index.search("lago", 10);
        assert_eq!(results.len(), 2);
        // Name match should score higher
        assert_eq!(results[0].name, "lago");
        assert!(results[0].score > results[1].score);
    }

    #[test]
    fn search_tag_boost() {
        let (_tmp, index) = build_index(&[
            (
                "/tagged.md",
                "---\ntags:\n  - rust\n  - agent\n---\n# Tagged\n\nSome content about rust.",
            ),
            ("/untagged.md", "# Untagged\n\nAlso about rust."),
        ]);

        let results = index.search("rust", 10);
        assert_eq!(results.len(), 2);
        // Tagged note should score higher (body + tag boost)
        assert_eq!(results[0].name, "tagged");
    }

    #[test]
    fn search_multi_term() {
        let (_tmp, index) = build_index(&[
            ("/a.md", "# A\n\nEvent sourcing and persistence."),
            ("/b.md", "# B\n\nJust persistence."),
        ]);

        let results = index.search("event persistence", 10);
        // A matches both terms, B matches one
        assert_eq!(results[0].name, "a");
    }

    #[test]
    fn search_no_matches() {
        let (_tmp, index) = build_index(&[("/a.md", "# A\n\nSome content.")]);
        let results = index.search("nonexistent", 10);
        assert!(results.is_empty());
    }

    #[test]
    fn search_empty_query() {
        let (_tmp, index) = build_index(&[("/a.md", "# A")]);
        let results = index.search("", 10);
        assert!(results.is_empty());
    }

    #[test]
    fn search_max_results() {
        let (_tmp, index) = build_index(&[
            ("/a.md", "# A\n\nRust code."),
            ("/b.md", "# B\n\nRust code."),
            ("/c.md", "# C\n\nRust code."),
        ]);

        let results = index.search("rust", 2);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn search_excerpts() {
        let (_tmp, index) = build_index(&[(
            "/note.md",
            "# Note\n\nLine one.\nLine about rust.\nLine three.\nAnother rust line.",
        )]);

        let results = index.search("rust", 10);
        assert_eq!(results[0].excerpts.len(), 2);
        assert!(results[0].excerpts[0].contains("rust"));
    }
}
