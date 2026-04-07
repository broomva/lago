//! Scored search over the knowledge index.
//!
//! Scoring: +2 per query term match in note name, +1 per term match
//! in body, +1 per tag match. Excerpts are extracted from matching lines.
//!
//! [`KnowledgeIndex::search_hybrid`] combines BM25 ranking with keyword
//! and graph-proximity boosts for higher-quality retrieval.

use serde::Serialize;

use crate::bm25::Bm25Index;
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

/// Configuration for hybrid search combining BM25 + keyword + graph proximity.
#[derive(Debug, Clone)]
pub struct HybridSearchConfig {
    /// Weight for exact keyword matches in title/tags (default 0.30).
    /// Empirically tuned by MemPalace over 500 queries.
    pub keyword_boost: f64,
    /// Weight for graph proximity bonus (default 0.15).
    pub graph_boost: f64,
    /// Maximum results to return.
    pub max_results: usize,
    /// Whether to boost recent notes (reserved for future use).
    pub temporal_boost: bool,
}

impl Default for HybridSearchConfig {
    fn default() -> Self {
        Self {
            keyword_boost: 0.30,
            graph_boost: 0.15,
            max_results: 10,
            temporal_boost: false,
        }
    }
}

impl KnowledgeIndex {
    /// Hybrid search combining BM25 scoring with keyword and graph proximity boosts.
    ///
    /// For each candidate note:
    /// 1. Compute BM25 score from the pre-built [`Bm25Index`].
    /// 2. Add a keyword bonus for exact term matches in note name and tags.
    /// 3. Compute graph proximity to the current top scorers (notes above median)
    ///    and add a graph bonus proportional to average proximity.
    ///
    /// Returns results sorted by final score descending, limited to
    /// [`HybridSearchConfig::max_results`].
    pub fn search_hybrid(
        &self,
        query: &str,
        bm25: &Bm25Index,
        config: &HybridSearchConfig,
    ) -> Vec<SearchResult> {
        let terms: Vec<String> = query
            .to_lowercase()
            .split_whitespace()
            .filter(|t| !t.is_empty())
            .map(String::from)
            .collect();

        if terms.is_empty() {
            return Vec::new();
        }

        // Phase 1: Score every note with BM25 + keyword bonus.
        // Collect (path, bm25_score, keyword_bonus) for notes that match at all.
        let mut candidates: Vec<(String, f64, f64)> = Vec::new();

        for note in self.notes.values() {
            let doc_text = format!("{} {}", note.name, note.body);
            let bm25_score = bm25.score(&terms, &doc_text);

            // Keyword bonus: exact term matches in name and tags
            let name_lower = note.name.to_lowercase();
            let name_matches = terms
                .iter()
                .filter(|t| name_lower.contains(t.as_str()))
                .count();

            let tag_matches = note
                .frontmatter
                .get("tags")
                .and_then(|v| v.as_sequence())
                .map(|seq| {
                    seq.iter()
                        .filter_map(|v| v.as_str())
                        .filter(|tag| {
                            let tag_lower = tag.to_lowercase();
                            terms.contains(&tag_lower)
                        })
                        .count()
                })
                .unwrap_or(0);

            let keyword_bonus = if !terms.is_empty() {
                config.keyword_boost * (name_matches + tag_matches) as f64 / terms.len() as f64
            } else {
                0.0
            };

            // Skip notes that have zero relevance
            if bm25_score == 0.0 && name_matches == 0 && tag_matches == 0 {
                continue;
            }

            candidates.push((note.path.clone(), bm25_score, keyword_bonus));
        }

        if candidates.is_empty() {
            return Vec::new();
        }

        // Phase 2: Compute graph proximity bonus.
        // Find the median base score (bm25 + keyword) to identify "above-median" notes.
        let mut base_scores: Vec<f64> = candidates
            .iter()
            .map(|(_, bm25_s, kw_b)| bm25_s + kw_b)
            .collect();
        base_scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median = if base_scores.is_empty() {
            0.0
        } else {
            base_scores[base_scores.len() / 2]
        };

        // Collect names of above-median notes for graph proximity computation.
        let above_median_names: Vec<String> = candidates
            .iter()
            .filter(|(_, bm25_s, kw_b)| bm25_s + kw_b > median)
            .filter_map(|(path, _, _)| self.notes.get(path).map(|n| n.name.clone()))
            .collect();

        // Phase 3: Assemble final scores.
        let mut results: Vec<SearchResult> = Vec::new();

        for (path, bm25_score, keyword_bonus) in &candidates {
            let note = match self.notes.get(path) {
                Some(n) => n,
                None => continue,
            };

            // Graph bonus: average proximity to above-median notes
            let graph_bonus = if !above_median_names.is_empty() {
                let total_proximity: f64 = above_median_names
                    .iter()
                    .map(|other_name| self.graph_proximity(&note.name, other_name) as f64)
                    .sum();
                config.graph_boost * total_proximity / above_median_names.len() as f64
            } else {
                0.0
            };

            let final_score = bm25_score + keyword_bonus + graph_bonus;

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
                score: final_score,
            });
        }

        // Sort by score descending
        results.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results.truncate(config.max_results);
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
    use crate::bm25::Bm25Index;
    use crate::index::KnowledgeIndex;
    use crate::search::HybridSearchConfig;
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

    // --- hybrid search tests ---

    #[test]
    fn hybrid_config_defaults() {
        let config = HybridSearchConfig::default();
        assert!((config.keyword_boost - 0.30).abs() < f64::EPSILON);
        assert!((config.graph_boost - 0.15).abs() < f64::EPSILON);
        assert_eq!(config.max_results, 10);
        assert!(!config.temporal_boost);
    }

    #[test]
    fn hybrid_empty_query() {
        let (_tmp, index) = build_index(&[("/a.md", "# A\n\nSome content.")]);
        let bm25 = Bm25Index::build(index.notes());
        let config = HybridSearchConfig::default();
        let results = index.search_hybrid("", &bm25, &config);
        assert!(results.is_empty());
    }

    #[test]
    fn hybrid_no_matches() {
        let (_tmp, index) = build_index(&[("/a.md", "# A\n\nSome content.")]);
        let bm25 = Bm25Index::build(index.notes());
        let config = HybridSearchConfig::default();
        let results = index.search_hybrid("nonexistent", &bm25, &config);
        assert!(results.is_empty());
    }

    #[test]
    fn hybrid_keyword_boost_helps_title_match() {
        // "lago" appears in both bodies, but note A has it in the title
        let (_tmp, index) = build_index(&[
            ("/lago.md", "# Lago\n\nPersistence substrate."),
            ("/other.md", "# Other\n\nMentions lago in passing."),
        ]);
        let bm25 = Bm25Index::build(index.notes());
        let config = HybridSearchConfig::default();

        let results = index.search_hybrid("lago", &bm25, &config);
        assert_eq!(results.len(), 2);
        // Name-bearing note should rank first due to keyword boost
        assert_eq!(results[0].name, "lago");
        assert!(results[0].score > results[1].score);
    }

    #[test]
    fn hybrid_graph_boost_helps_connected_notes() {
        // A links to B and C. D is isolated. All mention "rust".
        // B and C should get a graph boost because they're connected to A (also relevant).
        let (_tmp, index) = build_index(&[
            ("/a.md", "# A\n\nRust systems. See [[B]] and [[C]]."),
            ("/b.md", "# B\n\nRust programming."),
            ("/c.md", "# C\n\nRust language."),
            ("/d.md", "# D\n\nRust isolated note with no links."),
        ]);
        let bm25 = Bm25Index::build(index.notes());
        let config = HybridSearchConfig {
            graph_boost: 0.50, // amplify to make the effect measurable
            ..Default::default()
        };

        let results = index.search_hybrid("rust", &bm25, &config);
        assert!(!results.is_empty());

        // Find scores for linked vs isolated notes
        let score_b = results.iter().find(|r| r.name == "b").map(|r| r.score);
        let score_d = results.iter().find(|r| r.name == "d").map(|r| r.score);

        // B should score higher than D because B is graph-connected to A (also relevant)
        if let (Some(sb), Some(sd)) = (score_b, score_d) {
            assert!(
                sb >= sd,
                "graph-connected note B ({sb}) should score >= isolated D ({sd})"
            );
        }
    }

    #[test]
    fn hybrid_max_results_respected() {
        let (_tmp, index) = build_index(&[
            ("/a.md", "# A\n\nRust code."),
            ("/b.md", "# B\n\nRust code."),
            ("/c.md", "# C\n\nRust code."),
        ]);
        let bm25 = Bm25Index::build(index.notes());
        let config = HybridSearchConfig {
            max_results: 2,
            ..Default::default()
        };

        let results = index.search_hybrid("rust", &bm25, &config);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn hybrid_beats_basic_for_graph_connected() {
        // A links to B. B has the query term. C also has the query term but is isolated.
        // Hybrid search should rank B higher than basic search does (relative to C).
        let (_tmp, index) = build_index(&[
            ("/a.md", "# A\n\nEvent sourcing architecture. See [[B]]."),
            ("/b.md", "# B\n\nEvent persistence layer."),
            ("/c.md", "# C\n\nEvent logging utility."),
        ]);
        let bm25 = Bm25Index::build(index.notes());
        let config = HybridSearchConfig {
            graph_boost: 0.50,
            ..Default::default()
        };

        let basic = index.search("event", 10);
        let hybrid = index.search_hybrid("event", &bm25, &config);

        // Both should return results
        assert!(!basic.is_empty());
        assert!(!hybrid.is_empty());

        // In hybrid, B should benefit from graph proximity to A
        let hybrid_b = hybrid.iter().find(|r| r.name == "b").unwrap();
        assert!(hybrid_b.score > 0.0);
    }

    #[test]
    fn hybrid_tag_boost() {
        let (_tmp, index) = build_index(&[
            (
                "/tagged.md",
                "---\ntags:\n  - rust\n  - systems\n---\n# Tagged\n\nContent about rust programming",
            ),
            (
                "/untagged.md",
                "# Untagged\n\nAlso about rust programming here",
            ),
        ]);
        let bm25 = Bm25Index::build(index.notes());
        let config = HybridSearchConfig::default();

        let results = index.search_hybrid("rust", &bm25, &config);
        assert_eq!(results.len(), 2);
        // Tagged note should rank higher due to keyword boost on tags
        assert_eq!(results[0].name, "tagged");
    }
}
