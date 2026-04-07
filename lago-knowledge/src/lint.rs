//! Lint engine for the knowledge index.
//!
//! Detects structural issues: orphan pages, broken wikilinks, missing
//! concept pages, stale claims (expired `valid_to`), and simple
//! contradiction detection between notes with `core_claim` frontmatter.

use std::collections::HashSet;

use crate::index::KnowledgeIndex;

/// A detected contradiction between two notes.
#[derive(Debug, Clone)]
pub struct Contradiction {
    /// Path of the first note.
    pub note_a: String,
    /// Path of the second note.
    pub note_b: String,
    /// Claim from the first note.
    pub claim_a: String,
    /// Claim from the second note.
    pub claim_b: String,
    /// Confidence that this is a real contradiction (0.0–1.0).
    pub confidence: f32,
}

/// Report from linting the knowledge index.
#[derive(Debug, Clone)]
pub struct LintReport {
    /// Notes with zero inbound wikilinks.
    pub orphan_pages: Vec<String>,
    /// (source_path, broken_target) pairs.
    pub broken_links: Vec<(String, String)>,
    /// Detected claim contradictions.
    pub contradictions: Vec<Contradiction>,
    /// Notes with expired `valid_to` dates (if frontmatter has `valid_to`).
    pub stale_claims: Vec<String>,
    /// Concepts mentioned in wikilinks but no note exists.
    pub missing_pages: Vec<String>,
    /// Aggregate health score (0.0 = broken, 1.0 = perfect).
    pub health_score: f32,
}

/// Negation words used for simple contradiction detection.
const NEGATION_WORDS: &[&str] = &["not", "never", "no", "without", "instead", "rather"];

impl KnowledgeIndex {
    /// Lint the knowledge index for structural issues.
    ///
    /// Checks for orphan pages (no inbound links), broken wikilinks,
    /// missing concept pages, stale claims, and contradictions between
    /// notes that share high lexical similarity but diverge on negation.
    pub fn lint(&self) -> LintReport {
        let orphan_pages = self.detect_orphans();
        let broken_links = self.detect_broken_links();
        let missing_pages = self.detect_missing_pages();
        let stale_claims = self.detect_stale_claims();
        let contradictions = self.detect_contradictions();

        let total = self.notes.len() as f32;
        let issues = orphan_pages.len() as f32
            + broken_links.len() as f32
            + contradictions.len() as f32
            + stale_claims.len() as f32;

        let health_score = if total == 0.0 {
            1.0
        } else {
            (1.0 - issues / (4.0 * total)).clamp(0.0, 1.0)
        };

        LintReport {
            orphan_pages,
            broken_links,
            contradictions,
            stale_claims,
            missing_pages,
            health_score,
        }
    }

    /// Find notes with zero inbound wikilinks (orphans).
    fn detect_orphans(&self) -> Vec<String> {
        // Build a set of all note paths that are linked TO by at least one other note.
        let mut linked_to: HashSet<String> = HashSet::new();

        for note in self.notes.values() {
            for link in &note.links {
                if let Some(target) = self.resolve_wikilink(link) {
                    // Don't count self-links
                    if target.path != note.path {
                        linked_to.insert(target.path.clone());
                    }
                }
            }
        }

        let mut orphans: Vec<String> = self
            .notes
            .values()
            .filter(|note| !linked_to.contains(&note.path))
            .map(|note| note.path.clone())
            .collect();
        orphans.sort();
        orphans
    }

    /// Find broken wikilinks (link target does not resolve to any note).
    fn detect_broken_links(&self) -> Vec<(String, String)> {
        let mut broken: Vec<(String, String)> = Vec::new();

        for note in self.notes.values() {
            for link in &note.links {
                if self.resolve_wikilink(link).is_none() {
                    broken.push((note.path.clone(), link.clone()));
                }
            }
        }

        broken.sort();
        broken
    }

    /// Find concepts referenced in wikilinks that have no corresponding note.
    /// Deduplicated list of concept names.
    fn detect_missing_pages(&self) -> Vec<String> {
        let mut missing: HashSet<String> = HashSet::new();

        for note in self.notes.values() {
            for link in &note.links {
                // Strip heading anchors for the concept name
                let clean = link.split('#').next().unwrap_or(link).trim();
                if !clean.is_empty() && self.resolve_wikilink(link).is_none() {
                    missing.insert(clean.to_string());
                }
            }
        }

        let mut result: Vec<String> = missing.into_iter().collect();
        result.sort();
        result
    }

    /// Find notes with a `valid_to` frontmatter field that is in the past.
    ///
    /// Compares against the current system time. Recognizes ISO 8601 date
    /// strings (`YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SS`).
    fn detect_stale_claims(&self) -> Vec<String> {
        let now = chrono_like_today();
        let mut stale: Vec<String> = Vec::new();

        for note in self.notes.values() {
            if let Some(valid_to) = note.frontmatter.get("valid_to")
                && let Some(date_str) = valid_to.as_str()
                && date_str.len() >= 10
                && date_str[..10] < *now
            {
                stale.push(note.path.clone());
            }
        }

        stale.sort();
        stale
    }

    /// Detect potential contradictions between notes with `core_claim` frontmatter.
    ///
    /// Uses Jaccard similarity on claim tokens + negation asymmetry.
    fn detect_contradictions(&self) -> Vec<Contradiction> {
        // Collect notes that have a core_claim
        let claims: Vec<(&str, &str)> = self
            .notes
            .values()
            .filter_map(|note| {
                note.frontmatter
                    .get("core_claim")
                    .and_then(|v| v.as_str())
                    .map(|claim| (note.path.as_str(), claim))
            })
            .collect();

        let mut contradictions = Vec::new();

        // Compare all pairs
        for i in 0..claims.len() {
            for j in (i + 1)..claims.len() {
                let (path_a, claim_a) = claims[i];
                let (path_b, claim_b) = claims[j];

                let tokens_a = tokenize_claim(claim_a);
                let tokens_b = tokenize_claim(claim_b);

                let jaccard = jaccard_similarity(&tokens_a, &tokens_b);

                // Only consider pairs with sufficient topical overlap
                if jaccard > 0.3 {
                    let neg_a = negation_count(&tokens_a);
                    let neg_b = negation_count(&tokens_b);

                    // Negation asymmetry: one claim negates, the other doesn't
                    let negation_factor = if (neg_a > 0) != (neg_b > 0) {
                        1.0
                    } else {
                        0.2 // Both negate or neither — low confidence
                    };

                    let confidence = (jaccard * negation_factor) as f32;
                    if confidence > 0.1 {
                        contradictions.push(Contradiction {
                            note_a: path_a.to_string(),
                            note_b: path_b.to_string(),
                            claim_a: claim_a.to_string(),
                            claim_b: claim_b.to_string(),
                            confidence,
                        });
                    }
                }
            }
        }

        contradictions
    }
}

/// Tokenize a claim string into lowercase words.
fn tokenize_claim(text: &str) -> HashSet<String> {
    text.to_lowercase()
        .split_whitespace()
        .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()).to_string())
        .filter(|w| !w.is_empty())
        .collect()
}

/// Compute Jaccard similarity between two token sets.
fn jaccard_similarity(a: &HashSet<String>, b: &HashSet<String>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let intersection = a.intersection(b).count() as f64;
    let union = a.union(b).count() as f64;
    if union == 0.0 {
        0.0
    } else {
        intersection / union
    }
}

/// Count negation words in a token set.
fn negation_count(tokens: &HashSet<String>) -> usize {
    tokens
        .iter()
        .filter(|t| NEGATION_WORDS.contains(&t.as_str()))
        .count()
}

/// Return today's date as a `YYYY-MM-DD` string.
///
/// Uses a simple approach without pulling in chrono as a dependency:
/// reads `SystemTime::now()` and formats as date. This is adequate
/// for day-granularity stale-claim checks.
fn chrono_like_today() -> String {
    // Compute days since Unix epoch from SystemTime
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let total_days = duration.as_secs() / 86400;

    // Civil date from day count (Euclidean affine algorithm)
    let z = total_days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}")
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
    fn healthy_vault_scores_one() {
        // Two notes that link to each other — no orphans, no broken links
        let (_tmp, index) = build_index(&[
            ("/a.md", "# A\n\nSee [[B]]."),
            ("/b.md", "# B\n\nSee [[A]]."),
        ]);

        let report = index.lint();
        assert!(report.orphan_pages.is_empty());
        assert!(report.broken_links.is_empty());
        assert!(report.missing_pages.is_empty());
        assert!(report.stale_claims.is_empty());
        assert!(report.contradictions.is_empty());
        assert!((report.health_score - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn detects_broken_link() {
        let (_tmp, index) = build_index(&[("/a.md", "# A\n\nSee [[NonExistent]].")]);

        let report = index.lint();
        assert_eq!(report.broken_links.len(), 1);
        assert_eq!(report.broken_links[0].0, "/a.md");
        assert_eq!(report.broken_links[0].1, "NonExistent");
    }

    #[test]
    fn detects_orphan_page() {
        // B and C link to each other. A has no inbound links.
        let (_tmp, index) = build_index(&[
            ("/a.md", "# A\n\nIsolated note."),
            ("/b.md", "# B\n\nSee [[C]]."),
            ("/c.md", "# C\n\nSee [[B]]."),
        ]);

        let report = index.lint();
        assert!(report.orphan_pages.contains(&"/a.md".to_string()));
    }

    #[test]
    fn detects_missing_page() {
        let (_tmp, index) = build_index(&[
            ("/a.md", "# A\n\nSee [[Missing]] and [[AlsoMissing]]."),
            ("/b.md", "# B\n\nSee [[A]]."),
        ]);

        let report = index.lint();
        assert!(report.missing_pages.contains(&"Missing".to_string()));
        assert!(report.missing_pages.contains(&"AlsoMissing".to_string()));
        assert_eq!(report.missing_pages.len(), 2);
    }

    #[test]
    fn detects_contradiction() {
        let (_tmp, index) = build_index(&[
            (
                "/a.md",
                "---\ncore_claim: Event sourcing is the best persistence pattern\n---\n# A\n\nContent.",
            ),
            (
                "/b.md",
                "---\ncore_claim: Event sourcing is not the best persistence pattern\n---\n# B\n\nContent.",
            ),
        ]);

        let report = index.lint();
        assert_eq!(report.contradictions.len(), 1);
        let c = &report.contradictions[0];
        assert!(c.confidence > 0.1);
    }

    #[test]
    fn no_contradiction_for_unrelated_claims() {
        let (_tmp, index) = build_index(&[
            (
                "/a.md",
                "---\ncore_claim: Rust is great for systems programming\n---\n# A\n\nContent.",
            ),
            (
                "/b.md",
                "---\ncore_claim: Python excels at data science workflows\n---\n# B\n\nContent.",
            ),
        ]);

        let report = index.lint();
        assert!(report.contradictions.is_empty());
    }

    #[test]
    fn detects_stale_claim() {
        // Use a date that is definitely in the past
        let (_tmp, index) = build_index(&[(
            "/old.md",
            "---\nvalid_to: 2020-01-01\n---\n# Old\n\nOutdated claim.",
        )]);

        let report = index.lint();
        assert_eq!(report.stale_claims.len(), 1);
        assert_eq!(report.stale_claims[0], "/old.md");
    }

    #[test]
    fn no_stale_for_future_date() {
        // Use a date far in the future
        let (_tmp, index) = build_index(&[(
            "/future.md",
            "---\nvalid_to: 2099-12-31\n---\n# Future\n\nStill valid.",
        )]);

        let report = index.lint();
        assert!(report.stale_claims.is_empty());
    }

    #[test]
    fn health_score_degrades_with_issues() {
        // One orphan + one broken link should lower the score
        let (_tmp, index) = build_index(&[
            ("/a.md", "# A\n\nSee [[NonExistent]]."),
            ("/b.md", "# B\n\nNo links."),
        ]);

        let report = index.lint();
        assert!(report.health_score < 1.0);
        assert!(report.health_score >= 0.0);
    }

    #[test]
    fn empty_vault_scores_one() {
        let tmp = TempDir::new().unwrap();
        let store = BlobStore::open(tmp.path()).unwrap();
        let entries: Vec<ManifestEntry> = vec![];
        let index = KnowledgeIndex::build(&entries, &store).unwrap();

        let report = index.lint();
        assert!((report.health_score - 1.0).abs() < f32::EPSILON);
    }
}
