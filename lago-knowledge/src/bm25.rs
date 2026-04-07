//! BM25 (Okapi BM25) scoring for the knowledge index.
//!
//! Provides proper TF-IDF–based ranking as an alternative to the naive
//! keyword scoring in `search.rs`. Build a [`Bm25Index`] from the notes
//! in a [`KnowledgeIndex`], then call [`Bm25Index::score`] to rank
//! individual documents against a set of query terms.

use std::collections::HashMap;

use crate::index::Note;

/// Pre-computed corpus statistics for BM25 scoring.
///
/// Build once from a set of `Note`s, then reuse across queries.
pub struct Bm25Index {
    /// Total number of documents in the corpus.
    doc_count: usize,
    /// Average document length (in terms) across the corpus.
    avg_doc_len: f64,
    /// term → number of documents containing that term.
    term_doc_freq: HashMap<String, usize>,
    /// BM25 term-frequency saturation parameter (default 1.2).
    k1: f64,
    /// BM25 document-length normalization parameter (default 0.75).
    b: f64,
}

impl Bm25Index {
    /// Build a BM25 index from the notes in a [`KnowledgeIndex`].
    ///
    /// Tokenizes each note's name and body (lowercased, whitespace-split)
    /// and computes document frequencies and average document length.
    pub fn build(notes: &HashMap<String, Note>) -> Self {
        let mut term_doc_freq: HashMap<String, usize> = HashMap::new();
        let mut total_terms: usize = 0;

        for note in notes.values() {
            let text = format!("{} {}", note.name, note.body).to_lowercase();
            let tokens: Vec<String> = text.split_whitespace().map(String::from).collect();

            total_terms += tokens.len();

            // Count each unique term once per document
            let mut seen = std::collections::HashSet::new();
            for token in &tokens {
                if seen.insert(token.clone()) {
                    *term_doc_freq.entry(token.clone()).or_insert(0) += 1;
                }
            }
        }

        let doc_count = notes.len();
        let avg_doc_len = if doc_count > 0 {
            total_terms as f64 / doc_count as f64
        } else {
            0.0
        };

        Self {
            doc_count,
            avg_doc_len,
            term_doc_freq,
            k1: 1.2,
            b: 0.75,
        }
    }

    /// Score a document against a set of query terms using BM25.
    ///
    /// `query_terms` should be lowercased. `doc_text` is the raw text
    /// of the document (name + body concatenated). Returns 0.0 for an
    /// empty query.
    ///
    /// Formula:
    /// ```text
    /// score(q, d) = SUM_i [ IDF(qi) * (tf(qi,d) * (k1+1)) / (tf(qi,d) + k1 * (1 - b + b * |d|/avgdl)) ]
    /// where IDF(qi) = ln((N - n(qi) + 0.5) / (n(qi) + 0.5) + 1)
    /// ```
    pub fn score(&self, query_terms: &[String], doc_text: &str) -> f64 {
        if query_terms.is_empty() || self.doc_count == 0 {
            return 0.0;
        }

        let doc_lower = doc_text.to_lowercase();
        let doc_tokens: Vec<&str> = doc_lower.split_whitespace().collect();
        let doc_len = doc_tokens.len() as f64;

        // Count term frequencies in this document
        let mut tf_map: HashMap<&str, usize> = HashMap::new();
        for token in &doc_tokens {
            *tf_map.entry(token).or_insert(0) += 1;
        }

        let n = self.doc_count as f64;
        let mut total_score = 0.0;

        for term in query_terms {
            let tf = *tf_map.get(term.as_str()).unwrap_or(&0) as f64;
            if tf == 0.0 {
                continue;
            }

            let df = *self.term_doc_freq.get(term).unwrap_or(&0) as f64;

            // IDF with floor at 0 to avoid negative scores for very common terms
            let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();
            let idf = idf.max(0.0);

            let numerator = tf * (self.k1 + 1.0);
            let denominator = tf + self.k1 * (1.0 - self.b + self.b * doc_len / self.avg_doc_len);

            total_score += idf * numerator / denominator;
        }

        total_score
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_note(path: &str, name: &str, body: &str) -> Note {
        Note {
            path: path.to_string(),
            name: name.to_string(),
            frontmatter: serde_yaml::Value::Null,
            body: body.to_string(),
            links: vec![],
        }
    }

    fn make_notes(entries: &[(&str, &str, &str)]) -> HashMap<String, Note> {
        entries
            .iter()
            .map(|(path, name, body)| (path.to_string(), make_note(path, name, body)))
            .collect()
    }

    #[test]
    fn empty_query_returns_zero() {
        let notes = make_notes(&[("/a.md", "alpha", "some text about alpha")]);
        let idx = Bm25Index::build(&notes);
        let score = idx.score(&[], "some text about alpha");
        assert!((score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn empty_corpus_returns_zero() {
        let notes: HashMap<String, Note> = HashMap::new();
        let idx = Bm25Index::build(&notes);
        let score = idx.score(&["hello".to_string()], "hello world");
        assert!((score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn name_match_scores_higher_than_body_match() {
        // Doc A has the query term in its name (so name + body both contain it)
        // Doc B only has the query term deep in its body
        let notes = make_notes(&[
            (
                "/rust.md",
                "rust",
                "Rust is a systems programming language.",
            ),
            ("/other.md", "other", "Some notes mentioning rust briefly."),
        ]);

        let idx = Bm25Index::build(&notes);
        let query = vec!["rust".to_string()];

        let score_a = idx.score(&query, "rust Rust is a systems programming language.");
        let score_b = idx.score(&query, "other Some notes mentioning rust briefly.");

        // Doc A has "rust" appearing more often (in name position)
        assert!(
            score_a > score_b,
            "name-bearing doc should score higher: {score_a} vs {score_b}"
        );
    }

    #[test]
    fn multi_term_query_boosts_multi_match() {
        let notes = make_notes(&[
            ("/a.md", "event", "Event sourcing and persistence layer."),
            ("/b.md", "persist", "Only about persistence."),
        ]);

        let idx = Bm25Index::build(&notes);
        let query = vec!["event".to_string(), "persistence".to_string()];

        let score_a = idx.score(&query, "event Event sourcing and persistence layer.");
        let score_b = idx.score(&query, "persist Only about persistence.");

        assert!(
            score_a > score_b,
            "multi-match should score higher: {score_a} vs {score_b}"
        );
    }

    #[test]
    fn rare_term_scores_higher() {
        // "quantum" appears in 1 doc, "the" appears in all docs
        let notes = make_notes(&[
            ("/a.md", "doc1", "the quantum computing revolution"),
            ("/b.md", "doc2", "the standard computing approach"),
            ("/c.md", "doc3", "the basic computing primer"),
        ]);

        let idx = Bm25Index::build(&notes);

        let quantum_score = idx.score(&["quantum".to_string()], "the quantum computing revolution");
        let the_score = idx.score(&["the".to_string()], "the quantum computing revolution");

        assert!(
            quantum_score > the_score,
            "rare term 'quantum' should score higher than common 'the': {quantum_score} vs {the_score}"
        );
    }

    #[test]
    fn no_match_returns_zero() {
        let notes = make_notes(&[("/a.md", "alpha", "some text content here")]);
        let idx = Bm25Index::build(&notes);
        let score = idx.score(&["nonexistent".to_string()], "some text content here");
        assert!((score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn build_computes_correct_stats() {
        let notes = make_notes(&[
            ("/a.md", "alpha", "one two three"),      // 4 tokens (alpha + 3)
            ("/b.md", "beta", "four five six seven"), // 5 tokens (beta + 4)
        ]);

        let idx = Bm25Index::build(&notes);
        assert_eq!(idx.doc_count, 2);
        assert!((idx.avg_doc_len - 4.5).abs() < f64::EPSILON); // (4+5)/2
        assert_eq!(idx.k1, 1.2);
        assert_eq!(idx.b, 0.75);
    }
}
