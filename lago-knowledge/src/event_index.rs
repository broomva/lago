//! Full-text search index over Lago event payloads.
//!
//! Provides BM25-ranked cross-session search by indexing the textual
//! content of events (messages, tool results, decisions, errors).
//! Built on-demand from a set of [`EventSearchEntry`]s extracted from
//! journal events.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

/// A searchable entry extracted from a Lago event envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSearchEntry {
    /// Unique event identifier.
    pub event_id: String,
    /// Session this event belongs to.
    pub session_id: String,
    /// Event type label (e.g. `"Message"`, `"ToolCallCompleted"`).
    pub event_kind: String,
    /// Microsecond timestamp.
    pub timestamp: u64,
    /// Extracted searchable text content.
    pub text: String,
}

/// A scored search result from the event index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSearchResult {
    /// Event identifier.
    pub event_id: String,
    /// Session identifier.
    pub session_id: String,
    /// Event type label.
    pub event_kind: String,
    /// Microsecond timestamp.
    pub timestamp: u64,
    /// BM25 relevance score.
    pub score: f64,
    /// Excerpt from the matching text (first matching line or truncated).
    pub excerpt: String,
}

/// BM25-ranked full-text search index over event payloads.
///
/// Build from a `Vec<EventSearchEntry>`, then search with a query string.
/// The index is immutable after construction — rebuild when new events arrive.
pub struct EventSearchIndex {
    entries: Vec<EventSearchEntry>,
    /// Total documents.
    doc_count: usize,
    /// Average document length in terms.
    avg_doc_len: f64,
    /// Term → document frequency (number of docs containing the term).
    term_doc_freq: HashMap<String, usize>,
    /// BM25 k1 parameter (term-frequency saturation).
    k1: f64,
    /// BM25 b parameter (document-length normalization).
    b: f64,
}

impl EventSearchIndex {
    /// Build a search index from extracted event entries.
    pub fn build(entries: Vec<EventSearchEntry>) -> Self {
        Self::build_with_params(entries, 1.2, 0.75)
    }

    /// Build with explicit BM25 parameters.
    pub fn build_with_params(entries: Vec<EventSearchEntry>, k1: f64, b: f64) -> Self {
        let mut term_doc_freq: HashMap<String, usize> = HashMap::new();
        let mut total_terms: usize = 0;

        for entry in &entries {
            let text = entry.text.to_lowercase();
            let tokens: Vec<&str> = text.split_whitespace().collect();
            total_terms += tokens.len();

            let mut seen = HashSet::new();
            for token in &tokens {
                if seen.insert(*token) {
                    *term_doc_freq.entry((*token).to_string()).or_insert(0) += 1;
                }
            }
        }

        let doc_count = entries.len();
        let avg_doc_len = if doc_count > 0 {
            total_terms as f64 / doc_count as f64
        } else {
            0.0
        };

        Self {
            entries,
            doc_count,
            avg_doc_len,
            term_doc_freq,
            k1,
            b,
        }
    }

    /// Search the index with a query string. Returns up to `max_results`
    /// results sorted by BM25 score descending.
    pub fn search(&self, query: &str, max_results: usize) -> Vec<EventSearchResult> {
        if self.doc_count == 0 || query.trim().is_empty() {
            return Vec::new();
        }

        let query_terms: Vec<String> = query
            .to_lowercase()
            .split_whitespace()
            .map(String::from)
            .collect();
        if query_terms.is_empty() {
            return Vec::new();
        }

        let mut scored: Vec<(usize, f64)> = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(i, entry)| {
                let score = self.bm25_score(&query_terms, &entry.text);
                if score > 0.0 { Some((i, score)) } else { None }
            })
            .collect();

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(max_results);

        scored
            .into_iter()
            .map(|(i, score)| {
                let entry = &self.entries[i];
                let excerpt = extract_excerpt(&entry.text, &query_terms, 200);
                EventSearchResult {
                    event_id: entry.event_id.clone(),
                    session_id: entry.session_id.clone(),
                    event_kind: entry.event_kind.clone(),
                    timestamp: entry.timestamp,
                    score,
                    excerpt,
                }
            })
            .collect()
    }

    /// Number of indexed entries.
    pub fn len(&self) -> usize {
        self.doc_count
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.doc_count == 0
    }

    fn bm25_score(&self, query_terms: &[String], doc_text: &str) -> f64 {
        let doc_lower = doc_text.to_lowercase();
        let doc_tokens: Vec<&str> = doc_lower.split_whitespace().collect();
        let doc_len = doc_tokens.len() as f64;

        let mut tf_map: HashMap<&str, usize> = HashMap::new();
        for token in &doc_tokens {
            *tf_map.entry(token).or_insert(0) += 1;
        }

        let n = self.doc_count as f64;
        let mut total = 0.0;

        for term in query_terms {
            let tf = *tf_map.get(term.as_str()).unwrap_or(&0) as f64;
            if tf == 0.0 {
                continue;
            }
            let df = *self.term_doc_freq.get(term).unwrap_or(&0) as f64;
            let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln().max(0.0);
            let numerator = tf * (self.k1 + 1.0);
            let denominator = tf + self.k1 * (1.0 - self.b + self.b * doc_len / self.avg_doc_len);
            total += idf * numerator / denominator;
        }

        total
    }
}

/// Extract an excerpt around the first query-term match, capped at `max_chars`.
fn extract_excerpt(text: &str, query_terms: &[String], max_chars: usize) -> String {
    let lower = text.to_lowercase();
    // Find earliest match position
    let pos = query_terms
        .iter()
        .filter_map(|term| lower.find(term.as_str()))
        .min()
        .unwrap_or(0);

    let start = pos.saturating_sub(40);
    let end = (start + max_chars).min(text.len());

    // Snap to word boundaries
    let start = if start > 0 {
        text[start..].find(' ').map_or(start, |i| start + i + 1)
    } else {
        0
    };

    let mut excerpt = text[start..end].to_string();
    if start > 0 {
        excerpt = format!("...{excerpt}");
    }
    if end < text.len() {
        excerpt.push_str("...");
    }
    excerpt
}

/// Extract searchable text from an `EventEnvelope` payload.
///
/// Returns `None` for event types that don't carry meaningful text
/// (e.g. `RunStarted`, `SessionCreated`).
pub fn extract_searchable_text(
    event_id: &str,
    session_id: &str,
    timestamp: u64,
    event_kind_name: &str,
    payload_json: &serde_json::Value,
) -> Option<EventSearchEntry> {
    let text = match event_kind_name {
        "Message" => {
            let content = payload_json.get("content")?.as_str()?;
            let role = payload_json
                .get("role")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("[{role}] {content}")
        }
        "UserMessage" => {
            let content = payload_json.get("content")?.as_str()?;
            format!("[user] {content}")
        }
        "ToolCallCompleted" => {
            let tool = payload_json
                .get("tool_name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let result = payload_json
                .get("result")
                .map(|v| {
                    if let Some(s) = v.as_str() {
                        s.to_string()
                    } else {
                        v.to_string()
                    }
                })
                .unwrap_or_default();
            // Cap tool output to avoid giant entries
            let result_capped = if result.len() > 500 {
                format!("{}...", &result[..500])
            } else {
                result
            };
            format!("[tool:{tool}] {result_capped}")
        }
        "ToolCallRequested" => {
            let tool = payload_json
                .get("tool_name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let args = payload_json
                .get("arguments")
                .map(|v| v.to_string())
                .unwrap_or_default();
            let args_capped = if args.len() > 300 {
                format!("{}...", &args[..300])
            } else {
                args
            };
            format!("[tool_call:{tool}] {args_capped}")
        }
        "ToolCallFailed" => {
            let tool = payload_json
                .get("tool_name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let error = payload_json
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            format!("[tool_error:{tool}] {error}")
        }
        "ErrorRaised" => {
            let msg = payload_json
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            format!("[error] {msg}")
        }
        "Custom" => {
            let event_type = payload_json
                .get("event_type")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            // Skip internal/machinery events
            if event_type.starts_with("eval.")
                || event_type.starts_with("autonomic.")
                || event_type.starts_with("vigil.")
            {
                return None;
            }
            let data = payload_json
                .get("data")
                .map(|v| v.to_string())
                .unwrap_or_default();
            let data_capped = if data.len() > 300 {
                format!("{}...", &data[..300])
            } else {
                data
            };
            format!("[custom:{event_type}] {data_capped}")
        }
        _ => return None,
    };

    if text.len() < 10 {
        return None; // Skip trivially short entries
    }

    Some(EventSearchEntry {
        event_id: event_id.to_string(),
        session_id: session_id.to_string(),
        event_kind: event_kind_name.to_string(),
        timestamp,
        text,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(id: &str, session: &str, kind: &str, text: &str) -> EventSearchEntry {
        EventSearchEntry {
            event_id: id.to_string(),
            session_id: session.to_string(),
            event_kind: kind.to_string(),
            timestamp: 1000,
            text: text.to_string(),
        }
    }

    #[test]
    fn empty_index_returns_no_results() {
        let idx = EventSearchIndex::build(vec![]);
        assert!(idx.is_empty());
        assert_eq!(idx.search("anything", 10).len(), 0);
    }

    #[test]
    fn empty_query_returns_no_results() {
        let idx = EventSearchIndex::build(vec![make_entry("e1", "s1", "Message", "hello world")]);
        assert_eq!(idx.search("", 10).len(), 0);
        assert_eq!(idx.search("   ", 10).len(), 0);
    }

    #[test]
    fn basic_search_finds_matching_entry() {
        let entries = vec![
            make_entry(
                "e1",
                "s1",
                "Message",
                "The agent used Rust for the implementation",
            ),
            make_entry("e2", "s1", "Message", "Python is also a good choice"),
            make_entry("e3", "s2", "Message", "Rust lifetime errors are common"),
        ];
        let idx = EventSearchIndex::build(entries);
        assert_eq!(idx.len(), 3);

        let results = idx.search("Rust", 10);
        assert_eq!(results.len(), 2);
        assert!(results[0].score >= results[1].score);
        // Both Rust-mentioning entries found
        let ids: Vec<&str> = results.iter().map(|r| r.event_id.as_str()).collect();
        assert!(ids.contains(&"e1"));
        assert!(ids.contains(&"e3"));
    }

    #[test]
    fn cross_session_search() {
        let entries = vec![
            make_entry(
                "e1",
                "session-A",
                "Message",
                "deployed the service to production",
            ),
            make_entry(
                "e2",
                "session-B",
                "ToolCallCompleted",
                "deployment succeeded on railway",
            ),
            make_entry(
                "e3",
                "session-C",
                "Message",
                "unrelated conversation about cooking",
            ),
        ];
        let idx = EventSearchIndex::build(entries);

        let results = idx.search("deployment production", 10);
        assert!(!results.is_empty());
        // Both deployment-related entries from different sessions
        let sessions: Vec<&str> = results.iter().map(|r| r.session_id.as_str()).collect();
        assert!(sessions.contains(&"session-A") || sessions.contains(&"session-B"));
    }

    #[test]
    fn max_results_limits_output() {
        let entries: Vec<_> = (0..20)
            .map(|i| {
                make_entry(
                    &format!("e{i}"),
                    "s1",
                    "Message",
                    &format!("event number {i} about Rust"),
                )
            })
            .collect();
        let idx = EventSearchIndex::build(entries);

        let results = idx.search("Rust", 5);
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn no_match_returns_empty() {
        let entries = vec![make_entry("e1", "s1", "Message", "hello world")];
        let idx = EventSearchIndex::build(entries);
        assert_eq!(idx.search("nonexistent", 10).len(), 0);
    }

    #[test]
    fn rare_term_scores_higher() {
        let entries = vec![
            make_entry(
                "e1",
                "s1",
                "Message",
                "the quantum computing breakthrough was significant",
            ),
            make_entry("e2", "s1", "Message", "the standard approach works fine"),
            make_entry("e3", "s1", "Message", "the basic method is simple"),
        ];
        let idx = EventSearchIndex::build(entries);

        let results = idx.search("quantum", 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event_id, "e1");
    }

    #[test]
    fn extract_searchable_text_message() {
        let payload = serde_json::json!({
            "content": "Hello, how can I help?",
            "role": "assistant"
        });
        let entry = extract_searchable_text("e1", "s1", 1000, "Message", &payload).unwrap();
        assert!(entry.text.contains("[assistant]"));
        assert!(entry.text.contains("Hello, how can I help?"));
    }

    #[test]
    fn extract_searchable_text_tool_completed() {
        let payload = serde_json::json!({
            "tool_name": "bash",
            "result": "command output here"
        });
        let entry =
            extract_searchable_text("e1", "s1", 1000, "ToolCallCompleted", &payload).unwrap();
        assert!(entry.text.contains("[tool:bash]"));
        assert!(entry.text.contains("command output"));
    }

    #[test]
    fn extract_skips_eval_events() {
        let payload = serde_json::json!({
            "event_type": "eval.InlineCompleted",
            "data": {"score": 0.95}
        });
        assert!(extract_searchable_text("e1", "s1", 1000, "Custom", &payload).is_none());
    }

    #[test]
    fn extract_skips_unknown_kinds() {
        let payload = serde_json::json!({"detail": "something"});
        assert!(extract_searchable_text("e1", "s1", 1000, "RunStarted", &payload).is_none());
    }

    #[test]
    fn extract_caps_long_tool_output() {
        let long_text = "x".repeat(1000);
        let payload = serde_json::json!({
            "tool_name": "bash",
            "result": long_text
        });
        let entry =
            extract_searchable_text("e1", "s1", 1000, "ToolCallCompleted", &payload).unwrap();
        assert!(entry.text.len() < 600);
        assert!(entry.text.ends_with("..."));
    }

    #[test]
    fn excerpt_extraction() {
        let text = "The quick brown fox jumps over the lazy dog near the river";
        let terms = vec!["fox".to_string()];
        let excerpt = extract_excerpt(text, &terms, 30);
        assert!(excerpt.contains("fox"));
    }
}
