//! Held-out benchmark schema and runner for knowledge retrieval calibration.

use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Bm25Index, HybridSearchConfig, KnowledgeIndex};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnowledgeBenchmark {
    pub version: u32,
    pub description: String,
    pub generated_from: String,
    pub questions: Vec<BenchmarkQuestion>,
    pub holdout_split: HoldoutSplit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BenchmarkQuestion {
    pub id: String,
    pub query: String,
    pub expected_top: String,
    pub expected_any_5: Vec<String>,
    pub category: String,
    pub difficulty: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HoldoutSplit {
    pub dev: String,
    pub holdout: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BenchmarkRun {
    pub version: u32,
    pub total_questions: usize,
    pub dev: SplitMetrics,
    pub holdout: SplitMetrics,
    pub questions: Vec<QuestionResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SplitMetrics {
    pub total: usize,
    pub correct_at_1: usize,
    pub correct_at_5: usize,
    pub recall_at_1: f64,
    pub recall_at_5: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuestionResult {
    pub id: String,
    pub split: String,
    pub expected_top: String,
    pub top_result: Option<String>,
    pub top_5_results: Vec<String>,
    pub hit_at_1: bool,
    pub hit_at_5: bool,
}

#[derive(Debug, Error)]
pub enum BenchmarkError {
    #[error("failed to read benchmark file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse benchmark file {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid benchmark split: {0}")]
    InvalidSplit(String),
}

impl KnowledgeBenchmark {
    pub fn load_from_path(path: &Path) -> Result<Self, BenchmarkError> {
        let contents = std::fs::read_to_string(path).map_err(|source| BenchmarkError::Io {
            path: path.display().to_string(),
            source,
        })?;
        serde_json::from_str(&contents).map_err(|source| BenchmarkError::Parse {
            path: path.display().to_string(),
            source,
        })
    }

    pub fn run(
        &self,
        index: &KnowledgeIndex,
        config: &HybridSearchConfig,
    ) -> Result<BenchmarkRun, BenchmarkError> {
        let (dev_ids, holdout_ids) = self.resolve_split_ids()?;
        let bm25 = Bm25Index::build_with_params(index.notes(), config.bm25_k1, config.bm25_b);

        let mut results = Vec::with_capacity(self.questions.len());
        for question in &self.questions {
            let ranked = index.search_hybrid(&question.query, &bm25, config);
            let top_5_results: Vec<String> = ranked
                .iter()
                .take(5)
                .map(|result| normalize_slug(&result.name))
                .collect();
            let top_result = top_5_results.first().cloned();
            let expected_at_5 = expected_at_5(question);

            let split = if dev_ids.contains(&question.id) {
                "dev"
            } else if holdout_ids.contains(&question.id) {
                "holdout"
            } else {
                return Err(BenchmarkError::InvalidSplit(format!(
                    "question {} is not covered by dev or holdout split",
                    question.id
                )));
            };

            let hit_at_1 = top_result
                .as_deref()
                .is_some_and(|slug| slug == normalize_slug(&question.expected_top));
            let hit_at_5 = top_5_results
                .iter()
                .any(|slug| expected_at_5.contains(slug));

            results.push(QuestionResult {
                id: question.id.clone(),
                split: split.to_string(),
                expected_top: normalize_slug(&question.expected_top),
                top_result,
                top_5_results,
                hit_at_1,
                hit_at_5,
            });
        }

        let dev = split_metrics(results.iter().filter(|result| result.split == "dev"));
        let holdout = split_metrics(results.iter().filter(|result| result.split == "holdout"));

        Ok(BenchmarkRun {
            version: self.version,
            total_questions: self.questions.len(),
            dev,
            holdout,
            questions: results,
        })
    }

    fn resolve_split_ids(&self) -> Result<(HashSet<String>, HashSet<String>), BenchmarkError> {
        let dev_ids = expand_question_range(&self.holdout_split.dev)?;
        let holdout_ids = expand_question_range(&self.holdout_split.holdout)?;
        Ok((dev_ids, holdout_ids))
    }
}

fn split_metrics<'a>(results: impl Iterator<Item = &'a QuestionResult>) -> SplitMetrics {
    let mut total = 0_usize;
    let mut correct_at_1 = 0_usize;
    let mut correct_at_5 = 0_usize;

    for result in results {
        total += 1;
        if result.hit_at_1 {
            correct_at_1 += 1;
        }
        if result.hit_at_5 {
            correct_at_5 += 1;
        }
    }

    SplitMetrics {
        total,
        correct_at_1,
        correct_at_5,
        recall_at_1: ratio(correct_at_1, total),
        recall_at_5: ratio(correct_at_5, total),
    }
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn expected_at_5(question: &BenchmarkQuestion) -> HashSet<String> {
    let mut expected = HashSet::new();
    expected.insert(normalize_slug(&question.expected_top));
    expected.extend(
        question
            .expected_any_5
            .iter()
            .map(|slug| normalize_slug(slug)),
    );
    expected
}

fn expand_question_range(range: &str) -> Result<HashSet<String>, BenchmarkError> {
    let (start, end) = range.split_once('-').ok_or_else(|| {
        BenchmarkError::InvalidSplit(format!(
            "expected <prefix><start>-<prefix><end>, got {range}"
        ))
    })?;

    let start_num = trailing_number(start)?;
    let end_num = trailing_number(end)?;
    if end_num < start_num {
        return Err(BenchmarkError::InvalidSplit(format!(
            "range end precedes start: {range}"
        )));
    }

    let start_prefix = start.trim_end_matches(|c: char| c.is_ascii_digit());
    let end_prefix = end.trim_end_matches(|c: char| c.is_ascii_digit());
    if start_prefix != end_prefix {
        return Err(BenchmarkError::InvalidSplit(format!(
            "range prefixes must match: {range}"
        )));
    }

    let width = start
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .count();
    let ids = (start_num..=end_num)
        .map(|num| format!("{start_prefix}{num:0width$}"))
        .collect();
    Ok(ids)
}

fn trailing_number(value: &str) -> Result<u32, BenchmarkError> {
    let digits: String = value
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .chars()
        .rev()
        .collect();

    if digits.is_empty() {
        return Err(BenchmarkError::InvalidSplit(format!(
            "range item missing numeric suffix: {value}"
        )));
    }

    digits.parse::<u32>().map_err(|_| {
        BenchmarkError::InvalidSplit(format!("invalid numeric suffix in range item: {value}"))
    })
}

fn normalize_slug(value: &str) -> String {
    value.trim().trim_end_matches(".md").to_lowercase()
}

#[cfg(test)]
mod tests {
    use lago_core::ManifestEntry;
    use lago_store::BlobStore;
    use tempfile::TempDir;

    use super::*;

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

    fn sample_benchmark() -> KnowledgeBenchmark {
        serde_json::from_str(
            r#"{
              "version": 1,
              "description": "sample",
              "generated_from": "tests",
              "questions": [
                {
                  "id": "q001",
                  "query": "what handles event persistence",
                  "expected_top": "journal",
                  "expected_any_5": ["protocol-bridge"],
                  "category": "concept",
                  "difficulty": "easy"
                },
                {
                  "id": "q002",
                  "query": "what handles tool execution",
                  "expected_top": "praxis",
                  "expected_any_5": ["tools"],
                  "category": "tool",
                  "difficulty": "easy"
                }
              ],
              "holdout_split": {
                "dev": "q001-q001",
                "holdout": "q002-q002",
                "description": "split"
              }
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn split_range_expands_ids() {
        let ids = expand_question_range("q001-q003").unwrap();
        assert!(ids.contains("q001"));
        assert!(ids.contains("q002"));
        assert!(ids.contains("q003"));
        assert_eq!(ids.len(), 3);
    }

    #[test]
    fn benchmark_runner_computes_recall_metrics() {
        let (_tmp, index) = build_index(&[
            (
                "/journal.md",
                "# Journal\n\nHandles event persistence and replay.",
            ),
            ("/praxis.md", "# Praxis\n\nCanonical tool execution engine."),
        ]);
        let benchmark = sample_benchmark();
        let report = benchmark
            .run(&index, &HybridSearchConfig::default())
            .unwrap();

        assert_eq!(report.total_questions, 2);
        assert_eq!(report.dev.total, 1);
        assert_eq!(report.holdout.total, 1);
        assert_eq!(report.dev.correct_at_1, 1);
        assert_eq!(report.holdout.correct_at_5, 1);
        assert_eq!(report.dev.recall_at_1, 1.0);
        assert_eq!(report.holdout.recall_at_5, 1.0);
    }

    #[test]
    fn load_seed_benchmark_file() {
        let benchmark: KnowledgeBenchmark =
            serde_json::from_str(include_str!("../benchmarks/knowledge-benchmark.json")).unwrap();
        assert_eq!(benchmark.questions.len(), 50);
        assert_eq!(benchmark.holdout_split.dev, "q001-q035");
        assert_eq!(benchmark.holdout_split.holdout, "q036-q050");
    }
}
