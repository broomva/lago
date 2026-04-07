//! Document ingestion module for knowledge normalization.
//!
//! Transforms raw source documents (JSONL transcripts, Obsidian markdown,
//! plain text) into structured [`MemCube`]s suitable for indexing and search.
//!
//! ## Supported formats
//!
//! - **Claude Code JSONL**: Extracts user/assistant messages from `.jsonl` transcripts
//! - **Obsidian Markdown**: Strips YAML frontmatter, chunks by paragraphs or headings
//! - **Plain Text**: Paragraph-split fallback for unrecognized formats
//!
//! ## Safety
//!
//! - PII redaction strips common secret patterns (API keys, tokens)
//! - Noise filtering skips system reminders, tool results, and trivially short messages

use lago_core::cognitive::{CognitionKind, MemCube, MemoryTier};

/// Source format for knowledge ingestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFormat {
    /// Claude Code JSONL transcripts (~/.claude/projects/**/*.jsonl)
    ClaudeCodeJsonl,
    /// Obsidian-flavored markdown with YAML frontmatter
    ObsidianMd,
    /// Plain text (paragraph-split fallback)
    PlainText,
}

/// Configuration for knowledge ingestion.
#[derive(Debug, Clone)]
pub struct IngestConfig {
    /// Apply PII redaction patterns (default true).
    pub pii_redaction: bool,
    /// Filter noise (system reminders, tool results, short messages) (default true).
    pub noise_filtering: bool,
    /// Chunking strategy.
    pub chunk_strategy: ChunkStrategy,
    /// Default memory tier for ingested content.
    pub default_tier: MemoryTier,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            pii_redaction: true,
            noise_filtering: true,
            chunk_strategy: ChunkStrategy::SemanticParagraphs,
            default_tier: MemoryTier::Episodic,
        }
    }
}

/// How to chunk source documents into MemCubes.
#[derive(Debug, Clone)]
pub enum ChunkStrategy {
    /// Split by paragraph boundaries (>= 40 chars each).
    SemanticParagraphs,
    /// Sliding window with overlap (character-level).
    SlidingWindow {
        /// Window size in characters.
        size: usize,
        /// Overlap between consecutive windows in characters.
        overlap: usize,
    },
    /// One MemCube per document.
    WholeDocument,
}

/// Detect source format from file extension.
pub fn detect_format(path: &std::path::Path) -> SourceFormat {
    match path.extension().and_then(|e| e.to_str()) {
        Some("jsonl") => SourceFormat::ClaudeCodeJsonl,
        Some("md") => SourceFormat::ObsidianMd,
        _ => SourceFormat::PlainText,
    }
}

/// Ingest a file into MemCubes.
///
/// Reads the file, detects its format, applies chunking, noise filtering,
/// and PII redaction, then wraps each chunk in a [`MemCube`] with sensible
/// defaults.
pub fn ingest_file(
    path: &std::path::Path,
    config: &IngestConfig,
) -> Result<Vec<MemCube>, crate::KnowledgeError> {
    let content =
        std::fs::read_to_string(path).map_err(|e| crate::KnowledgeError::Store(e.to_string()))?;

    let format = detect_format(path);
    let chunks = match format {
        SourceFormat::ClaudeCodeJsonl => chunk_jsonl(&content, config),
        SourceFormat::ObsidianMd => chunk_markdown(&content, config),
        SourceFormat::PlainText => chunk_plaintext(&content, config),
    };

    let source = path.display().to_string();
    let cubes: Vec<MemCube> = chunks
        .into_iter()
        .filter(|chunk| !chunk.is_empty())
        .map(|chunk| {
            let mut cube =
                MemCube::new(config.default_tier, CognitionKind::Perceive, chunk, &source);
            cube.importance = 0.5;
            cube.confidence = 0.7;
            cube
        })
        .collect();

    Ok(cubes)
}

/// Ingest raw content string with a given format.
///
/// Useful when the content is already in memory (e.g., from a blob store)
/// rather than on disk.
pub fn ingest_content(
    content: &str,
    format: SourceFormat,
    source: &str,
    config: &IngestConfig,
) -> Vec<MemCube> {
    let chunks = match format {
        SourceFormat::ClaudeCodeJsonl => chunk_jsonl(content, config),
        SourceFormat::ObsidianMd => chunk_markdown(content, config),
        SourceFormat::PlainText => chunk_plaintext(content, config),
    };

    chunks
        .into_iter()
        .filter(|chunk| !chunk.is_empty())
        .map(|chunk| {
            let mut cube =
                MemCube::new(config.default_tier, CognitionKind::Perceive, chunk, source);
            cube.importance = 0.5;
            cube.confidence = 0.7;
            cube
        })
        .collect()
}

/// Chunk JSONL transcript: extract user and assistant messages.
fn chunk_jsonl(content: &str, config: &IngestConfig) -> Vec<String> {
    let mut chunks = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        // Try to parse as JSON and extract message content
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
            // Look for message content in common JSONL patterns
            let msg = val
                .get("message")
                .or_else(|| val.get("content"))
                .and_then(|v| v.as_str());
            if let Some(text) = msg {
                if config.noise_filtering && is_noise(text) {
                    continue;
                }
                if config.pii_redaction {
                    chunks.push(redact_pii(text));
                } else {
                    chunks.push(text.to_string());
                }
            }
        }
    }
    chunks
}

/// Chunk markdown by stripping frontmatter then applying the configured strategy.
fn chunk_markdown(content: &str, config: &IngestConfig) -> Vec<String> {
    let body = strip_frontmatter(content);
    chunk_by_strategy(body, config)
}

/// Chunk plain text using the configured strategy.
fn chunk_plaintext(content: &str, config: &IngestConfig) -> Vec<String> {
    chunk_by_strategy(content, config)
}

/// Strip YAML frontmatter delimited by `---` from markdown content.
fn strip_frontmatter(content: &str) -> &str {
    if let Some(after_open) = content.strip_prefix("---") {
        // Look for closing `---` after the opening one
        if let Some(end) = after_open.find("---") {
            // Skip past the closing `---` and any trailing newline
            let rest = &after_open[end + 3..];
            return rest.strip_prefix('\n').unwrap_or(rest);
        }
    }
    content
}

fn chunk_by_strategy(text: &str, config: &IngestConfig) -> Vec<String> {
    match &config.chunk_strategy {
        ChunkStrategy::SemanticParagraphs => text
            .split("\n\n")
            .map(|p| p.trim().to_string())
            .filter(|p| p.len() >= 40)
            .collect(),
        ChunkStrategy::SlidingWindow { size, overlap } => {
            let chars: Vec<char> = text.chars().collect();
            let mut chunks = Vec::new();
            let mut start = 0;
            while start < chars.len() {
                let end = (start + size).min(chars.len());
                let chunk: String = chars[start..end].iter().collect();
                let trimmed = chunk.trim().to_string();
                if !trimmed.is_empty() {
                    chunks.push(trimmed);
                }
                if end >= chars.len() {
                    break;
                }
                start += size.saturating_sub(*overlap);
            }
            chunks
        }
        ChunkStrategy::WholeDocument => {
            let trimmed = text.trim().to_string();
            if trimmed.is_empty() {
                vec![]
            } else {
                vec![trimmed]
            }
        }
    }
}

/// Basic noise filtering for conversation transcripts.
fn is_noise(text: &str) -> bool {
    let t = text.trim();
    t.len() < 5
        || t.starts_with("<system-reminder>")
        || t.starts_with("<task-notification>")
        || t.contains("toolUseResult")
}

/// Basic PII redaction — replace common secret patterns.
///
/// For production use, this should be extended with comprehensive regex
/// patterns covering 30+ secret types. Currently handles the most common
/// API key prefixes.
fn redact_pii(text: &str) -> String {
    let mut result = text.to_string();
    let patterns = [
        "sk-", "ghp_", "gho_", "xoxb-", "xoxp-", "sk_live_", "sk_test_",
    ];
    for pat in patterns {
        if let Some(start) = result.find(pat) {
            // Find end of token (next whitespace or end of string)
            let end = result[start..]
                .find(|c: char| c.is_whitespace())
                .map(|i| start + i)
                .unwrap_or(result.len());
            result.replace_range(start..end, "[REDACTED]");
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn detect_format_jsonl() {
        assert_eq!(
            detect_format(Path::new("session.jsonl")),
            SourceFormat::ClaudeCodeJsonl
        );
    }

    #[test]
    fn detect_format_markdown() {
        assert_eq!(
            detect_format(Path::new("notes/idea.md")),
            SourceFormat::ObsidianMd
        );
    }

    #[test]
    fn detect_format_txt() {
        assert_eq!(
            detect_format(Path::new("readme.txt")),
            SourceFormat::PlainText
        );
    }

    #[test]
    fn detect_format_unknown_extension() {
        assert_eq!(
            detect_format(Path::new("data.csv")),
            SourceFormat::PlainText
        );
    }

    #[test]
    fn detect_format_no_extension() {
        assert_eq!(
            detect_format(Path::new("Makefile")),
            SourceFormat::PlainText
        );
    }

    #[test]
    fn chunk_plaintext_paragraphs() {
        let config = IngestConfig::default();
        let text = "This is the first paragraph with enough characters to pass.\n\n\
                     This is the second paragraph, also with enough characters.\n\n\
                     Short.";
        let chunks = chunk_plaintext(text, &config);
        // Third paragraph is under 40 chars, should be filtered
        assert_eq!(chunks.len(), 2);
        assert!(chunks[0].contains("first paragraph"));
        assert!(chunks[1].contains("second paragraph"));
    }

    #[test]
    fn chunk_markdown_strips_frontmatter() {
        let config = IngestConfig::default();
        let md = "---\ntitle: Test\ntags:\n  - rust\n---\n\
                  This is the body content which is long enough to pass the filter.\n\n\
                  Second paragraph also has enough characters to be included here.";
        let chunks = chunk_markdown(md, &config);
        assert!(!chunks.is_empty());
        // None of the chunks should contain frontmatter
        for chunk in &chunks {
            assert!(!chunk.contains("title: Test"));
            assert!(!chunk.contains("tags:"));
        }
        assert!(chunks[0].contains("body content"));
    }

    #[test]
    fn chunk_markdown_no_frontmatter() {
        let config = IngestConfig::default();
        let md = "# Title\n\nThis paragraph has enough text to pass the minimum length filter.";
        let chunks = chunk_markdown(md, &config);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].contains("enough text"));
    }

    #[test]
    fn noise_filtering_system_reminders() {
        assert!(is_noise(
            "<system-reminder>You are Claude.</system-reminder>"
        ));
    }

    #[test]
    fn noise_filtering_task_notifications() {
        assert!(is_noise(
            "<task-notification>Task completed</task-notification>"
        ));
    }

    #[test]
    fn noise_filtering_tool_results() {
        assert!(is_noise(
            "The toolUseResult was successful for operation xyz"
        ));
    }

    #[test]
    fn noise_filtering_short_text() {
        assert!(is_noise("ok"));
        assert!(is_noise("    "));
    }

    #[test]
    fn noise_filtering_normal_text() {
        assert!(!is_noise(
            "This is a normal message from the user about architecture."
        ));
    }

    #[test]
    fn whole_document_strategy() {
        let config = IngestConfig {
            chunk_strategy: ChunkStrategy::WholeDocument,
            ..IngestConfig::default()
        };
        let text = "Line one.\n\nLine two.\n\nLine three.";
        let chunks = chunk_by_strategy(text, &config);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].contains("Line one."));
        assert!(chunks[0].contains("Line three."));
    }

    #[test]
    fn whole_document_empty() {
        let config = IngestConfig {
            chunk_strategy: ChunkStrategy::WholeDocument,
            ..IngestConfig::default()
        };
        let chunks = chunk_by_strategy("   \n  \n  ", &config);
        assert!(chunks.is_empty());
    }

    #[test]
    fn sliding_window_strategy() {
        let config = IngestConfig {
            chunk_strategy: ChunkStrategy::SlidingWindow {
                size: 20,
                overlap: 5,
            },
            ..IngestConfig::default()
        };
        let text = "abcdefghijklmnopqrstuvwxyz0123456789";
        let chunks = chunk_by_strategy(text, &config);
        assert!(chunks.len() > 1);
        assert_eq!(chunks[0].len(), 20);
    }

    #[test]
    fn pii_redaction_api_keys() {
        let text = "Use this key: sk-abcdef123456 to authenticate";
        let redacted = redact_pii(text);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("sk-abcdef123456"));
    }

    #[test]
    fn pii_redaction_github_token() {
        let text = "Token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx end";
        let redacted = redact_pii(text);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("ghp_"));
    }

    #[test]
    fn pii_redaction_no_secrets() {
        let text = "This is a normal message without any secrets.";
        let redacted = redact_pii(text);
        assert_eq!(redacted, text);
    }

    #[test]
    fn pii_redaction_key_at_end() {
        let text = "Key is sk_live_abcdef123";
        let redacted = redact_pii(text);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("sk_live_"));
    }

    #[test]
    fn ingest_file_not_found() {
        let config = IngestConfig::default();
        let result = ingest_file(Path::new("/nonexistent/file.txt"), &config);
        assert!(result.is_err());
    }

    #[test]
    fn ingest_file_empty() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("empty.txt");
        std::fs::write(&path, "").unwrap();

        let config = IngestConfig::default();
        let cubes = ingest_file(&path, &config).unwrap();
        assert!(cubes.is_empty());
    }

    #[test]
    fn ingest_file_plaintext() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("doc.txt");
        std::fs::write(
            &path,
            "This is the first long paragraph for testing purposes.\n\n\
             This is the second long paragraph for testing purposes.",
        )
        .unwrap();

        let config = IngestConfig::default();
        let cubes = ingest_file(&path, &config).unwrap();
        assert_eq!(cubes.len(), 2);
        assert_eq!(cubes[0].tier, MemoryTier::Episodic);
        assert_eq!(cubes[0].kind, CognitionKind::Perceive);
        assert!((cubes[0].confidence - 0.7).abs() < f32::EPSILON);
        assert!(cubes[0].source.contains("doc.txt"));
    }

    #[test]
    fn ingest_file_markdown_strips_frontmatter() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("note.md");
        std::fs::write(
            &path,
            "---\ntitle: Test Note\n---\n\
             This is the body which is long enough to be a valid chunk.",
        )
        .unwrap();

        let config = IngestConfig::default();
        let cubes = ingest_file(&path, &config).unwrap();
        assert!(!cubes.is_empty());
        for cube in &cubes {
            assert!(!cube.content.contains("title: Test Note"));
        }
    }

    #[test]
    fn ingest_jsonl_extracts_messages() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("session.jsonl");
        std::fs::write(
            &path,
            r#"{"message": "Hello, this is a user message that is long enough."}
{"message": "ok"}
{"content": "This is an assistant reply with sufficient length here."}
{"other_field": "not a message"}
"#,
        )
        .unwrap();

        let config = IngestConfig::default();
        let cubes = ingest_file(&path, &config).unwrap();
        // "ok" is too short (noise filtered), "other_field" has no message/content
        assert_eq!(cubes.len(), 2);
        assert!(cubes[0].content.contains("user message"));
        assert!(cubes[1].content.contains("assistant reply"));
    }

    #[test]
    fn ingest_content_api() {
        let config = IngestConfig::default();
        let cubes = ingest_content(
            "Paragraph one is long enough to pass the forty character minimum.\n\n\
             Paragraph two is also long enough to pass the forty character minimum.",
            SourceFormat::PlainText,
            "test://inline",
            &config,
        );
        assert_eq!(cubes.len(), 2);
        assert_eq!(cubes[0].source, "test://inline");
    }

    #[test]
    fn ingest_with_custom_tier() {
        let config = IngestConfig {
            default_tier: MemoryTier::Semantic,
            ..IngestConfig::default()
        };
        let cubes = ingest_content(
            "This is semantic knowledge extracted from research papers and documentation.",
            SourceFormat::PlainText,
            "research",
            &config,
        );
        // Whole thing is one paragraph >= 40 chars
        assert_eq!(cubes.len(), 1);
        assert_eq!(cubes[0].tier, MemoryTier::Semantic);
    }

    #[test]
    fn jsonl_noise_filtered() {
        let config = IngestConfig {
            noise_filtering: true,
            ..IngestConfig::default()
        };
        let content = r#"{"message": "<system-reminder>You are Claude.</system-reminder>"}
{"message": "This is a real user question about the architecture."}
{"message": "The toolUseResult was successful"}
"#;
        let chunks = chunk_jsonl(content, &config);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].contains("real user question"));
    }

    #[test]
    fn jsonl_pii_redacted() {
        let config = IngestConfig {
            pii_redaction: true,
            noise_filtering: false,
            ..IngestConfig::default()
        };
        let content = r#"{"message": "Set your key to sk-abc123def456 for access"}"#;
        let chunks = chunk_jsonl(content, &config);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].contains("[REDACTED]"));
        assert!(!chunks[0].contains("sk-abc123def456"));
    }

    #[test]
    fn jsonl_no_pii_redaction() {
        let config = IngestConfig {
            pii_redaction: false,
            noise_filtering: false,
            ..IngestConfig::default()
        };
        let content = r#"{"message": "Key is sk-abc123def456 end"}"#;
        let chunks = chunk_jsonl(content, &config);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].contains("sk-abc123def456"));
    }

    #[test]
    fn strip_frontmatter_preserves_body() {
        let content = "---\ntitle: Hello\ntags: [a, b]\n---\n# Body\n\nParagraph.";
        let body = strip_frontmatter(content);
        assert!(body.starts_with("# Body"));
        assert!(!body.contains("title: Hello"));
    }

    #[test]
    fn strip_frontmatter_no_delimiter() {
        let content = "# Just a heading\n\nNo frontmatter here.";
        let body = strip_frontmatter(content);
        assert_eq!(body, content);
    }

    #[test]
    fn strip_frontmatter_unclosed() {
        let content = "---\ntitle: Oops\nNo closing delimiter";
        let body = strip_frontmatter(content);
        // Unclosed frontmatter is preserved as-is
        assert_eq!(body, content);
    }
}
