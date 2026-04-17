//! `lago wiki` subcommands — knowledge substrate operations.
//!
//! Operates directly on a directory of `.md` files, building a
//! `KnowledgeIndex` for search, lint, index generation, and more.
//! No daemon required — works fully offline.

use std::path::{Path, PathBuf};

use lago_core::ManifestEntry;
use lago_knowledge::bm25::Bm25Index;
use lago_knowledge::ingest::{self, IngestConfig};
use lago_knowledge::{HybridSearchConfig, KnowledgeIndex};
use lago_store::BlobStore;

/// Build a KnowledgeIndex from all `.md` files in a directory.
///
/// Stores content in a temporary BlobStore and constructs the index.
/// Returns the index and the blob store (kept alive for the index to reference).
fn build_index_from_dir(
    wiki_dir: &Path,
) -> Result<(KnowledgeIndex, BlobStore), Box<dyn std::error::Error>> {
    let blob_dir = wiki_dir.join(".lago-blobs");
    std::fs::create_dir_all(&blob_dir)?;
    let store = BlobStore::open(&blob_dir)?;

    let md_files = collect_md_files(wiki_dir);
    let mut entries = Vec::new();

    for file in &md_files {
        let content = std::fs::read(file)?;
        let hash = store.put(&content)?;
        let rel_path = file
            .strip_prefix(wiki_dir)
            .unwrap_or(file)
            .to_string_lossy();
        entries.push(ManifestEntry {
            path: format!("/{rel_path}"),
            blob_hash: hash,
            size_bytes: content.len() as u64,
            content_type: Some("text/markdown".to_string()),
            updated_at: file
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0),
        });
    }

    let index = KnowledgeIndex::build(&entries, &store)?;
    Ok((index, store))
}

/// Recursively collect `.md` files, skipping hidden dirs and node_modules.
fn collect_md_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if name.starts_with('.') || name == "node_modules" {
                continue;
            }
            if path.is_dir() {
                files.extend(collect_md_files(&path));
            } else if path.extension().is_some_and(|e| e == "md") {
                files.push(path);
            }
        }
    }
    files
}

// ── Search ──────────────────────────────────────────────────────────────

pub fn search(
    wiki_dir: &Path,
    query: &str,
    max_results: usize,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (index, _store) = build_index_from_dir(wiki_dir)?;
    let config = HybridSearchConfig {
        max_results,
        ..Default::default()
    };
    let bm25 = Bm25Index::build_with_params(index.notes(), config.bm25_k1, config.bm25_b);

    let results = index.search_hybrid(query, &bm25, &config);

    if json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else if results.is_empty() {
        println!("No results found for: {query}");
    } else {
        for (i, r) in results.iter().enumerate() {
            println!("{}. **{}** [score: {:.2}]", i + 1, r.name, r.score);
            println!("   {}", r.path);
            for excerpt in r.excerpts.iter().take(2) {
                println!("   > {excerpt}");
            }
            if !r.links.is_empty() {
                println!("   links: {}", r.links.join(", "));
            }
            println!();
        }
        println!("{} result(s)", results.len());
    }

    Ok(())
}

// ── Lint ─────────────────────────────────────────────────────────────────

pub fn lint(wiki_dir: &Path, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let (index, _store) = build_index_from_dir(wiki_dir)?;
    let report = index.lint();

    if json {
        let json_report = serde_json::json!({
            "health_score": report.health_score,
            "orphan_pages": report.orphan_pages,
            "broken_links": report.broken_links,
            "contradictions": report.contradictions.iter().map(|c| {
                serde_json::json!({
                    "note_a": c.note_a,
                    "note_b": c.note_b,
                    "claim_a": c.claim_a,
                    "claim_b": c.claim_b,
                    "confidence": c.confidence,
                })
            }).collect::<Vec<_>>(),
            "stale_claims": report.stale_claims,
            "missing_pages": report.missing_pages,
            "total_notes": index.len(),
        });
        println!("{}", serde_json::to_string_pretty(&json_report)?);
    } else {
        println!("## Knowledge Lint Report\n");
        println!("Health score: **{:.0}%**", report.health_score * 100.0);
        println!("Total notes: {}\n", index.len());

        if report.orphan_pages.is_empty()
            && report.broken_links.is_empty()
            && report.contradictions.is_empty()
            && report.stale_claims.is_empty()
            && report.missing_pages.is_empty()
        {
            println!("No issues found.");
            return Ok(());
        }

        if !report.orphan_pages.is_empty() {
            println!(
                "### Orphan Pages ({} notes with no inbound links)",
                report.orphan_pages.len()
            );
            for p in &report.orphan_pages {
                println!("  - {p}");
            }
            println!();
        }

        if !report.broken_links.is_empty() {
            println!("### Broken Links ({})", report.broken_links.len());
            for (source, target) in &report.broken_links {
                println!("  - {source} → [[{target}]]");
            }
            println!();
        }

        if !report.contradictions.is_empty() {
            println!("### Contradictions ({})", report.contradictions.len());
            for c in &report.contradictions {
                println!(
                    "  - **{}** vs **{}** (confidence: {:.0}%)",
                    c.note_a,
                    c.note_b,
                    c.confidence * 100.0
                );
                println!("    A: {}", c.claim_a);
                println!("    B: {}", c.claim_b);
            }
            println!();
        }

        if !report.stale_claims.is_empty() {
            println!("### Stale Claims ({})", report.stale_claims.len());
            for s in &report.stale_claims {
                println!("  - {s}");
            }
            println!();
        }

        if !report.missing_pages.is_empty() {
            println!(
                "### Missing Pages ({} referenced but not found)",
                report.missing_pages.len()
            );
            for m in &report.missing_pages {
                println!("  - [[{m}]]");
            }
        }
    }

    Ok(())
}

// ── Index ────────────────────────────────────────────────────────────────

pub fn index(wiki_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let (idx, _store) = build_index_from_dir(wiki_dir)?;
    let catalog = idx.generate_index();
    println!("{catalog}");
    Ok(())
}

// ── Ingest ───────────────────────────────────────────────────────────────

pub fn ingest_file(path: &Path, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    let config = IngestConfig::default();
    let cubes = ingest::ingest_file(path, &config)?;

    if cubes.is_empty() {
        println!("No content extracted from: {}", path.display());
        return Ok(());
    }

    println!("Ingested {} MemCubes from: {}", cubes.len(), path.display());

    if verbose {
        for (i, cube) in cubes.iter().enumerate() {
            let preview: String = cube.content.chars().take(80).collect();
            let preview = preview.replace('\n', " ");
            println!(
                "  {}. [{}] {} (importance: {:.2}, confidence: {:.2})",
                i + 1,
                format!("{:?}", cube.tier).to_lowercase(),
                preview,
                cube.importance,
                cube.confidence,
            );
        }
    }

    Ok(())
}

// ── Wake-up ──────────────────────────────────────────────────────────────

pub fn wakeup(wiki_dir: &Path, token_budget: usize) -> Result<(), Box<dyn std::error::Error>> {
    let (index, _store) = build_index_from_dir(wiki_dir)?;

    // Assemble L0: identity from the index itself
    let total_notes = index.len();
    println!("## L0: Knowledge Substrate\n");
    println!(
        "Wiki: {} notes indexed from {}\n",
        total_notes,
        wiki_dir.display()
    );

    // Assemble L1: top notes by frontmatter score
    println!("## L1: Top Entities\n");

    let mut scored_notes: Vec<(&str, &str, i64)> = Vec::new();
    for note in index.notes().values() {
        let score = note
            .frontmatter
            .get("scoring")
            .and_then(|s| s.get("raw_score"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let title = note
            .frontmatter
            .get("title")
            .and_then(|v| v.as_str())
            .or_else(|| note.frontmatter.get("core_claim").and_then(|v| v.as_str()))
            .unwrap_or(&note.name);
        scored_notes.push((&note.name, title, score));
    }

    scored_notes.sort_by_key(|t| std::cmp::Reverse(t.2));

    let mut tokens_used = 50; // L0 overhead
    for (name, title, score) in &scored_notes {
        let line = format!("- {name} | {title} | score: {score}");
        let est = line.len() / 4;
        if tokens_used + est > token_budget {
            break;
        }
        println!("{line}");
        tokens_used += est;
    }

    // Navigation pointer
    println!("\n## Navigation\n");
    println!(
        "Run `lago wiki index --wiki-dir {}` for full catalog",
        wiki_dir.display()
    );
    println!(
        "Run `lago wiki search --wiki-dir {} <query>` to find specific topics",
        wiki_dir.display()
    );

    Ok(())
}
