//! In-memory knowledge index for a Lago session's `.md` vault.
//!
//! Maps note names and paths to parsed `Note` structs and maintains
//! a graph adjacency list derived from wikilinks.

use std::collections::HashMap;
use std::time::Instant;

use lago_core::ManifestEntry;
use lago_store::BlobStore;
use thiserror::Error;

use crate::frontmatter::parse_frontmatter;
use crate::wikilink::extract_wikilinks;

/// Errors specific to the knowledge index.
#[derive(Debug, Error)]
pub enum KnowledgeError {
    #[error("blob not found: {0}")]
    BlobNotFound(String),
    #[error("invalid UTF-8 in blob: {0}")]
    InvalidUtf8(String),
    #[error("store error: {0}")]
    Store(String),
}

/// A parsed `.md` note with structured metadata.
#[derive(Debug, Clone)]
pub struct Note {
    /// Relative path in the manifest (e.g. `/docs/architecture.md`).
    pub path: String,
    /// Filename without `.md` extension.
    pub name: String,
    /// Parsed YAML frontmatter.
    pub frontmatter: serde_yaml::Value,
    /// Markdown body (without frontmatter).
    pub body: String,
    /// Extracted `[[wikilink]]` targets.
    pub links: Vec<String>,
}

/// In-memory knowledge index for a session's vault.
///
/// Built from a Lago manifest + blob store. Provides name/path resolution,
/// scored search, and graph traversal over wikilink edges.
pub struct KnowledgeIndex {
    /// name (lowercase) → relative path
    pub(crate) name_map: HashMap<String, String>,
    /// relative path (lowercase, no .md) → relative path (original case)
    pub(crate) path_map: HashMap<String, String>,
    /// path → parsed Note (cached)
    pub(crate) notes: HashMap<String, Note>,
    /// When this index was built.
    built_at: Instant,
}

impl KnowledgeIndex {
    /// Build an index from a Lago manifest and blob store.
    ///
    /// Reads all `.md` entries, parses frontmatter, extracts wikilinks,
    /// and builds the name/path maps and graph adjacency list.
    pub fn build(manifest: &[ManifestEntry], store: &BlobStore) -> Result<Self, KnowledgeError> {
        let mut name_map = HashMap::new();
        let mut path_map = HashMap::new();
        let mut notes = HashMap::new();

        for entry in manifest {
            if !entry.path.ends_with(".md") {
                continue;
            }

            // Read blob content
            let data = store
                .get(&entry.blob_hash)
                .map_err(|e| KnowledgeError::Store(e.to_string()))?;
            let content = String::from_utf8(data)
                .map_err(|_| KnowledgeError::InvalidUtf8(entry.path.clone()))?;

            // Parse
            let (frontmatter, body) = parse_frontmatter(&content);
            let links = extract_wikilinks(body);

            // Derive name from path: /docs/architecture.md → architecture
            let name = entry
                .path
                .rsplit('/')
                .next()
                .unwrap_or(&entry.path)
                .trim_end_matches(".md")
                .to_string();

            let note = Note {
                path: entry.path.clone(),
                name: name.clone(),
                frontmatter,
                body: body.to_string(),
                links: links.clone(),
            };

            // Name map: first-seen wins
            let name_lower = name.to_lowercase();
            name_map.entry(name_lower).or_insert(entry.path.clone());

            // Path map: strip .md and lowercase for lookup
            let path_key = entry
                .path
                .trim_start_matches('/')
                .trim_end_matches(".md")
                .to_lowercase();
            path_map.entry(path_key).or_insert(entry.path.clone());

            // Cache note
            notes.insert(entry.path.clone(), note);
        }

        Ok(Self {
            name_map,
            path_map,
            notes,
            built_at: Instant::now(),
        })
    }

    /// Resolve a wikilink target to a `Note`.
    ///
    /// Tries name lookup first, then path lookup. Strips heading anchors
    /// (`Note#heading` → `Note`).
    pub fn resolve_wikilink(&self, target: &str) -> Option<&Note> {
        // Strip heading anchors
        let clean = target.split('#').next().unwrap_or(target).trim();
        let lower = clean.to_lowercase();

        // Try name first
        if let Some(path) = self.name_map.get(&lower) {
            return self.notes.get(path);
        }

        // Try path (without .md)
        if let Some(path) = self.path_map.get(&lower) {
            return self.notes.get(path);
        }

        None
    }

    /// Get a note by its exact path.
    pub fn get_note(&self, path: &str) -> Option<&Note> {
        self.notes.get(path)
    }

    /// Get all notes in the index.
    pub fn notes(&self) -> &HashMap<String, Note> {
        &self.notes
    }

    /// Number of notes in the index.
    pub fn len(&self) -> usize {
        self.notes.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.notes.is_empty()
    }

    /// Check if the index is stale based on a TTL.
    pub fn is_stale(&self, ttl: std::time::Duration) -> bool {
        self.built_at.elapsed() > ttl
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_store_with_files(files: &[(&str, &str)]) -> (TempDir, BlobStore, Vec<ManifestEntry>) {
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

        (tmp, store, entries)
    }

    #[test]
    fn build_index_from_manifest() {
        let files = [
            (
                "/notes/hello.md",
                "---\ntitle: Hello\n---\n# Hello\n\nSee [[World]].",
            ),
            ("/notes/world.md", "# World\n\nSee [[Hello]]."),
        ];

        let (_tmp, store, entries) = setup_store_with_files(&files);
        let index = KnowledgeIndex::build(&entries, &store).unwrap();

        assert_eq!(index.len(), 2);

        let hello = index.resolve_wikilink("Hello").unwrap();
        assert_eq!(hello.name, "hello");
        assert_eq!(hello.links, vec!["World"]);
        assert_eq!(hello.frontmatter["title"].as_str(), Some("Hello"));

        let world = index.resolve_wikilink("World").unwrap();
        assert_eq!(world.name, "world");
        assert_eq!(world.links, vec!["Hello"]);
    }

    #[test]
    fn resolve_wikilink_with_heading() {
        let files = [("/note.md", "# Note\n\nContent.")];
        let (_tmp, store, entries) = setup_store_with_files(&files);
        let index = KnowledgeIndex::build(&entries, &store).unwrap();

        let note = index.resolve_wikilink("note#heading").unwrap();
        assert_eq!(note.name, "note");
    }

    #[test]
    fn resolve_missing_wikilink() {
        let files = [("/note.md", "# Note")];
        let (_tmp, store, entries) = setup_store_with_files(&files);
        let index = KnowledgeIndex::build(&entries, &store).unwrap();

        assert!(index.resolve_wikilink("nonexistent").is_none());
    }

    #[test]
    fn skips_non_md_files() {
        let files = [("/data.json", "{\"key\": \"value\"}")];
        let (_tmp, store, entries) = setup_store_with_files(&files);
        let index = KnowledgeIndex::build(&entries, &store).unwrap();

        assert_eq!(index.len(), 0);
    }

    #[test]
    fn stale_check() {
        let files = [("/note.md", "# Note")];
        let (_tmp, store, entries) = setup_store_with_files(&files);
        let index = KnowledgeIndex::build(&entries, &store).unwrap();

        assert!(!index.is_stale(std::time::Duration::from_secs(60)));
        assert!(index.is_stale(std::time::Duration::ZERO));
    }
}
