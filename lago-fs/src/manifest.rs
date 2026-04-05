use lago_core::{BlobHash, ManifestEntry};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::tree::parent_dirs;

/// A versioned filesystem manifest mapping paths to file entries.
///
/// The manifest is the core data structure of lago-fs. It tracks every file
/// in the virtual filesystem as a `ManifestEntry` keyed by its path string.
/// Parent directories are implicitly created when files are written.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Manifest {
    entries: BTreeMap<String, ManifestEntry>,
}

impl Manifest {
    /// Create a new empty manifest.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Insert or update a file entry. Implicitly creates parent directory
    /// entries (as zero-size sentinel entries) if they do not already exist.
    pub fn apply_write(
        &mut self,
        path: String,
        blob_hash: BlobHash,
        size_bytes: u64,
        content_type: Option<String>,
        timestamp: u64,
    ) {
        // Ensure all parent directories exist as implicit entries
        for dir in parent_dirs(&path) {
            if !self.entries.contains_key(&dir) {
                self.entries.insert(
                    dir.clone(),
                    ManifestEntry {
                        path: dir,
                        blob_hash: BlobHash::from_hex(""),
                        size_bytes: 0,
                        content_type: Some("inode/directory".to_string()),
                        updated_at: timestamp,
                    },
                );
            }
        }

        let entry = ManifestEntry {
            path: path.clone(),
            blob_hash,
            size_bytes,
            content_type,
            updated_at: timestamp,
        };
        self.entries.insert(path, entry);
    }

    /// Remove a file entry from the manifest.
    pub fn apply_delete(&mut self, path: &str) {
        self.entries.remove(path);
    }

    /// Move an entry from `old_path` to `new_path`.
    /// If the old entry does not exist, this is a no-op.
    pub fn apply_rename(&mut self, old_path: &str, new_path: String) {
        if let Some(mut entry) = self.entries.remove(old_path) {
            entry.path = new_path.clone();
            self.entries.insert(new_path, entry);
        }
    }

    /// Look up a single entry by exact path.
    pub fn get(&self, path: &str) -> Option<&ManifestEntry> {
        self.entries.get(path)
    }

    /// List all entries whose path starts with the given prefix.
    pub fn list(&self, prefix: &str) -> Vec<&ManifestEntry> {
        self.entries
            .range(prefix.to_string()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(_, v)| v)
            .collect()
    }

    /// Check whether a path exists in the manifest.
    pub fn exists(&self, path: &str) -> bool {
        self.entries.contains_key(path)
    }

    /// Return a reference to the underlying entries map.
    pub fn entries(&self) -> &BTreeMap<String, ManifestEntry> {
        &self.entries
    }

    /// Return the number of entries in the manifest.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check whether the manifest is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_and_get() {
        let mut m = Manifest::new();
        m.apply_write(
            "/src/main.rs".to_string(),
            BlobHash::from_hex("abc123"),
            1024,
            Some("text/x-rust".to_string()),
            1000,
        );
        let entry = m.get("/src/main.rs").unwrap();
        assert_eq!(entry.blob_hash.as_str(), "abc123");
        assert_eq!(entry.size_bytes, 1024);
    }

    #[test]
    fn write_creates_parent_dirs() {
        let mut m = Manifest::new();
        m.apply_write(
            "/a/b/c.txt".to_string(),
            BlobHash::from_hex("abc"),
            10,
            None,
            1000,
        );
        assert!(m.exists("/a"));
        assert!(m.exists("/a/b"));
        assert!(m.exists("/a/b/c.txt"));
    }

    #[test]
    fn delete_removes_entry() {
        let mut m = Manifest::new();
        m.apply_write(
            "/file.txt".to_string(),
            BlobHash::from_hex("aaa"),
            5,
            None,
            1000,
        );
        assert!(m.exists("/file.txt"));
        m.apply_delete("/file.txt");
        assert!(!m.exists("/file.txt"));
    }

    #[test]
    fn rename_moves_entry() {
        let mut m = Manifest::new();
        m.apply_write(
            "/old.txt".to_string(),
            BlobHash::from_hex("aaa"),
            5,
            None,
            1000,
        );
        m.apply_rename("/old.txt", "/new.txt".to_string());
        assert!(!m.exists("/old.txt"));
        assert!(m.exists("/new.txt"));
        assert_eq!(m.get("/new.txt").unwrap().path, "/new.txt");
    }

    #[test]
    fn list_by_prefix() {
        let mut m = Manifest::new();
        m.apply_write("/src/a.rs".to_string(), BlobHash::from_hex("a"), 1, None, 1);
        m.apply_write("/src/b.rs".to_string(), BlobHash::from_hex("b"), 2, None, 2);
        m.apply_write("/doc/c.md".to_string(), BlobHash::from_hex("c"), 3, None, 3);

        let src_entries = m.list("/src/");
        assert_eq!(src_entries.len(), 2);
    }

    #[test]
    fn empty_manifest() {
        let m = Manifest::new();
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
    }
}
