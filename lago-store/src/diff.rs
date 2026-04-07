//! Manifest diffing — compare two filesystem manifests to find added,
//! removed, and modified entries.

use std::collections::HashMap;

use lago_core::ManifestEntry;

/// Result of comparing two manifests.
#[derive(Debug, Clone)]
pub struct ManifestDiff {
    /// Entries present in the new manifest but not in the old.
    pub added: Vec<ManifestEntry>,
    /// Entries present in the old manifest but not in the new.
    pub removed: Vec<ManifestEntry>,
    /// Entries present in both but with different blob hashes: `(old, new)`.
    pub modified: Vec<(ManifestEntry, ManifestEntry)>,
}

impl ManifestDiff {
    /// Whether the diff is empty (manifests are identical).
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }

    /// Total number of changed entries.
    pub fn len(&self) -> usize {
        self.added.len() + self.removed.len() + self.modified.len()
    }
}

/// Compare two manifests by path and blob hash.
///
/// - **Added**: path exists in `new` but not in `old`.
/// - **Removed**: path exists in `old` but not in `new`.
/// - **Modified**: path exists in both but the blob hash differs.
pub fn diff_manifests(old: &[ManifestEntry], new: &[ManifestEntry]) -> ManifestDiff {
    let old_map: HashMap<&str, &ManifestEntry> = old.iter().map(|e| (e.path.as_str(), e)).collect();
    let new_map: HashMap<&str, &ManifestEntry> = new.iter().map(|e| (e.path.as_str(), e)).collect();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut modified = Vec::new();

    // Find added and modified
    for (path, new_entry) in &new_map {
        match old_map.get(path) {
            None => added.push((*new_entry).clone()),
            Some(old_entry) => {
                if old_entry.blob_hash != new_entry.blob_hash {
                    modified.push(((*old_entry).clone(), (*new_entry).clone()));
                }
            }
        }
    }

    // Find removed
    for (path, old_entry) in &old_map {
        if !new_map.contains_key(path) {
            removed.push((*old_entry).clone());
        }
    }

    // Sort for deterministic output
    added.sort_by(|a, b| a.path.cmp(&b.path));
    removed.sort_by(|a, b| a.path.cmp(&b.path));
    modified.sort_by(|a, b| a.0.path.cmp(&b.0.path));

    ManifestDiff {
        added,
        removed,
        modified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lago_core::{BlobHash, ManifestEntry};

    fn entry(path: &str, hash: &str) -> ManifestEntry {
        ManifestEntry {
            path: path.to_string(),
            blob_hash: BlobHash::from_hex(hash),
            size_bytes: 100,
            content_type: Some("text/plain".to_string()),
            updated_at: 0,
        }
    }

    #[test]
    fn identical_manifests_empty_diff() {
        let old = vec![entry("/a.md", "aabb"), entry("/b.md", "ccdd")];
        let new = old.clone();
        let diff = diff_manifests(&old, &new);
        assert!(diff.is_empty());
        assert_eq!(diff.len(), 0);
    }

    #[test]
    fn added_file() {
        let old = vec![entry("/a.md", "aabb")];
        let new = vec![entry("/a.md", "aabb"), entry("/b.md", "ccdd")];
        let diff = diff_manifests(&old, &new);
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].path, "/b.md");
        assert!(diff.removed.is_empty());
        assert!(diff.modified.is_empty());
    }

    #[test]
    fn removed_file() {
        let old = vec![entry("/a.md", "aabb"), entry("/b.md", "ccdd")];
        let new = vec![entry("/a.md", "aabb")];
        let diff = diff_manifests(&old, &new);
        assert!(diff.added.is_empty());
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.removed[0].path, "/b.md");
        assert!(diff.modified.is_empty());
    }

    #[test]
    fn modified_file() {
        let old = vec![entry("/a.md", "aabb")];
        let new = vec![entry("/a.md", "eeff")];
        let diff = diff_manifests(&old, &new);
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert_eq!(diff.modified.len(), 1);
        assert_eq!(diff.modified[0].0.path, "/a.md");
        assert_eq!(diff.modified[0].0.blob_hash, BlobHash::from_hex("aabb"));
        assert_eq!(diff.modified[0].1.blob_hash, BlobHash::from_hex("eeff"));
    }

    #[test]
    fn mixed_changes() {
        let old = vec![
            entry("/keep.md", "1111"),
            entry("/modify.md", "2222"),
            entry("/remove.md", "3333"),
        ];
        let new = vec![
            entry("/keep.md", "1111"),
            entry("/modify.md", "4444"),
            entry("/add.md", "5555"),
        ];
        let diff = diff_manifests(&old, &new);
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].path, "/add.md");
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.removed[0].path, "/remove.md");
        assert_eq!(diff.modified.len(), 1);
        assert_eq!(diff.modified[0].0.path, "/modify.md");
    }

    #[test]
    fn empty_manifests() {
        let diff = diff_manifests(&[], &[]);
        assert!(diff.is_empty());
    }

    #[test]
    fn all_new() {
        let old: Vec<ManifestEntry> = Vec::new();
        let new = vec![entry("/a.md", "1111"), entry("/b.md", "2222")];
        let diff = diff_manifests(&old, &new);
        assert_eq!(diff.added.len(), 2);
        assert!(diff.removed.is_empty());
        assert!(diff.modified.is_empty());
    }

    #[test]
    fn all_removed() {
        let old = vec![entry("/a.md", "1111"), entry("/b.md", "2222")];
        let new: Vec<ManifestEntry> = Vec::new();
        let diff = diff_manifests(&old, &new);
        assert!(diff.added.is_empty());
        assert_eq!(diff.removed.len(), 2);
        assert!(diff.modified.is_empty());
    }

    #[test]
    fn diff_len() {
        let old = vec![entry("/a.md", "1111"), entry("/b.md", "2222")];
        let new = vec![entry("/a.md", "3333"), entry("/c.md", "4444")];
        let diff = diff_manifests(&old, &new);
        // 1 modified (a.md), 1 removed (b.md), 1 added (c.md)
        assert_eq!(diff.len(), 3);
    }
}
