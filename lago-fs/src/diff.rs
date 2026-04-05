use lago_core::ManifestEntry;
use serde::{Deserialize, Serialize};

use crate::manifest::Manifest;

/// A single difference between two manifest versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiffEntry {
    /// A path that exists in the new manifest but not the old.
    Added { path: String, entry: ManifestEntry },
    /// A path that exists in the old manifest but not the new.
    Removed { path: String, entry: ManifestEntry },
    /// A path that exists in both manifests but with a different blob_hash.
    Modified {
        path: String,
        old: ManifestEntry,
        new: ManifestEntry,
    },
}

/// Compute the diff between two manifest versions.
///
/// Iterates over both manifests' sorted entries in lockstep (leveraging the
/// BTreeMap ordering) and classifies each path as added, removed, or
/// modified. Modification is detected by comparing `blob_hash` values.
pub fn diff(old: &Manifest, new: &Manifest) -> Vec<DiffEntry> {
    let mut result = Vec::new();

    let old_entries = old.entries();
    let new_entries = new.entries();

    let mut old_iter = old_entries.iter().peekable();
    let mut new_iter = new_entries.iter().peekable();

    loop {
        match (old_iter.peek(), new_iter.peek()) {
            (Some((old_path, _)), Some((new_path, _))) => {
                match old_path.cmp(new_path) {
                    std::cmp::Ordering::Less => {
                        // Path only in old => removed
                        let (path, entry) = old_iter.next().unwrap();
                        result.push(DiffEntry::Removed {
                            path: path.clone(),
                            entry: entry.clone(),
                        });
                    }
                    std::cmp::Ordering::Greater => {
                        // Path only in new => added
                        let (path, entry) = new_iter.next().unwrap();
                        result.push(DiffEntry::Added {
                            path: path.clone(),
                            entry: entry.clone(),
                        });
                    }
                    std::cmp::Ordering::Equal => {
                        // Path in both, check if modified
                        let (path, old_entry) = old_iter.next().unwrap();
                        let (_, new_entry) = new_iter.next().unwrap();
                        if old_entry.blob_hash != new_entry.blob_hash {
                            result.push(DiffEntry::Modified {
                                path: path.clone(),
                                old: old_entry.clone(),
                                new: new_entry.clone(),
                            });
                        }
                    }
                }
            }
            (Some(_), None) => {
                // Remaining old entries were removed
                let (path, entry) = old_iter.next().unwrap();
                result.push(DiffEntry::Removed {
                    path: path.clone(),
                    entry: entry.clone(),
                });
            }
            (None, Some(_)) => {
                // Remaining new entries were added
                let (path, entry) = new_iter.next().unwrap();
                result.push(DiffEntry::Added {
                    path: path.clone(),
                    entry: entry.clone(),
                });
            }
            (None, None) => break,
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use lago_core::BlobHash;

    #[test]
    fn diff_empty_manifests() {
        let old = Manifest::new();
        let new = Manifest::new();
        let d = diff(&old, &new);
        assert!(d.is_empty());
    }

    #[test]
    fn diff_added_files() {
        let old = Manifest::new();
        let mut new = Manifest::new();
        new.apply_write("/a.txt".to_string(), BlobHash::from_hex("aaa"), 10, None, 1);

        let d = diff(&old, &new);
        assert_eq!(d.len(), 1);
        assert!(matches!(&d[0], DiffEntry::Added { path, .. } if path == "/a.txt"));
    }

    #[test]
    fn diff_removed_files() {
        let mut old = Manifest::new();
        old.apply_write("/a.txt".to_string(), BlobHash::from_hex("aaa"), 10, None, 1);
        let new = Manifest::new();

        let d = diff(&old, &new);
        assert_eq!(d.len(), 1);
        assert!(matches!(&d[0], DiffEntry::Removed { path, .. } if path == "/a.txt"));
    }

    #[test]
    fn diff_modified_files() {
        let mut old = Manifest::new();
        old.apply_write("/a.txt".to_string(), BlobHash::from_hex("aaa"), 10, None, 1);
        let mut new = Manifest::new();
        new.apply_write("/a.txt".to_string(), BlobHash::from_hex("bbb"), 20, None, 2);

        let d = diff(&old, &new);
        assert_eq!(d.len(), 1);
        assert!(matches!(&d[0], DiffEntry::Modified { path, .. } if path == "/a.txt"));
    }

    #[test]
    fn diff_unchanged_files_not_reported() {
        let mut old = Manifest::new();
        old.apply_write("/a.txt".to_string(), BlobHash::from_hex("aaa"), 10, None, 1);
        let mut new = Manifest::new();
        new.apply_write("/a.txt".to_string(), BlobHash::from_hex("aaa"), 10, None, 2);

        let d = diff(&old, &new);
        assert!(d.is_empty());
    }

    #[test]
    fn diff_mixed_changes() {
        let mut old = Manifest::new();
        old.apply_write(
            "/keep.txt".to_string(),
            BlobHash::from_hex("aaa"),
            1,
            None,
            1,
        );
        old.apply_write(
            "/modify.txt".to_string(),
            BlobHash::from_hex("bbb"),
            2,
            None,
            1,
        );
        old.apply_write(
            "/remove.txt".to_string(),
            BlobHash::from_hex("ccc"),
            3,
            None,
            1,
        );

        let mut new = Manifest::new();
        new.apply_write(
            "/keep.txt".to_string(),
            BlobHash::from_hex("aaa"),
            1,
            None,
            2,
        );
        new.apply_write(
            "/modify.txt".to_string(),
            BlobHash::from_hex("ddd"),
            4,
            None,
            2,
        );
        new.apply_write(
            "/add.txt".to_string(),
            BlobHash::from_hex("eee"),
            5,
            None,
            2,
        );

        let d = diff(&old, &new);
        // /add.txt added, /modify.txt modified, /remove.txt removed
        assert_eq!(d.len(), 3);

        let added = d
            .iter()
            .filter(|e| matches!(e, DiffEntry::Added { .. }))
            .count();
        let removed = d
            .iter()
            .filter(|e| matches!(e, DiffEntry::Removed { .. }))
            .count();
        let modified = d
            .iter()
            .filter(|e| matches!(e, DiffEntry::Modified { .. }))
            .count();

        assert_eq!(added, 1);
        assert_eq!(removed, 1);
        assert_eq!(modified, 1);
    }
}
