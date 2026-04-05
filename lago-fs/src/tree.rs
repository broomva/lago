use lago_core::ManifestEntry;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::manifest::Manifest;

/// An entry returned when listing a directory's immediate children.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TreeEntry {
    /// A file entry with its name and manifest data.
    File { name: String, entry: ManifestEntry },
    /// A subdirectory identified by name.
    Directory { name: String },
}

/// List the immediate children (files and subdirectories) of the given directory path.
///
/// The `path` should be a directory prefix such as `"/"` or `"/src"`.
/// Trailing slashes are normalized. The function inspects all manifest entries
/// under the prefix and groups them into files (exact depth + 1) and
/// directories (deeper entries collapsed to their first component).
pub fn list_directory(manifest: &Manifest, path: &str) -> Vec<TreeEntry> {
    let prefix = if path.ends_with('/') {
        path.to_string()
    } else {
        format!("{path}/")
    };

    let mut files: Vec<TreeEntry> = Vec::new();
    let mut dirs: BTreeSet<String> = BTreeSet::new();

    for (entry_path, entry) in manifest.entries() {
        // Skip the directory sentinel itself
        if entry_path == path {
            continue;
        }

        let Some(suffix) = entry_path.strip_prefix(&prefix) else {
            continue;
        };

        if suffix.is_empty() {
            continue;
        }

        if let Some(slash_pos) = suffix.find('/') {
            // This entry is in a subdirectory
            let dir_name = &suffix[..slash_pos];
            dirs.insert(dir_name.to_string());
        } else {
            // This entry is an immediate child file
            // Skip directory sentinel entries that happen to match
            if entry
                .content_type
                .as_deref()
                .is_some_and(|ct| ct == "inode/directory")
            {
                dirs.insert(suffix.to_string());
            } else {
                files.push(TreeEntry::File {
                    name: suffix.to_string(),
                    entry: entry.clone(),
                });
            }
        }
    }

    let mut result: Vec<TreeEntry> = dirs
        .into_iter()
        .map(|name| TreeEntry::Directory { name })
        .collect();
    result.append(&mut files);
    result
}

/// Recursively walk all file entries under the given path prefix.
///
/// Returns only actual file entries (not directory sentinels).
pub fn walk<'a>(manifest: &'a Manifest, path: &str) -> Vec<&'a ManifestEntry> {
    let prefix = if path.ends_with('/') {
        path.to_string()
    } else {
        format!("{path}/")
    };

    manifest
        .entries()
        .range(prefix.clone()..)
        .take_while(|(k, _)| k.starts_with(&prefix))
        .filter(|(_, entry)| {
            entry
                .content_type
                .as_deref()
                .is_none_or(|ct| ct != "inode/directory")
        })
        .map(|(_, v)| v)
        .collect()
}

/// Extract all parent directory paths for a given path.
///
/// For example, `"/a/b/c.txt"` yields `["/a", "/a/b"]`.
/// Root `"/"` is not included.
pub fn parent_dirs(path: &str) -> Vec<String> {
    let mut dirs = Vec::new();
    let mut current = String::new();

    // Skip leading slash
    let trimmed = path.strip_prefix('/').unwrap_or(path);

    let parts: Vec<&str> = trimmed.split('/').collect();
    // Iterate all parts except the last (the filename)
    for part in &parts[..parts.len().saturating_sub(1)] {
        current.push('/');
        current.push_str(part);
        dirs.push(current.clone());
    }

    dirs
}

#[cfg(test)]
mod tests {
    use super::*;
    use lago_core::BlobHash;

    fn make_manifest() -> Manifest {
        let mut m = Manifest::new();
        m.apply_write(
            "/src/main.rs".to_string(),
            BlobHash::from_hex("aaa"),
            100,
            Some("text/x-rust".to_string()),
            1,
        );
        m.apply_write(
            "/src/lib.rs".to_string(),
            BlobHash::from_hex("bbb"),
            200,
            Some("text/x-rust".to_string()),
            2,
        );
        m.apply_write(
            "/src/util/helpers.rs".to_string(),
            BlobHash::from_hex("ccc"),
            50,
            Some("text/x-rust".to_string()),
            3,
        );
        m.apply_write(
            "/README.md".to_string(),
            BlobHash::from_hex("ddd"),
            300,
            Some("text/markdown".to_string()),
            4,
        );
        m
    }

    #[test]
    fn list_root_directory() {
        let m = make_manifest();
        let entries = list_directory(&m, "/");
        let names: Vec<String> = entries
            .iter()
            .map(|e| match e {
                TreeEntry::File { name, .. } => name.clone(),
                TreeEntry::Directory { name } => format!("{name}/"),
            })
            .collect();
        assert!(names.contains(&"src/".to_string()));
        assert!(names.contains(&"README.md".to_string()));
    }

    #[test]
    fn list_src_directory() {
        let m = make_manifest();
        let entries = list_directory(&m, "/src");
        let names: Vec<String> = entries
            .iter()
            .map(|e| match e {
                TreeEntry::File { name, .. } => name.clone(),
                TreeEntry::Directory { name } => format!("{name}/"),
            })
            .collect();
        assert!(names.contains(&"main.rs".to_string()));
        assert!(names.contains(&"lib.rs".to_string()));
        assert!(names.contains(&"util/".to_string()));
    }

    #[test]
    fn walk_all_files() {
        let m = make_manifest();
        let files = walk(&m, "/");
        // Should contain main.rs, lib.rs, helpers.rs, README.md
        assert_eq!(files.len(), 4);
    }

    #[test]
    fn walk_subdirectory() {
        let m = make_manifest();
        let files = walk(&m, "/src");
        // main.rs, lib.rs, helpers.rs
        assert_eq!(files.len(), 3);
    }

    #[test]
    fn parent_dirs_deep_path() {
        let dirs = parent_dirs("/a/b/c/d.txt");
        assert_eq!(dirs, vec!["/a", "/a/b", "/a/b/c"]);
    }

    #[test]
    fn parent_dirs_shallow_path() {
        let dirs = parent_dirs("/file.txt");
        assert!(dirs.is_empty());
    }

    #[test]
    fn parent_dirs_two_levels() {
        let dirs = parent_dirs("/src/main.rs");
        assert_eq!(dirs, vec!["/src"]);
    }
}
