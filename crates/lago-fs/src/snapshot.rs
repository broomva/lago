use std::fs;
use std::path::Path;
use walkdir::WalkDir;

use crate::manifest::Manifest;
use lago_core::LagoResult;
use lago_store::BlobStore;

/// Builds a new manifest by scanning a physical directory.
///
/// Uses the `previous_manifest` to optimize hashing. If a file's size and
/// last modified time (mtime) match the previous entry, its hash is reused
/// instead of recalculating and re-storing the blob.
pub fn snapshot(
    root: &Path,
    previous_manifest: &Manifest,
    blob_store: &BlobStore,
) -> LagoResult<Manifest> {
    let mut new_manifest = Manifest::new();

    // Prune entire directory trees early so WalkDir never descends into them.
    let walker = WalkDir::new(root).into_iter().filter_entry(|entry| {
        let name = entry.file_name().to_string_lossy();
        !matches!(
            name.as_ref(),
            ".git"
                | ".lago"
                | ".lake"
                | ".arcan"
                | ".target"
                | "target"
                | "node_modules"
                | ".DS_Store"
        )
    });

    for entry in walker.filter_map(Result::ok) {
        let path = entry.path();

        // Ignore symlinks and directories in this pass
        if !path.is_file() {
            continue;
        }

        let rel_path = path.strip_prefix(root).unwrap_or(path);
        let rel_str = rel_path.to_string_lossy().to_string();

        let virtual_path = format!("/{}", rel_str);

        let metadata = fs::metadata(path)?;
        let size = metadata.len();
        let mtime = metadata
            .modified()
            .unwrap_or_else(|_| std::time::SystemTime::now())
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check if we can reuse the previous hash (fast path)
        let mut reused = false;
        if let Some(prev_entry) = previous_manifest.get(&virtual_path) {
            if prev_entry.size_bytes == size && prev_entry.updated_at == mtime {
                // Match: assume content is identical to skip IO + hashing
                new_manifest.apply_write(
                    virtual_path.clone(),
                    prev_entry.blob_hash.clone(),
                    size,
                    prev_entry.content_type.clone(),
                    mtime,
                );
                reused = true;
            }
        }

        if !reused {
            // Slow path: Read file, hash, and store in the blob store
            let data = fs::read(path)?;
            let new_hash = blob_store.put(&data)?;

            new_manifest.apply_write(
                virtual_path,
                // The blob store returns a lego_core::BlobHash
                lago_core::BlobHash::from_hex(new_hash.as_str()),
                size,
                None,
                mtime,
            );
        }
    }

    Ok(new_manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn snapshot_creates_new_manifest() {
        let temp = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::open(temp.path().join("blobs")).unwrap();
        let workspace = temp.path().join("ws");
        fs::create_dir_all(&workspace).unwrap();

        // Write a file to real disk
        let file_path = workspace.join("hello.txt");
        let mut file = fs::File::create(&file_path).unwrap();
        file.write_all(b"world").unwrap();
        file.sync_all().unwrap();

        let prev = Manifest::new();
        let next = snapshot(&workspace, &prev, &blob_store).unwrap();

        assert!(next.exists("/hello.txt"));
        let entry = next.get("/hello.txt").unwrap();
        assert_eq!(entry.size_bytes, 5);
        assert!(blob_store.exists(&entry.blob_hash));
    }

    #[test]
    fn snapshot_reuses_unchanged_files() {
        let temp = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::open(temp.path().join("blobs")).unwrap();
        let workspace = temp.path().join("ws");
        fs::create_dir_all(&workspace).unwrap();

        let file_path = workspace.join("hello.txt");
        fs::write(&file_path, "world").unwrap();

        let prev = snapshot(&workspace, &Manifest::new(), &blob_store).unwrap();

        let prev_entry = prev.get("/hello.txt").unwrap().clone();

        // Take snapshot again without changes
        let next = snapshot(&workspace, &prev, &blob_store).unwrap();
        let next_entry = next.get("/hello.txt").unwrap();

        assert_eq!(prev_entry.blob_hash, next_entry.blob_hash);
        assert_eq!(prev_entry.updated_at, next_entry.updated_at);
    }
}
