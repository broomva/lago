use std::io::Write;
use std::path::Path;

use lago_core::{BranchId, EventQuery, Journal, Projection, SessionId};
use lago_fs::ManifestProjection;
use lago_store::BlobStore;

use crate::db::open_journal;

/// Options for the `lago cat` command.
#[derive(Debug, Clone)]
pub struct CatOptions {
    pub path: String,
    pub session_id: String,
    pub branch: String,
}

/// Execute the `lago cat` command.
///
/// Reconstructs the manifest by replaying events for the given session and
/// branch, looks up the file's blob hash, retrieves the blob from the store,
/// and writes its content to stdout.
pub async fn run(data_dir: &Path, opts: CatOptions) -> Result<(), Box<dyn std::error::Error>> {
    let journal = open_journal(data_dir)?;
    let blob_store = BlobStore::open(data_dir.join("blobs"))?;

    let session_id = SessionId::from_string(&opts.session_id);
    let branch_id = BranchId::from_string(&opts.branch);

    // Read all events for this session+branch to reconstruct the manifest
    let query = EventQuery::new().session(session_id).branch(branch_id);
    let events = journal.read(query).await?;

    let mut projection = ManifestProjection::new();
    for event in &events {
        projection.on_event(event)?;
    }

    // Look up the file in the manifest
    let entry = projection
        .manifest()
        .get(&opts.path)
        .ok_or_else(|| format!("file not found in manifest: {}", opts.path))?;

    // Retrieve the blob content
    let data = blob_store.get(&entry.blob_hash)?;

    // Write to stdout
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    handle.write_all(&data)?;
    handle.flush()?;

    Ok(())
}
