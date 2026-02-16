use lago_core::event::{EventEnvelope, EventPayload};
use lago_core::{LagoResult, Projection};

use crate::branch::BranchManager;
use crate::manifest::Manifest;

/// A projection that builds a filesystem manifest and branch state from an event stream.
///
/// `ManifestProjection` implements `lago_core::Projection` and processes
/// file-operation and branch-lifecycle events to maintain an up-to-date
/// in-memory manifest and branch manager.
#[derive(Debug, Clone, Default)]
pub struct ManifestProjection {
    manifest: Manifest,
    branch_manager: BranchManager,
}

impl ManifestProjection {
    /// Create a new empty projection.
    pub fn new() -> Self {
        Self {
            manifest: Manifest::new(),
            branch_manager: BranchManager::new(),
        }
    }

    /// Access the current manifest snapshot.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Access the current branch manager.
    pub fn branch_manager(&self) -> &BranchManager {
        &self.branch_manager
    }
}

impl Projection for ManifestProjection {
    fn on_event(&mut self, event: &EventEnvelope) -> LagoResult<()> {
        match &event.payload {
            // --- File operations
            EventPayload::FileWrite {
                path,
                blob_hash,
                size_bytes,
                content_type,
            } => {
                // Convert aios_protocol::BlobHash -> lago_core::BlobHash
                self.manifest.apply_write(
                    path.clone(),
                    lago_core::BlobHash::from_hex(blob_hash.as_str()),
                    *size_bytes,
                    content_type.clone(),
                    event.timestamp,
                );
            }

            EventPayload::FileDelete { path } => {
                self.manifest.apply_delete(path);
            }

            EventPayload::FileRename { old_path, new_path } => {
                self.manifest.apply_rename(old_path, new_path.clone());
            }

            // --- Branch lifecycle
            EventPayload::BranchCreated {
                new_branch_id,
                fork_point_seq,
                name,
            } => {
                // Convert aios_protocol::BranchId -> lago_core::BranchId
                self.branch_manager.create_branch_with_id(
                    lago_core::BranchId::from_string(new_branch_id.as_str()),
                    name.clone(),
                    *fork_point_seq,
                    Some(event.branch_id.clone()),
                );
            }

            EventPayload::BranchMerged {
                source_branch_id,
                merge_seq,
            } => {
                // Convert aios_protocol::BranchId -> lago_core::BranchId
                let lago_branch_id = lago_core::BranchId::from_string(source_branch_id.as_str());
                if let Some(branch) = self.branch_manager.get_branch_mut(&lago_branch_id) {
                    branch.head_seq = *merge_seq;
                }
            }

            // All other event types are not relevant to the filesystem projection
            _ => {}
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "manifest_projection"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lago_core::id::*;

    fn make_envelope(seq: SeqNo, payload: EventPayload) -> EventEnvelope {
        EventEnvelope {
            event_id: EventId::new(),
            session_id: SessionId::new(),
            branch_id: BranchId::from_string("main"),
            run_id: None,
            seq,
            timestamp: 1000 + seq,
            parent_id: None,
            payload,
            metadata: std::collections::HashMap::new(),
            schema_version: 1,
        }
    }

    #[test]
    fn projection_file_write() {
        let mut proj = ManifestProjection::new();
        let event = make_envelope(
            1,
            EventPayload::FileWrite {
                path: "/src/main.rs".to_string(),
                blob_hash: BlobHash::from_hex("abc123").into(),
                size_bytes: 512,
                content_type: Some("text/x-rust".to_string()),
            },
        );

        proj.on_event(&event).unwrap();

        let entry = proj.manifest().get("/src/main.rs").unwrap();
        assert_eq!(entry.blob_hash.as_str(), "abc123");
        assert_eq!(entry.size_bytes, 512);
    }

    #[test]
    fn projection_file_delete() {
        let mut proj = ManifestProjection::new();

        let write = make_envelope(
            1,
            EventPayload::FileWrite {
                path: "/tmp.txt".to_string(),
                blob_hash: BlobHash::from_hex("aaa").into(),
                size_bytes: 10,
                content_type: None,
            },
        );
        proj.on_event(&write).unwrap();
        assert!(proj.manifest().exists("/tmp.txt"));

        let delete = make_envelope(
            2,
            EventPayload::FileDelete {
                path: "/tmp.txt".to_string(),
            },
        );
        proj.on_event(&delete).unwrap();
        assert!(!proj.manifest().exists("/tmp.txt"));
    }

    #[test]
    fn projection_file_rename() {
        let mut proj = ManifestProjection::new();

        let write = make_envelope(
            1,
            EventPayload::FileWrite {
                path: "/old.txt".to_string(),
                blob_hash: BlobHash::from_hex("aaa").into(),
                size_bytes: 10,
                content_type: None,
            },
        );
        proj.on_event(&write).unwrap();

        let rename = make_envelope(
            2,
            EventPayload::FileRename {
                old_path: "/old.txt".to_string(),
                new_path: "/new.txt".to_string(),
            },
        );
        proj.on_event(&rename).unwrap();

        assert!(!proj.manifest().exists("/old.txt"));
        assert!(proj.manifest().exists("/new.txt"));
    }

    #[test]
    fn projection_branch_created() {
        let mut proj = ManifestProjection::new();
        let branch_id = BranchId::from_string("feature-branch");

        let event = make_envelope(
            5,
            EventPayload::BranchCreated {
                new_branch_id: branch_id.clone().into(),
                fork_point_seq: 5,
                name: "feature".to_string(),
            },
        );
        proj.on_event(&event).unwrap();

        let info = proj.branch_manager().get_branch(&branch_id).unwrap();
        assert_eq!(info.name, "feature");
        assert_eq!(info.fork_point_seq, 5);
    }

    #[test]
    fn projection_branch_merged() {
        let mut proj = ManifestProjection::new();
        let branch_id = BranchId::from_string("feature-branch");

        // First create the branch
        let create = make_envelope(
            1,
            EventPayload::BranchCreated {
                new_branch_id: branch_id.clone().into(),
                fork_point_seq: 1,
                name: "feature".to_string(),
            },
        );
        proj.on_event(&create).unwrap();

        // Then merge it
        let merge = make_envelope(
            10,
            EventPayload::BranchMerged {
                source_branch_id: branch_id.clone().into(),
                merge_seq: 10,
            },
        );
        proj.on_event(&merge).unwrap();

        let info = proj.branch_manager().get_branch(&branch_id).unwrap();
        assert_eq!(info.head_seq, 10);
    }

    #[test]
    fn projection_ignores_unrelated_events() {
        let mut proj = ManifestProjection::new();
        let event = make_envelope(
            1,
            EventPayload::SessionCreated {
                name: "test".to_string(),
                config: serde_json::json!({}),
            },
        );

        // Should not error
        proj.on_event(&event).unwrap();
        assert!(proj.manifest().is_empty());
    }

    #[test]
    fn projection_name() {
        let proj = ManifestProjection::new();
        assert_eq!(proj.name(), "manifest_projection");
    }
}
