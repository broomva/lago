use lago_core::id::{BranchId, SeqNo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Metadata about a single branch in the versioned filesystem.
///
/// Branches are copy-on-write at the event level: the fork point records
/// which sequence number the branch was forked from, and events are
/// replayed to reconstruct the branch state without duplicating the manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchInfo {
    pub branch_id: BranchId,
    pub name: String,
    pub fork_point_seq: SeqNo,
    pub head_seq: SeqNo,
    pub parent_branch: Option<BranchId>,
}

/// Manages the set of known branches.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BranchManager {
    branches: HashMap<BranchId, BranchInfo>,
}

impl BranchManager {
    /// Create a new empty branch manager.
    pub fn new() -> Self {
        Self {
            branches: HashMap::new(),
        }
    }

    /// Create a new branch forked at the given sequence number.
    ///
    /// Returns the newly generated `BranchId`.
    pub fn create_branch(
        &mut self,
        name: String,
        fork_point_seq: SeqNo,
        parent_branch: Option<BranchId>,
    ) -> BranchId {
        let branch_id = BranchId::new();
        let info = BranchInfo {
            branch_id: branch_id.clone(),
            name,
            fork_point_seq,
            head_seq: fork_point_seq,
            parent_branch,
        };
        self.branches.insert(branch_id.clone(), info);
        branch_id
    }

    /// Create a branch with an explicit ID (used when replaying events
    /// that already carry a `BranchId`).
    pub fn create_branch_with_id(
        &mut self,
        branch_id: BranchId,
        name: String,
        fork_point_seq: SeqNo,
        parent_branch: Option<BranchId>,
    ) {
        let info = BranchInfo {
            branch_id: branch_id.clone(),
            name,
            fork_point_seq,
            head_seq: fork_point_seq,
            parent_branch,
        };
        self.branches.insert(branch_id, info);
    }

    /// Look up a branch by ID.
    pub fn get_branch(&self, id: &BranchId) -> Option<&BranchInfo> {
        self.branches.get(id)
    }

    /// Return a mutable reference to a branch (for updating head_seq).
    pub fn get_branch_mut(&mut self, id: &BranchId) -> Option<&mut BranchInfo> {
        self.branches.get_mut(id)
    }

    /// List all known branches.
    pub fn list_branches(&self) -> Vec<&BranchInfo> {
        self.branches.values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_get_branch() {
        let mut bm = BranchManager::new();
        let id = bm.create_branch("main".to_string(), 0, None);
        let info = bm.get_branch(&id).unwrap();
        assert_eq!(info.name, "main");
        assert_eq!(info.fork_point_seq, 0);
        assert_eq!(info.head_seq, 0);
        assert!(info.parent_branch.is_none());
    }

    #[test]
    fn create_child_branch() {
        let mut bm = BranchManager::new();
        let parent = bm.create_branch("main".to_string(), 0, None);
        let child = bm.create_branch("feature".to_string(), 10, Some(parent.clone()));
        let info = bm.get_branch(&child).unwrap();
        assert_eq!(info.name, "feature");
        assert_eq!(info.fork_point_seq, 10);
        assert_eq!(
            info.parent_branch.as_ref().unwrap().as_str(),
            parent.as_str()
        );
    }

    #[test]
    fn list_branches() {
        let mut bm = BranchManager::new();
        bm.create_branch("main".to_string(), 0, None);
        bm.create_branch("dev".to_string(), 5, None);
        assert_eq!(bm.list_branches().len(), 2);
    }

    #[test]
    fn create_branch_with_explicit_id() {
        let mut bm = BranchManager::new();
        let id = BranchId::from_string("my-branch-id");
        bm.create_branch_with_id(id.clone(), "explicit".to_string(), 0, None);
        let info = bm.get_branch(&id).unwrap();
        assert_eq!(info.name, "explicit");
    }
}
