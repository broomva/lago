use thiserror::Error;

#[derive(Debug, Error)]
pub enum LagoError {
    #[error("journal error: {0}")]
    Journal(String),

    #[error("store error: {0}")]
    Store(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("session not found: {0}")]
    SessionNotFound(String),

    #[error("branch not found: {0}")]
    BranchNotFound(String),

    #[error("event not found: {0}")]
    EventNotFound(String),

    #[error("blob not found: {0}")]
    BlobNotFound(String),

    #[error("file not found: {0}")]
    FileNotFound(String),

    #[error("sequence conflict: expected {expected}, got {actual}")]
    SequenceConflict { expected: u64, actual: u64 },

    #[error("policy denied: {0}")]
    PolicyDenied(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("hashline error: {0}")]
    HashLine(#[from] crate::hashline::HashLineError),

    #[error("sandbox error: {0}")]
    Sandbox(String),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type LagoResult<T> = Result<T, LagoError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_journal() {
        let e = LagoError::Journal("disk full".into());
        assert_eq!(e.to_string(), "journal error: disk full");
    }

    #[test]
    fn error_display_store() {
        let e = LagoError::Store("corrupt blob".into());
        assert_eq!(e.to_string(), "store error: corrupt blob");
    }

    #[test]
    fn error_display_not_found_variants() {
        assert_eq!(
            LagoError::SessionNotFound("S1".into()).to_string(),
            "session not found: S1"
        );
        assert_eq!(
            LagoError::BranchNotFound("B1".into()).to_string(),
            "branch not found: B1"
        );
        assert_eq!(
            LagoError::EventNotFound("E1".into()).to_string(),
            "event not found: E1"
        );
        assert_eq!(
            LagoError::BlobNotFound("H1".into()).to_string(),
            "blob not found: H1"
        );
        assert_eq!(
            LagoError::FileNotFound("/foo".into()).to_string(),
            "file not found: /foo"
        );
    }

    #[test]
    fn error_display_sequence_conflict() {
        let e = LagoError::SequenceConflict {
            expected: 10,
            actual: 5,
        };
        assert_eq!(e.to_string(), "sequence conflict: expected 10, got 5");
    }

    #[test]
    fn error_display_policy_denied() {
        let e = LagoError::PolicyDenied("blocked by rule X".into());
        assert_eq!(e.to_string(), "policy denied: blocked by rule X");
    }

    #[test]
    fn error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let e: LagoError = io_err.into();
        assert!(e.to_string().contains("io error"));
    }

    #[test]
    fn error_from_serde_json() {
        let bad_json: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        let e: LagoError = bad_json.unwrap_err().into();
        assert!(e.to_string().contains("serialization error"));
    }

    #[test]
    fn error_from_hashline() {
        let hl_err = crate::hashline::HashLineError::LineOutOfBounds {
            line_num: 10,
            total_lines: 5,
        };
        let e: LagoError = hl_err.into();
        assert!(e.to_string().contains("hashline error"));
        assert!(e.to_string().contains("line 10 out of bounds"));
    }

    #[test]
    fn error_display_sandbox() {
        let e = LagoError::Sandbox("container failed".into());
        assert_eq!(e.to_string(), "sandbox error: container failed");
    }
}
