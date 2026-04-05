use serde::{Deserialize, Serialize};
use std::fmt;
use ulid::Ulid;

macro_rules! typed_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new() -> Self {
                Self(Ulid::new().to_string())
            }

            pub fn from_string(s: impl Into<String>) -> Self {
                Self(s.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self(s.to_string())
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

typed_id!(EventId);
typed_id!(SessionId);
typed_id!(BranchId);
typed_id!(RunId);
typed_id!(SnapshotId);
typed_id!(ApprovalId);
typed_id!(MemoryId);

/// Content-addressed blob hash (SHA-256 hex)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BlobHash(String);

impl BlobHash {
    pub fn from_hex(hex: impl Into<String>) -> Self {
        Self(hex.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BlobHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for BlobHash {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl AsRef<str> for BlobHash {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Monotonic sequence number within a branch
pub type SeqNo = u64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_id_new_is_unique() {
        let a = EventId::new();
        let b = EventId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn session_id_from_string() {
        let id = SessionId::from_string("test-session");
        assert_eq!(id.as_str(), "test-session");
        assert_eq!(id.to_string(), "test-session");
    }

    #[test]
    fn branch_id_from_str_trait() {
        let id: BranchId = "main".into();
        assert_eq!(id.as_str(), "main");
    }

    #[test]
    fn typed_id_display() {
        let id = RunId::from_string("run-42");
        assert_eq!(format!("{id}"), "run-42");
    }

    #[test]
    fn typed_id_default_generates_ulid() {
        let id = EventId::default();
        // ULIDs are 26 characters in Crockford Base32
        assert_eq!(id.as_str().len(), 26);
    }

    #[test]
    fn typed_id_as_ref_str() {
        let id = SessionId::from_string("hello");
        let s: &str = id.as_ref();
        assert_eq!(s, "hello");
    }

    #[test]
    fn typed_id_from_string_owned() {
        let id = BranchId::from(String::from("dev"));
        assert_eq!(id.as_str(), "dev");
    }

    #[test]
    fn typed_id_serde_roundtrip() {
        let id = EventId::from_string("01HXYZ");
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"01HXYZ\"");
        let back: EventId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn typed_id_hash_equality() {
        use std::collections::HashSet;
        let id = SessionId::from_string("same");
        let id2 = SessionId::from_string("same");
        let mut set = HashSet::new();
        set.insert(id.clone());
        assert!(set.contains(&id2));
    }

    #[test]
    fn blob_hash_from_hex_and_display() {
        let hash = BlobHash::from_hex("abcdef0123456789");
        assert_eq!(hash.as_str(), "abcdef0123456789");
        assert_eq!(format!("{hash}"), "abcdef0123456789");
    }

    #[test]
    fn blob_hash_serde_roundtrip() {
        let hash = BlobHash::from_hex("deadbeef");
        let json = serde_json::to_string(&hash).unwrap();
        assert_eq!(json, "\"deadbeef\"");
        let back: BlobHash = serde_json::from_str(&json).unwrap();
        assert_eq!(hash, back);
    }

    #[test]
    fn blob_hash_from_string_trait() {
        let hash = BlobHash::from(String::from("cafebabe"));
        assert_eq!(hash.as_str(), "cafebabe");
    }

    #[test]
    fn blob_hash_as_ref() {
        let hash = BlobHash::from_hex("abc");
        let s: &str = hash.as_ref();
        assert_eq!(s, "abc");
    }
}
