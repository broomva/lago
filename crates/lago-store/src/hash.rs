use lago_core::BlobHash;
use sha2::{Digest, Sha256};

/// Compute SHA-256 hex digest of the given bytes.
pub fn hash_bytes(data: &[u8]) -> BlobHash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    BlobHash::from_hex(hex::encode(result))
}

/// Verify that the SHA-256 digest of `data` matches `expected`.
pub fn verify_hash(data: &[u8], expected: &BlobHash) -> bool {
    let actual = hash_bytes(data);
    actual == *expected
}

// ---
// hex encoding helper — we use sha2's output directly

mod hex {
    /// Encode bytes as lowercase hex string.
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_empty_bytes() {
        let hash = hash_bytes(b"");
        // SHA-256 of empty input is a well-known constant
        assert_eq!(
            hash.as_str(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hash_hello_world() {
        let hash = hash_bytes(b"hello world");
        assert_eq!(
            hash.as_str(),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn verify_matching_hash() {
        let data = b"test data";
        let hash = hash_bytes(data);
        assert!(verify_hash(data, &hash));
    }

    #[test]
    fn verify_mismatched_hash() {
        let data = b"test data";
        let wrong =
            BlobHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000");
        assert!(!verify_hash(data, &wrong));
    }
}
