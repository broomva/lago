//! Per-tenant AES-256-GCM blob encryption.
//!
//! Encrypts blob data before compression/storage and decrypts on retrieval.
//! The SHA-256 content hash is computed on **plaintext** (before encryption)
//! to preserve content-addressed deduplication within a tenant.
//!
//! Wire format: `[12-byte nonce][ciphertext+tag]`
//!
//! Key management is pluggable — the `TenantKeyProvider` trait abstracts
//! over KMS backends (AWS KMS, Vault, local file, etc.).

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::Aead,
};
use lago_core::{LagoError, LagoResult};
use rand::RngCore;
use tracing::debug;

/// AES-256-GCM nonce size (96 bits / 12 bytes).
const NONCE_SIZE: usize = 12;

/// AES-256 key size (256 bits / 32 bytes).
pub const KEY_SIZE: usize = 32;

/// Encrypt plaintext using AES-256-GCM.
///
/// Returns `[nonce (12B) || ciphertext || tag (16B)]`.
pub fn encrypt(plaintext: &[u8], key: &[u8; KEY_SIZE]) -> LagoResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| LagoError::Store(format!("failed to create AES cipher: {e}")))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| LagoError::Store(format!("AES-GCM encryption failed: {e}")))?;

    // Wire format: nonce || ciphertext+tag
    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    debug!(
        plaintext_len = plaintext.len(),
        encrypted_len = output.len(),
        "blob encrypted"
    );

    Ok(output)
}

/// Decrypt data encrypted with [`encrypt`].
///
/// Expects `[nonce (12B) || ciphertext || tag (16B)]`.
pub fn decrypt(encrypted: &[u8], key: &[u8; KEY_SIZE]) -> LagoResult<Vec<u8>> {
    if encrypted.len() < NONCE_SIZE {
        return Err(LagoError::Store(
            "encrypted data too short: missing nonce".to_string(),
        ));
    }

    let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| LagoError::Store(format!("failed to create AES cipher: {e}")))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| LagoError::Store(format!("AES-GCM decryption failed: {e}")))?;

    Ok(plaintext)
}

/// Trait for resolving per-tenant encryption keys.
///
/// Implementations may back this with a KMS, Vault, a local key file,
/// or a redb table of key references.
pub trait TenantKeyProvider: Send + Sync {
    /// Get the current encryption key for a tenant.
    /// Returns `None` if encryption is not enabled for this tenant.
    fn get_key(&self, tenant_id: &str) -> LagoResult<Option<[u8; KEY_SIZE]>>;

    /// Store a new encryption key for a tenant (key rotation).
    fn set_key(&self, tenant_id: &str, key: [u8; KEY_SIZE]) -> LagoResult<()>;
}

/// In-memory key provider for testing and development.
pub struct InMemoryKeyProvider {
    keys: std::sync::RwLock<std::collections::HashMap<String, [u8; KEY_SIZE]>>,
}

impl InMemoryKeyProvider {
    pub fn new() -> Self {
        Self {
            keys: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }
}

impl Default for InMemoryKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl TenantKeyProvider for InMemoryKeyProvider {
    fn get_key(&self, tenant_id: &str) -> LagoResult<Option<[u8; KEY_SIZE]>> {
        let keys = self.keys.read().map_err(|e| {
            LagoError::Store(format!("failed to read key store: {e}"))
        })?;
        Ok(keys.get(tenant_id).copied())
    }

    fn set_key(&self, tenant_id: &str, key: [u8; KEY_SIZE]) -> LagoResult<()> {
        let mut keys = self.keys.write().map_err(|e| {
            LagoError::Store(format!("failed to write key store: {e}"))
        })?;
        keys.insert(tenant_id.to_string(), key);
        Ok(())
    }
}

/// Generate a random AES-256 key.
pub fn generate_key() -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = generate_key();
        let plaintext = b"hello, encrypted lago blobs!";
        let encrypted = encrypt(plaintext, &key).unwrap();

        // Encrypted data should be larger (nonce + tag overhead)
        assert!(encrypted.len() > plaintext.len());

        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = generate_key();
        let key2 = generate_key();
        let plaintext = b"secret data";
        let encrypted = encrypt(plaintext, &key1).unwrap();

        let result = decrypt(&encrypted, &key2);
        assert!(result.is_err());
    }

    #[test]
    fn truncated_data_fails() {
        let key = generate_key();
        let result = decrypt(&[0u8; 5], &key);
        assert!(result.is_err());
    }

    #[test]
    fn empty_plaintext() {
        let key = generate_key();
        let encrypted = encrypt(b"", &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn large_plaintext() {
        let key = generate_key();
        let plaintext: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let encrypted = encrypt(&plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn in_memory_key_provider() {
        let provider = InMemoryKeyProvider::new();

        // No key initially
        assert!(provider.get_key("tenant1").unwrap().is_none());

        // Set and retrieve
        let key = generate_key();
        provider.set_key("tenant1", key).unwrap();
        let retrieved = provider.get_key("tenant1").unwrap().unwrap();
        assert_eq!(retrieved, key);

        // Different tenant has no key
        assert!(provider.get_key("tenant2").unwrap().is_none());
    }

    #[test]
    fn key_rotation() {
        let provider = InMemoryKeyProvider::new();
        let key1 = generate_key();
        let key2 = generate_key();

        provider.set_key("t1", key1).unwrap();
        let plaintext = b"rotatable secret";
        let encrypted_v1 = encrypt(plaintext, &key1).unwrap();

        // Rotate key
        provider.set_key("t1", key2).unwrap();

        // Old ciphertext still decrypts with old key
        let decrypted = decrypt(&encrypted_v1, &key1).unwrap();
        assert_eq!(decrypted, plaintext);

        // New encryption uses new key
        let encrypted_v2 = encrypt(plaintext, &key2).unwrap();
        let decrypted_v2 = decrypt(&encrypted_v2, &key2).unwrap();
        assert_eq!(decrypted_v2, plaintext);

        // Old key cannot decrypt new ciphertext
        assert!(decrypt(&encrypted_v2, &key1).is_err());
    }
}
