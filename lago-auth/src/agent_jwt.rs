//! Spec D L4-D6 — Agent Auth Protocol JWT verification with multi-curve support.
//!
//! The Agent Auth Protocol is the signing layer for events that come from
//! anima-issued identities. Pre-D-Sub-A this was Ed25519 (`alg=EdDSA`);
//! post-D-Sub-A it is P-256 (`alg=ES256`). This module detects the alg
//! from the JWT header and dispatches to the matching verifier.
//!
//! The Ed25519 path is preserved for verifying historical events signed
//! before the cutover. The `rotation_chain` on `AgentIdentityDocument`
//! tells verifiers which historical DIDs are still considered valid.
//!
//! # Threat model
//!
//! - A pwned client can present any header alg. The verifier MUST check
//!   the alg before dispatching, and MUST refuse anything other than
//!   `EdDSA` or `ES256`. Other algorithms (HS256, RS256, none) are
//!   rejected with `JwtError::Invalid`.
//! - The `kid` (header) carries the DID of the signer. The verifier
//!   resolves the DID to extract the public key and confirms that the
//!   resolved curve matches the alg.
//! - Rotation: the caller is responsible for checking the
//!   `AgentIdentityDocument.rotation_chain` against the seq of the event
//!   being verified. This module verifies the signature only.

use std::sync::Arc;

use anima_core::error::AnimaResult;
use anima_core::identity_document::DidRotation;
use anima_identity::did::{AuthAlg, DidResolution, resolve_did_key};
use anima_identity::revocation::RevocationCache;
use anima_identity::rotation::walk_rotation_chain;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::jwt::JwtError;

// Re-export the trait surface so callers don't need an explicit
// anima-identity dep. Spec D D-Sub-E: the journal-resolver
// abstraction lives in anima-identity but lago-auth's verifier path
// is the canonical consumer.
pub use anima_identity::rotation::{JournalResolver, RotationChainQuery};

/// Supported agent-JWT algorithms.
///
/// `#[non_exhaustive]` so future curves (e.g. P-384 / `ES384`) can be added
/// without breaking match exhaustiveness in callers.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum AgentJwtAlg {
    EdDsa,
    Es256,
}

impl AgentJwtAlg {
    /// Parse from the JWT header `alg` string.
    pub fn from_header_str(s: &str) -> Result<Self, JwtError> {
        match s {
            "EdDSA" => Ok(Self::EdDsa),
            "ES256" => Ok(Self::Es256),
            other => Err(JwtError::Invalid(format!(
                "unsupported agent JWT alg '{other}' (expected EdDSA or ES256)"
            ))),
        }
    }

    /// String representation in the JWT header.
    pub fn as_header_str(&self) -> &'static str {
        match self {
            Self::EdDsa => "EdDSA",
            Self::Es256 => "ES256",
        }
    }
}

/// Detect the alg of an Agent Auth Protocol JWT WITHOUT verifying the
/// signature. Used by callers that need to dispatch to the right verifier
/// based on the alg.
///
/// Only the header is parsed; the body and signature are not touched.
/// The header MUST carry a `kid` (DID of signer) for downstream resolution.
pub fn detect_alg(jwt: &str) -> Result<AgentJwtAlg, JwtError> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtError::Invalid(format!(
            "agent JWT must have 3 parts, got {}",
            parts.len()
        )));
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| JwtError::Invalid(format!("base64 decode header: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| JwtError::Invalid(format!("decode header json: {e}")))?;
    let alg_str = header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JwtError::Invalid("agent JWT header missing 'alg'".to_string()))?;
    AgentJwtAlg::from_header_str(alg_str)
}

/// Extract the `kid` (signer DID) from the JWT header.
///
/// Spec D L4-D6 — every agent JWT carries the DID in the header so
/// verifiers can resolve to the public key without an out-of-band lookup.
pub fn extract_kid(jwt: &str) -> Result<String, JwtError> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtError::Invalid(format!(
            "agent JWT must have 3 parts, got {}",
            parts.len()
        )));
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| JwtError::Invalid(format!("base64 decode header: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| JwtError::Invalid(format!("decode header json: {e}")))?;
    header
        .get("kid")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| JwtError::Invalid("agent JWT header missing 'kid' (DID)".to_string()))
}

/// Verified claims body returned by [`verify_jwt`].
///
/// The body is whatever the JWT carried; lago-auth's job is to
/// confirm the signature + rotation chain + revocation status, not to
/// interpret the claims. Callers downcast as needed.
#[derive(Debug, Clone)]
pub struct VerifiedAgentJwt {
    /// Algorithm advertised in the JWT header.
    pub alg: AgentJwtAlg,
    /// `kid` claim — the DID the signature was produced under. May
    /// differ from `effective_did` when the signature was minted by
    /// an old DID still inside the rotation chain.
    pub kid_did: String,
    /// The DID the verifier ultimately resolved the public key from.
    /// Same as `kid_did` when no rotations apply; the head of the
    /// rotation chain otherwise.
    pub effective_did: String,
    /// Rotation chain that was walked to resolve the verifying key.
    /// Empty when the signature was minted by the current DID and no
    /// rotations exist for it.
    pub rotation_chain: Vec<DidRotation>,
    /// Decoded body of the JWT.
    pub claims: serde_json::Value,
}

// Trait surface implemented by lago-auth's production resolver
// (which talks to a real Lago journal) and by the test fixture used
// in `tests/integration_rotation_chain.rs`. Re-exported above next to
// the use statements to avoid duplicate `pub use` lines.

/// Verify a JWT against the public key resolved through the rotation
/// chain.
///
/// Steps (Spec D D-Sub-E):
/// 1. Detect the alg via [`detect_alg`]; reject anything that isn't
///    EdDSA or ES256.
/// 2. Extract the `kid` (DID) via [`extract_kid`].
/// 3. Walk the rotation chain forward from `kid_did` to find the
///    currently authoritative DID.
/// 4. Check whether the effective DID has been revoked (via the
///    revocation cache, falling back to the resolver).
/// 5. Resolve the effective DID's public key through `did:key`
///    multicodec parsing.
/// 6. Verify the signature using the alg-appropriate verifier.
///
/// On success returns [`VerifiedAgentJwt`] with the chain that was
/// walked + the decoded claims. On failure returns the most specific
/// [`JwtError`] variant available (rotation-chain failures and
/// revocation are surfaced as `JwtError::Invalid` with descriptive
/// messages so debug logs say *why* the JWT failed verification).
pub async fn verify_jwt(
    jwt: &str,
    journal: &dyn JournalResolver,
    revocation_cache: Option<&RevocationCache>,
) -> Result<VerifiedAgentJwt, JwtError> {
    // 1. Alg detection.
    let alg = detect_alg(jwt)?;
    // 2. Kid extraction.
    let kid_did = extract_kid(jwt)?;
    // 3. Rotation chain walk.
    let rotation_chain = walk_rotation_chain(&kid_did, journal)
        .await
        .map_err(|e| JwtError::Invalid(format!("rotation walk for {kid_did}: {e}")))?;
    let effective_did = rotation_chain
        .last()
        .map(|r| r.new_did.clone())
        .unwrap_or_else(|| kid_did.clone());
    // 4. Revocation check.
    let is_revoked = match revocation_cache {
        Some(cache) => cache
            .check(&effective_did, journal)
            .await
            .map_err(|e| JwtError::Invalid(format!("revocation check: {e}")))?,
        None => journal
            .revocation_event_for(&effective_did)
            .await
            .map_err(|e| JwtError::Invalid(format!("revocation lookup: {e}")))?
            .is_some(),
    };
    if is_revoked {
        return Err(JwtError::Invalid(format!(
            "did {effective_did} has been revoked"
        )));
    }
    // 5. Resolve the public key via did:key. We resolve the EFFECTIVE
    //    DID — the head of the rotation chain — because that's the DID
    //    whose key actually signed the payload.
    //
    //    NB: If the kid_did differs from the effective_did, the JWT
    //    header advertises the OLD DID but the signature is by the NEW
    //    key. That's the "verifier sees the old DID, fetches rotation
    //    chain, re-resolves" flow per Spec D L4-D10. Old signatures
    //    minted before the rotation event seq are still valid against
    //    the OLD DID — that path is for replaying historical events,
    //    not for live verification.
    let DidResolution {
        algorithm: did_alg,
        public_key,
    } = resolve_did_key(&effective_did)
        .map_err(|e| JwtError::Invalid(format!("resolve {effective_did}: {e}")))?;
    // Sanity: the alg the JWT advertises must match the curve carried
    // in the resolved DID. Mixing ES256 + Ed25519 is a forged-header
    // smell.
    let alg_matches = matches!(
        (alg, did_alg),
        (AgentJwtAlg::Es256, AuthAlg::P256) | (AgentJwtAlg::EdDsa, AuthAlg::Ed25519)
    );
    if !alg_matches {
        return Err(JwtError::Invalid(format!(
            "alg/curve mismatch: jwt alg={alg:?} did alg={did_alg:?}"
        )));
    }
    // 6. Per-alg signature verification.
    let claims = match alg {
        AgentJwtAlg::Es256 => verify_es256_signature(jwt, &public_key)?,
        AgentJwtAlg::EdDsa => verify_eddsa_signature(jwt, &public_key)?,
    };
    Ok(VerifiedAgentJwt {
        alg,
        kid_did,
        effective_did,
        rotation_chain,
        claims,
    })
}

/// Convenience handle for verifier callers that want to share a
/// resolver + revocation cache across many calls.
#[derive(Clone)]
pub struct AgentJwtVerifier {
    journal: Arc<dyn JournalResolver>,
    revocation_cache: Option<Arc<RevocationCache>>,
}

impl AgentJwtVerifier {
    pub fn new(journal: Arc<dyn JournalResolver>) -> Self {
        Self {
            journal,
            revocation_cache: Some(Arc::new(RevocationCache::new())),
        }
    }

    pub fn without_cache(journal: Arc<dyn JournalResolver>) -> Self {
        Self {
            journal,
            revocation_cache: None,
        }
    }

    pub fn revocation_cache(&self) -> Option<&Arc<RevocationCache>> {
        self.revocation_cache.as_ref()
    }

    pub async fn verify(&self, jwt: &str) -> Result<VerifiedAgentJwt, JwtError> {
        verify_jwt(jwt, self.journal.as_ref(), self.revocation_cache.as_deref()).await
    }
}

fn verify_es256_signature(
    jwt: &str,
    pubkey_sec1_compressed: &[u8],
) -> Result<serde_json::Value, JwtError> {
    let mut parts = jwt.split('.');
    let header_b64 = parts.next().unwrap_or_default();
    let body_b64 = parts.next().unwrap_or_default();
    let sig_b64 = parts.next().unwrap_or_default();
    use p256::PublicKey;
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| JwtError::Invalid(format!("es256 sig base64: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(JwtError::Invalid(format!(
            "es256 sig wrong length: {}",
            sig_bytes.len()
        )));
    }
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| JwtError::Invalid(format!("es256 sig parse: {e}")))?;
    if pubkey_sec1_compressed.len() != 33 {
        return Err(JwtError::Invalid(format!(
            "es256 expected 33-byte SEC1 compressed pubkey, got {}",
            pubkey_sec1_compressed.len()
        )));
    }
    let public_key = PublicKey::from_sec1_bytes(pubkey_sec1_compressed)
        .map_err(|e| JwtError::Invalid(format!("es256 pubkey parse: {e}")))?;
    let verifying_key = VerifyingKey::from(&public_key);
    let signing_input = format!("{header_b64}.{body_b64}");
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|e| JwtError::Invalid(format!("es256 verify: {e}")))?;
    let body_json = URL_SAFE_NO_PAD
        .decode(body_b64)
        .map_err(|e| JwtError::Invalid(format!("body base64: {e}")))?;
    serde_json::from_slice(&body_json).map_err(|e| JwtError::Invalid(format!("body json: {e}")))
}

fn verify_eddsa_signature(jwt: &str, pubkey: &[u8]) -> Result<serde_json::Value, JwtError> {
    let mut parts = jwt.split('.');
    let header_b64 = parts.next().unwrap_or_default();
    let body_b64 = parts.next().unwrap_or_default();
    let sig_b64 = parts.next().unwrap_or_default();
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| JwtError::Invalid(format!("eddsa sig base64: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(JwtError::Invalid(format!(
            "eddsa sig wrong length: {}",
            sig_bytes.len()
        )));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);
    if pubkey.len() != 32 {
        return Err(JwtError::Invalid(format!(
            "eddsa expected 32-byte pubkey, got {}",
            pubkey.len()
        )));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(pubkey);
    let verifying_key = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| JwtError::Invalid(format!("eddsa pubkey parse: {e}")))?;
    let signing_input = format!("{header_b64}.{body_b64}");
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|e| JwtError::Invalid(format!("eddsa verify: {e}")))?;
    let body_json = URL_SAFE_NO_PAD
        .decode(body_b64)
        .map_err(|e| JwtError::Invalid(format!("body base64: {e}")))?;
    serde_json::from_slice(&body_json).map_err(|e| JwtError::Invalid(format!("body json: {e}")))
}

/// Trivial in-memory journal resolver. Tests + lago-auth callers
/// without a real journal use this; production deploys provide a
/// resolver that talks to lago-journal.
///
/// Keeps `Arc<dyn JournalResolver>` callable without forcing every
/// caller to write a custom impl for the empty case.
#[derive(Debug, Default, Clone)]
pub struct EmptyJournal;

#[async_trait]
impl JournalResolver for EmptyJournal {
    async fn rotation_events_for(
        &self,
        _q: anima_identity::rotation::RotationChainQuery<'_>,
    ) -> AnimaResult<Vec<DidRotation>> {
        Ok(Vec::new())
    }

    async fn revocation_event_for(&self, _did: &str) -> AnimaResult<Option<u64>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn encode_jwt(header: &serde_json::Value, body: &serde_json::Value) -> String {
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap());
        let b = URL_SAFE_NO_PAD.encode(serde_json::to_vec(body).unwrap());
        format!("{h}.{b}.deadbeef")
    }

    #[test]
    fn detect_alg_es256() {
        let header = json!({"alg": "ES256", "kid": "did:key:zDnXyz"});
        let body = json!({"sub": "agt_001"});
        let jwt = encode_jwt(&header, &body);
        assert_eq!(detect_alg(&jwt).unwrap(), AgentJwtAlg::Es256);
    }

    #[test]
    fn detect_alg_eddsa_legacy() {
        let header = json!({"alg": "EdDSA", "kid": "did:key:z6MkLegacy"});
        let body = json!({"sub": "agt_001"});
        let jwt = encode_jwt(&header, &body);
        assert_eq!(detect_alg(&jwt).unwrap(), AgentJwtAlg::EdDsa);
    }

    #[test]
    fn detect_alg_rejects_hs256() {
        let header = json!({"alg": "HS256"});
        let body = json!({"sub": "x"});
        let jwt = encode_jwt(&header, &body);
        assert!(detect_alg(&jwt).is_err());
    }

    #[test]
    fn detect_alg_rejects_none() {
        let header = json!({"alg": "none"});
        let body = json!({"sub": "x"});
        let jwt = encode_jwt(&header, &body);
        assert!(detect_alg(&jwt).is_err());
    }

    #[test]
    fn detect_alg_rejects_malformed() {
        assert!(detect_alg("not.a.valid.jwt").is_err());
        assert!(detect_alg("nodots").is_err());
    }

    #[test]
    fn extract_kid_returns_did() {
        let header = json!({"alg": "ES256", "kid": "did:key:zDnSigner"});
        let body = json!({});
        let jwt = encode_jwt(&header, &body);
        assert_eq!(extract_kid(&jwt).unwrap(), "did:key:zDnSigner");
    }

    #[test]
    fn extract_kid_missing_header_field_errors() {
        let header = json!({"alg": "ES256"});
        let body = json!({});
        let jwt = encode_jwt(&header, &body);
        assert!(extract_kid(&jwt).is_err());
    }

    #[test]
    fn alg_round_trip() {
        for alg in [AgentJwtAlg::EdDsa, AgentJwtAlg::Es256] {
            let s = alg.as_header_str();
            assert_eq!(AgentJwtAlg::from_header_str(s).unwrap(), alg);
        }
    }
}
