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

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::jwt::JwtError;

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
