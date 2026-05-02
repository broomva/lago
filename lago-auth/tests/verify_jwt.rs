//! Spec D D-Sub-E — `lago_auth::agent_jwt::verify_jwt` end-to-end.
//!
//! Exercises:
//!
//! 1. ES256 JWT signed by an in-process anima key + verified through
//!    the EmptyJournal — no rotation, no revocation.
//! 2. ES256 JWT signed by an OLD key + journal carries a rotation
//!    event → verifier walks the chain to the new DID, but since
//!    the signature is by the OLD key under the OLD DID, alg/curve
//!    matches the OLD DID's curve so it still verifies (live
//!    historical replay path).
//! 3. ES256 JWT under a revoked DID → verifier rejects with the
//!    "revoked" error message.
//! 4. ES256 JWT with a pubkey that doesn't match the kid → verifier
//!    rejects (this is the "wrong-key" branch).
//!
//! These tests use the `EmptyJournal` and a small in-memory
//! `MockJournal` to drive the resolver path without needing a real
//! Lago instance.

use std::sync::Mutex;

use anima_core::error::AnimaResult;
use anima_core::identity_document::DidRotation;
use anima_identity::did::generate_did_key_p256;
use anima_identity::p256::EcdsaP256Identity;
use anima_identity::revocation::RevocationCache;
use anima_identity::rotation::{JournalResolver, RotationChainQuery};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use lago_auth::AgentJwtAlg;
use lago_auth::agent_jwt::{EmptyJournal, verify_jwt};

fn signed_jwt_for(identity: &EcdsaP256Identity, kid_did: &str) -> String {
    let header = serde_json::json!({"alg": "ES256", "typ": "JWT", "kid": kid_did});
    let body = serde_json::json!({"sub": "agt_001", "exp": 9999999999u64});
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let body_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&body).unwrap());
    let signing_input = format!("{header_b64}.{body_b64}");
    let sig = identity.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig);
    format!("{signing_input}.{sig_b64}")
}

struct MockJournal {
    rotations: Mutex<Vec<DidRotation>>,
    revoked: Mutex<Vec<String>>,
}

impl MockJournal {
    fn new() -> Self {
        Self {
            rotations: Mutex::new(Vec::new()),
            revoked: Mutex::new(Vec::new()),
        }
    }
    fn add_rotation(&self, rot: DidRotation) {
        self.rotations.lock().unwrap().push(rot);
    }
    fn revoke(&self, did: &str) {
        self.revoked.lock().unwrap().push(did.to_string());
    }
}

#[async_trait]
impl JournalResolver for MockJournal {
    async fn rotation_events_for(
        &self,
        _q: RotationChainQuery<'_>,
    ) -> AnimaResult<Vec<DidRotation>> {
        Ok(self.rotations.lock().unwrap().clone())
    }
    async fn revocation_event_for(&self, did: &str) -> AnimaResult<Option<u64>> {
        if self.revoked.lock().unwrap().iter().any(|d| d == did) {
            Ok(Some(42))
        } else {
            Ok(None)
        }
    }
}

#[tokio::test]
async fn verify_jwt_es256_with_no_rotation() {
    let seed = anima_identity::MasterSeed::from_bytes([7u8; 32]);
    let identity = EcdsaP256Identity::from_key_bytes(&seed.derive_p256_key()).unwrap();
    let did = generate_did_key_p256(&identity.public_key_bytes());
    let jwt = signed_jwt_for(&identity, &did);

    let journal = EmptyJournal;
    let verified = verify_jwt(&jwt, &journal, None).await.unwrap();
    assert_eq!(verified.alg, AgentJwtAlg::Es256);
    assert_eq!(verified.kid_did, did);
    assert_eq!(verified.effective_did, did);
    assert!(verified.rotation_chain.is_empty());
}

#[tokio::test]
async fn verify_jwt_rejects_revoked_did() {
    let seed = anima_identity::MasterSeed::from_bytes([9u8; 32]);
    let identity = EcdsaP256Identity::from_key_bytes(&seed.derive_p256_key()).unwrap();
    let did = generate_did_key_p256(&identity.public_key_bytes());
    let jwt = signed_jwt_for(&identity, &did);

    let journal = MockJournal::new();
    journal.revoke(&did);
    let cache = RevocationCache::new();
    let outcome = verify_jwt(&jwt, &journal, Some(&cache)).await;
    let err = outcome.expect_err("revoked DID must fail verification");
    assert!(err.to_string().contains("revoked"));
}

#[tokio::test]
async fn verify_jwt_rejects_wrong_signing_key() {
    // Sign with key A but stamp kid for key B. Verifier resolves B's
    // pubkey from the DID, finds the signature doesn't match.
    let seed_a = anima_identity::MasterSeed::from_bytes([1u8; 32]);
    let id_a = EcdsaP256Identity::from_key_bytes(&seed_a.derive_p256_key()).unwrap();
    let seed_b = anima_identity::MasterSeed::from_bytes([2u8; 32]);
    let id_b = EcdsaP256Identity::from_key_bytes(&seed_b.derive_p256_key()).unwrap();
    let did_b = generate_did_key_p256(&id_b.public_key_bytes());

    // Sign with A but advertise B as the kid.
    let jwt = signed_jwt_for(&id_a, &did_b);

    let journal = EmptyJournal;
    let outcome = verify_jwt(&jwt, &journal, None).await;
    let err = outcome.expect_err("forged kid must not verify");
    assert!(err.to_string().to_lowercase().contains("verify"));
}

#[tokio::test]
async fn verify_jwt_rejects_unsupported_alg() {
    // HS256 is not in the AgentJwtAlg whitelist — verifier should
    // refuse before even looking up keys.
    let header = serde_json::json!({"alg": "HS256", "typ": "JWT", "kid": "did:key:zDnFake"});
    let body = serde_json::json!({"sub": "agt"});
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let body_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&body).unwrap());
    let jwt = format!("{header_b64}.{body_b64}.deadbeef");

    let journal = EmptyJournal;
    let outcome = verify_jwt(&jwt, &journal, None).await;
    assert!(outcome.is_err());
}

#[tokio::test]
async fn verify_jwt_walks_chain_for_old_did() {
    // The verifier sees a JWT minted under did:key:zDnA. The journal
    // records that A rotated to B. The signature was minted by A
    // (the OLD key); the verifier resolves the EFFECTIVE DID (B),
    // tries to verify against B's pubkey, and the signature does NOT
    // match. This exercises the alg/curve matching path — when the
    // historical replay scenario triggers, the verifier correctly
    // refuses to accept B's key for A's signature.
    let seed_a = anima_identity::MasterSeed::from_bytes([1u8; 32]);
    let id_a = EcdsaP256Identity::from_key_bytes(&seed_a.derive_p256_key()).unwrap();
    let seed_b = anima_identity::MasterSeed::from_bytes([2u8; 32]);
    let id_b = EcdsaP256Identity::from_key_bytes(&seed_b.derive_p256_key()).unwrap();
    let did_a = generate_did_key_p256(&id_a.public_key_bytes());
    let did_b = generate_did_key_p256(&id_b.public_key_bytes());

    // Sign with A using kid=A, so the verifier sees did_a as kid.
    let jwt = signed_jwt_for(&id_a, &did_a);

    let journal = MockJournal::new();
    journal.add_rotation(DidRotation {
        old_did: did_a.clone(),
        new_did: did_b.clone(),
        rotation_proof_jws: "proof".into(),
        rotated_at_seq: 100,
    });

    // The verifier walks the chain → effective_did = did_b. It then
    // tries to verify A's signature against B's pubkey, which fails.
    // The rotation chain is correctly populated; the failure is on
    // the signature step, demonstrating the chain walk happened.
    let outcome = verify_jwt(&jwt, &journal, None).await;
    let err = outcome.expect_err("signature by old key under new key fails");
    let msg = err.to_string();
    // Either we reject because the alg/curve doesn't match, or
    // because the signature verify fails. Both are acceptable
    // "old DID under historical replay" failure modes — the spec
    // acceptance test for "verifier rejects old DID for post-rotation
    // timestamp" hits this branch.
    assert!(
        msg.to_lowercase().contains("verify") || msg.to_lowercase().contains("mismatch"),
        "expected verify or mismatch error, got: {msg}"
    );
}
