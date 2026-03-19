//! JWT token validation using a shared secret.
//!
//! broomva.tech signs tokens with `AUTH_SECRET`; lagod validates them
//! using the same secret via `LAGO_JWT_SECRET`.

use jsonwebtoken::{DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// JWT claims signed by broomva.tech.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroomvaClaims {
    /// User ID (subject).
    pub sub: String,
    /// User email.
    pub email: String,
    /// Expiry (unix timestamp).
    pub exp: u64,
    /// Issued at (unix timestamp).
    pub iat: u64,
}

/// JWT validation errors.
#[derive(Debug, Error)]
pub enum JwtError {
    #[error("missing bearer token")]
    MissingToken,
    #[error("invalid token: {0}")]
    Invalid(String),
    #[error("token expired")]
    Expired,
}

/// Validate a JWT token string against the shared secret.
///
/// Returns the decoded claims on success.
pub fn validate_jwt(token: &str, secret: &str) -> Result<BroomvaClaims, JwtError> {
    let key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_exp = true;
    // Don't require specific audience/issuer — broomva.tech may not set them
    validation.required_spec_claims.clear();
    validation.required_spec_claims.insert("exp".to_string());
    validation.required_spec_claims.insert("sub".to_string());

    let token_data =
        decode::<BroomvaClaims>(token, &key, &validation).map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtError::Expired,
            _ => JwtError::Invalid(e.to_string()),
        })?;

    Ok(token_data.claims)
}

/// Extract a bearer token from an Authorization header value.
pub fn extract_bearer_token(header_value: &str) -> Result<&str, JwtError> {
    header_value
        .strip_prefix("Bearer ")
        .or_else(|| header_value.strip_prefix("bearer "))
        .ok_or(JwtError::MissingToken)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};

    fn make_token(claims: &BroomvaClaims, secret: &str) -> String {
        let key = EncodingKey::from_secret(secret.as_bytes());
        encode(&Header::default(), claims, &key).unwrap()
    }

    fn valid_claims() -> BroomvaClaims {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        BroomvaClaims {
            sub: "user_123".to_string(),
            email: "test@broomva.tech".to_string(),
            exp: now + 3600, // 1 hour from now
            iat: now,
        }
    }

    #[test]
    fn valid_token() {
        let secret = "test-secret";
        let claims = valid_claims();
        let token = make_token(&claims, secret);

        let decoded = validate_jwt(&token, secret).unwrap();
        assert_eq!(decoded.sub, "user_123");
        assert_eq!(decoded.email, "test@broomva.tech");
    }

    #[test]
    fn wrong_secret() {
        let claims = valid_claims();
        let token = make_token(&claims, "real-secret");

        let result = validate_jwt(&token, "wrong-secret");
        assert!(matches!(result, Err(JwtError::Invalid(_))));
    }

    #[test]
    fn expired_token() {
        let secret = "test-secret";
        let mut claims = valid_claims();
        claims.exp = 1000; // long past
        claims.iat = 900;
        let token = make_token(&claims, secret);

        let result = validate_jwt(&token, secret);
        assert!(matches!(result, Err(JwtError::Expired)));
    }

    #[test]
    fn extract_bearer() {
        assert_eq!(extract_bearer_token("Bearer abc123").unwrap(), "abc123");
        assert_eq!(extract_bearer_token("bearer abc123").unwrap(), "abc123");
        assert!(extract_bearer_token("Basic abc123").is_err());
    }
}
