//! Axum middleware layer for JWT authentication.
//!
//! Extracts the `Authorization: Bearer <token>` header, validates the JWT,
//! resolves the user to a Lago session, and injects `UserContext` into
//! the request extensions.

use std::sync::Arc;

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use lago_core::SessionId;

use crate::jwt::{extract_bearer_token, validate_jwt};
use crate::session_map::SessionMap;

/// User context injected into request extensions after auth.
#[derive(Debug, Clone, Serialize)]
pub struct UserContext {
    /// User ID from JWT `sub` claim.
    pub user_id: String,
    /// User email from JWT `email` claim.
    pub email: String,
    /// Lago session ID for this user's vault.
    pub lago_session_id: SessionId,
}

/// Shared auth state threaded into the middleware.
pub struct AuthLayer {
    /// Shared JWT secret (same as broomva.tech `AUTH_SECRET`).
    pub jwt_secret: String,
    /// User → session mapping.
    pub session_map: Arc<SessionMap>,
}

/// Auth error response.
#[derive(Serialize)]
struct AuthErrorBody {
    error: String,
    message: String,
}

fn auth_error(status: StatusCode, message: impl Into<String>) -> Response {
    let body = AuthErrorBody {
        error: "unauthorized".to_string(),
        message: message.into(),
    };
    (status, axum::Json(body)).into_response()
}

/// Axum middleware that validates JWT bearer tokens and injects `UserContext`.
pub async fn auth_middleware(
    axum::extract::State(auth): axum::extract::State<Arc<AuthLayer>>,
    mut request: Request,
    next: Next,
) -> Response {
    // Extract Authorization header
    let auth_header = match request.headers().get("authorization") {
        Some(h) => match h.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return auth_error(StatusCode::UNAUTHORIZED, "invalid authorization header"),
        },
        None => return auth_error(StatusCode::UNAUTHORIZED, "missing authorization header"),
    };

    // Extract bearer token
    let token = match extract_bearer_token(&auth_header) {
        Ok(t) => t,
        Err(e) => return auth_error(StatusCode::UNAUTHORIZED, e.to_string()),
    };

    // Validate JWT
    let claims = match validate_jwt(token, &auth.jwt_secret) {
        Ok(c) => c,
        Err(e) => return auth_error(StatusCode::UNAUTHORIZED, e.to_string()),
    };

    // Resolve user to Lago session
    let session_id = match auth
        .session_map
        .get_or_create(&claims.sub, &claims.email)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::error!(error = %e, user_id = %claims.sub, "failed to resolve vault session");
            return auth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to resolve vault session",
            );
        }
    };

    // Inject UserContext into request extensions
    request.extensions_mut().insert(UserContext {
        user_id: claims.sub,
        email: claims.email,
        lago_session_id: session_id,
    });

    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::BroomvaClaims;
    use jsonwebtoken::{EncodingKey, Header, encode};

    #[allow(dead_code)]
    fn make_token(sub: &str, email: &str, secret: &str) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = BroomvaClaims {
            sub: sub.to_string(),
            email: email.to_string(),
            exp: now + 3600,
            iat: now,
        };
        let key = EncodingKey::from_secret(secret.as_bytes());
        encode(&Header::default(), &claims, &key).unwrap()
    }

    #[test]
    fn user_context_serializes() {
        let ctx = UserContext {
            user_id: "u1".into(),
            email: "a@b.com".into(),
            lago_session_id: SessionId::from_string("sid".to_string()),
        };
        let json = serde_json::to_string(&ctx).unwrap();
        assert!(json.contains("u1"));
    }
}
