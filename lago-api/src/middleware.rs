//! Axum middleware for policy and RBAC enforcement on HTTP routes.
//!
//! Maps HTTP write operations (PUT, POST, DELETE, PATCH) to synthetic
//! tool names and evaluates them against the `PolicyEngine`. Read
//! operations pass through without policy checks.
//!
//! After policy evaluation, RBAC is enforced based on the session tier
//! derived from the session ID prefix:
//! - `site-assets:` / `site-content:` → **public** (anonymous read-only)
//! - `vault:` → **user** (only the owning user may read/write)
//! - `agent:` → **agent** (only the owning agent may access)
//! - Anything else → **default** (no additional RBAC restriction)

use std::sync::Arc;

use axum::extract::Request;
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use lago_auth::UserContext;
use lago_core::event::PolicyDecisionKind;
use lago_core::policy::PolicyContext;

use crate::state::AppState;

/// JSON body returned for policy denial responses.
#[derive(Serialize)]
struct PolicyDeniedBody {
    error: String,
    message: String,
    rule_id: Option<String>,
}

/// Map an HTTP method + path to a synthetic tool name for policy evaluation.
///
/// Returns `None` for read operations (GET, HEAD, OPTIONS) which bypass policy.
fn request_to_tool_name(method: &Method, path: &str) -> Option<String> {
    // Only evaluate policy for write operations
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return None;
    }

    // Derive tool name from the route pattern
    let action = match *method {
        Method::PUT => "write",
        Method::POST => "create",
        Method::DELETE => "delete",
        Method::PATCH => "patch",
        _ => "unknown",
    };

    // Extract the resource type from the path
    let resource = if path.contains("/blobs/") {
        "blob"
    } else if path.contains("/files/") {
        "file"
    } else if path.contains("/branches") {
        "branch"
    } else if path.contains("/sessions") {
        "session"
    } else if path.contains("/memory/") {
        "memory"
    } else if path.contains("/snapshots") {
        "snapshot"
    } else {
        "http"
    };

    Some(format!("http.{resource}.{action}"))
}

/// Extract a session ID from the request path, if present.
///
/// Matches patterns like `/v1/sessions/{id}/...`.
fn extract_session_id(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    for (i, part) in parts.iter().enumerate() {
        if *part == "sessions"
            && let Some(id) = parts.get(i + 1)
        {
            return id.to_string();
        }
    }
    "anonymous".to_string()
}

/// Access tier derived from the session ID prefix.
///
/// Determines what RBAC rules apply to requests targeting a given session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionTier {
    /// Public content — anonymous users may read, only admins may write.
    Public,
    /// User vault — only the owning user (or admin) may access.
    User,
    /// Agent session — only the owning agent (or admin) may access.
    Agent,
    /// No special tier — falls through to default RBAC/policy rules.
    Default,
}

/// Classify a session ID into an access tier based on its prefix.
///
/// Convention:
/// - `site-assets:*` or `site-content:*` → public (read-only for anonymous)
/// - `vault:*` → user tier (owner-only access)
/// - `agent:*` → agent tier (owner-only access)
/// - Anything else → default (no additional RBAC restriction)
fn map_session_to_tier(session_id: &str) -> SessionTier {
    if session_id.starts_with("site-assets:") || session_id.starts_with("site-content:") {
        SessionTier::Public
    } else if session_id.starts_with("vault:") {
        SessionTier::User
    } else if session_id.starts_with("agent:") {
        SessionTier::Agent
    } else {
        SessionTier::Default
    }
}

/// Resolve a session UUID to its human-readable name by querying the journal.
///
/// Returns `None` if the session doesn't exist or the lookup fails.
/// Falls back gracefully — RBAC will treat unknown sessions as `Default` tier.
async fn resolve_session_name(state: &AppState, session_id: &str) -> Option<String> {
    let sid = lago_core::SessionId::from_string(session_id);
    match state.journal.get_session(&sid).await {
        Ok(Some(session)) => Some(session.config.name),
        _ => None,
    }
}

/// Check whether a user has an admin role according to the RBAC manager.
///
/// Returns `true` if the RBAC manager has an explicit `Permission::Admin`
/// for any role assigned to the given session ID.
///
/// Note: We cannot use `check_permission` for this because it returns
/// `Allow` by default when no roles are assigned. Instead we inspect the
/// role assignments and permissions directly.
async fn has_admin_role(state: &AppState, rbac_session_id: &str) -> bool {
    use lago_policy::Permission;

    let Some(ref rbac) = state.rbac_manager else {
        return false;
    };

    let mgr = rbac.read().await;

    // Look up roles assigned to this session
    let Some(role_names) = mgr.assignments().get(rbac_session_id) else {
        return false;
    };

    // Check if any assigned role has the Admin permission
    for role_name in role_names {
        if let Some(role) = mgr.roles().get(role_name)
            && role
                .permissions
                .iter()
                .any(|p| matches!(p, Permission::Admin))
        {
            return true;
        }
    }

    false
}

/// Evaluate RBAC tier restrictions for the request.
///
/// Returns `None` if the request is allowed, or `Some(Response)` with a 403
/// if the request is denied by RBAC.
///
/// The logic per tier:
/// - **Public**: GET/HEAD allowed for everyone. Writes require admin role.
/// - **User**: The requesting user's lago_session_id must match the target
///   session, or the user must be admin. Anonymous requests are denied.
/// - **Agent**: Same ownership check as User tier, using agent identity.
/// - **Default**: No RBAC restriction (pass through).
async fn check_rbac(
    state: &AppState,
    method: &Method,
    session_id: &str,
    user_ctx: Option<&UserContext>,
) -> Option<Response> {
    // If no RBAC manager is configured, skip enforcement entirely.
    state.rbac_manager.as_ref()?;

    // Resolve session name from journal — the URL path contains the UUID,
    // but tier classification requires the session name (e.g., "site-assets:public").
    let session_name = resolve_session_name(state, session_id).await;
    let tier = map_session_to_tier(session_name.as_deref().unwrap_or(session_id));

    match tier {
        SessionTier::Public => {
            // Read operations are always allowed for public sessions
            if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
                return None;
            }

            // Write operations on public sessions require authentication.
            // Any authenticated user (valid JWT) can manage public content —
            // they possess the server's JWT secret, making them a trusted operator.
            // Anonymous writes are denied.
            match user_ctx {
                Some(_) => None, // Authenticated → allowed
                None => Some(rbac_denied(
                    "write operations on public sessions require authentication",
                )),
            }
        }

        SessionTier::User => {
            let ctx = match user_ctx {
                Some(c) => c,
                None => {
                    return Some(rbac_denied(
                        "authentication required to access user vault sessions",
                    ));
                }
            };

            // Check if the requesting user owns this session.
            // vault:{user_id} must match the user's lago_session_id.
            if ctx.lago_session_id.as_str() == session_id {
                return None;
            }

            // Fall back to admin check
            if has_admin_role(state, ctx.lago_session_id.as_str()).await {
                return None;
            }

            Some(rbac_denied(
                "access denied: you do not own this vault session",
            ))
        }

        SessionTier::Agent => {
            let ctx = match user_ctx {
                Some(c) => c,
                None => {
                    return Some(rbac_denied(
                        "authentication required to access agent sessions",
                    ));
                }
            };

            // Check if the requesting user/agent owns this session
            if ctx.lago_session_id.as_str() == session_id {
                return None;
            }

            // Fall back to admin check
            if has_admin_role(state, ctx.lago_session_id.as_str()).await {
                return None;
            }

            Some(rbac_denied(
                "access denied: you do not own this agent session",
            ))
        }

        SessionTier::Default => {
            // No additional RBAC restriction for default-tier sessions
            None
        }
    }
}

/// Build a 403 Forbidden response for RBAC denials.
fn rbac_denied(message: &str) -> Response {
    let body = PolicyDeniedBody {
        error: "rbac_denied".to_string(),
        message: message.to_string(),
        rule_id: None,
    };
    (StatusCode::FORBIDDEN, axum::Json(body)).into_response()
}

/// Axum middleware that evaluates write operations against the policy engine
/// and enforces RBAC tier restrictions.
///
/// **Policy enforcement** (when `policy_engine` is `Some`): all write
/// operations are evaluated. If the policy denies the operation, a 403
/// response is returned with the denial explanation.
///
/// **RBAC enforcement** (when `rbac_manager` is `Some`): after the policy
/// check passes, the session tier is evaluated. Public sessions allow
/// anonymous reads but require admin for writes. User/agent sessions
/// require ownership or admin role. See [`check_rbac`] for details.
///
/// Read operations bypass policy checks but still undergo RBAC tier checks.
pub async fn policy_middleware(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let session_id = extract_session_id(&path);

    // ── Phase 1: Policy engine check (write operations only) ──────────
    if let Some(ref policy_engine) = state.policy_engine
        && let Some(tool_name) = request_to_tool_name(&method, &path)
    {
        let ctx = PolicyContext {
            tool_name,
            arguments: serde_json::json!({}),
            category: Some("http".to_string()),
            risk: None,
            session_id: session_id.clone(),
            role: None,
            sandbox_tier: None,
        };

        let decision = policy_engine.evaluate(&ctx);

        match decision.decision {
            PolicyDecisionKind::Deny => {
                let body = PolicyDeniedBody {
                    error: "policy_denied".to_string(),
                    message: decision
                        .explanation
                        .unwrap_or_else(|| "operation denied by policy".to_string()),
                    rule_id: decision.rule_id,
                };
                return (StatusCode::FORBIDDEN, axum::Json(body)).into_response();
            }
            PolicyDecisionKind::RequireApproval => {
                let body = PolicyDeniedBody {
                    error: "approval_required".to_string(),
                    message: decision
                        .explanation
                        .unwrap_or_else(|| "operation requires approval".to_string()),
                    rule_id: decision.rule_id,
                };
                return (StatusCode::FORBIDDEN, axum::Json(body)).into_response();
            }
            PolicyDecisionKind::Allow => { /* continue to RBAC check */ }
        }
    }

    // ── Phase 2: RBAC tier enforcement ────────────────────────────────
    // Try to get UserContext from request extensions (injected by auth middleware
    // on /v1/memory/* routes). If not present, attempt to extract directly from
    // the Authorization header — this enables RBAC on non-auth-protected routes
    // (e.g., /v1/sessions/:id/files/*) when a Bearer token is provided.
    let user_ctx = request
        .extensions()
        .get::<UserContext>()
        .cloned()
        .or_else(|| try_extract_user_context(&request, &state));

    if let Some(deny_response) = check_rbac(&state, &method, &session_id, user_ctx.as_ref()).await {
        return deny_response;
    }

    next.run(request).await
}

/// Attempt to extract UserContext from a Bearer token in the Authorization header.
///
/// This enables RBAC enforcement on routes that don't have the auth middleware layer
/// (everything except /v1/memory/*). Returns None if no token or invalid token.
fn try_extract_user_context(request: &Request, state: &AppState) -> Option<UserContext> {
    let auth_layer = state.auth.as_ref()?;
    let auth_header = request.headers().get("authorization")?.to_str().ok()?;
    let token = lago_auth::jwt::extract_bearer_token(auth_header).ok()?;
    let claims = lago_auth::jwt::validate_jwt(token, &auth_layer.jwt_secret).ok()?;

    // Create a synthetic UserContext without resolving the session
    // (session resolution would require async, which we avoid here)
    Some(UserContext {
        user_id: claims.sub,
        email: claims.email,
        lago_session_id: lago_core::SessionId::from_string("authenticated"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_methods_bypass_policy() {
        assert!(request_to_tool_name(&Method::GET, "/v1/blobs/abc").is_none());
        assert!(request_to_tool_name(&Method::HEAD, "/v1/blobs/abc").is_none());
        assert!(request_to_tool_name(&Method::OPTIONS, "/v1/blobs/abc").is_none());
    }

    #[test]
    fn write_methods_get_tool_names() {
        assert_eq!(
            request_to_tool_name(&Method::PUT, "/v1/blobs/abc"),
            Some("http.blob.write".to_string())
        );
        assert_eq!(
            request_to_tool_name(&Method::POST, "/v1/sessions"),
            Some("http.session.create".to_string())
        );
        assert_eq!(
            request_to_tool_name(&Method::DELETE, "/v1/sessions/sid/files/foo.rs"),
            Some("http.file.delete".to_string())
        );
        assert_eq!(
            request_to_tool_name(&Method::PATCH, "/v1/sessions/sid/files/foo.rs"),
            Some("http.file.patch".to_string())
        );
    }

    #[test]
    fn session_id_extracted_from_path() {
        assert_eq!(
            extract_session_id("/v1/sessions/my-session/files/foo.rs"),
            "my-session"
        );
        assert_eq!(extract_session_id("/v1/blobs/abc"), "anonymous");
        assert_eq!(extract_session_id("/v1/sessions/abc123/branches"), "abc123");
    }

    // ── Session tier mapping tests ────────────────────────────────────

    #[test]
    fn tier_public_site_assets() {
        assert_eq!(
            map_session_to_tier("site-assets:images"),
            SessionTier::Public
        );
    }

    #[test]
    fn tier_public_site_content() {
        assert_eq!(
            map_session_to_tier("site-content:blog"),
            SessionTier::Public
        );
    }

    #[test]
    fn tier_user_vault() {
        assert_eq!(map_session_to_tier("vault:user-123"), SessionTier::User);
    }

    #[test]
    fn tier_agent() {
        assert_eq!(map_session_to_tier("agent:arcan-01"), SessionTier::Agent);
    }

    #[test]
    fn tier_default_for_unknown_prefix() {
        assert_eq!(map_session_to_tier("my-session"), SessionTier::Default);
        assert_eq!(map_session_to_tier("anonymous"), SessionTier::Default);
        assert_eq!(map_session_to_tier("dev-branch"), SessionTier::Default);
    }

    #[test]
    fn tier_prefix_must_include_colon() {
        // "vault" without colon should be Default, not User
        assert_eq!(map_session_to_tier("vault"), SessionTier::Default);
        assert_eq!(map_session_to_tier("agent"), SessionTier::Default);
        assert_eq!(map_session_to_tier("site-assets"), SessionTier::Default);
    }

    // ── RBAC check_rbac tests ─────────────────────────────────────────

    use lago_core::SessionId;
    use lago_policy::RbacManager;
    use std::time::Instant;
    use tokio::sync::RwLock;

    /// Build a minimal AppState with an optional RbacManager for testing.
    ///
    /// Uses a unique temp directory per call to avoid redb lock conflicts
    /// when tests run in parallel.
    fn test_state(rbac: Option<RbacManager>) -> (Arc<AppState>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_path_buf();
        let blob_store = Arc::new(lago_store::BlobStore::open(data_dir.join("blobs")).unwrap());
        let journal: Arc<dyn lago_core::Journal> =
            Arc::new(lago_journal::RedbJournal::open(data_dir.join("journal.redb")).unwrap());

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let prometheus_handle = recorder.handle();
        let _ = metrics::set_global_recorder(recorder);

        let state = Arc::new(AppState {
            journal,
            blob_store,
            data_dir,
            started_at: Instant::now(),
            auth: None,
            policy_engine: None,
            rbac_manager: rbac.map(|m| Arc::new(RwLock::new(m))),
            hook_runner: None,
            rate_limiter: None,
            prometheus_handle,
            manifest_cache: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        });
        (state, tmp)
    }

    fn make_user_ctx(session_id: &str) -> UserContext {
        UserContext {
            user_id: "user-1".to_string(),
            email: "test@example.com".to_string(),
            lago_session_id: SessionId::from_string(session_id),
        }
    }

    #[tokio::test]
    async fn rbac_disabled_allows_everything() {
        let (state, _tmp) = test_state(None);
        // Public session write with no user — should be allowed when RBAC is disabled
        let result = check_rbac(&state, &Method::PUT, "site-assets:img", None).await;
        assert!(result.is_none(), "RBAC disabled should allow all requests");
    }

    #[tokio::test]
    async fn rbac_public_allows_get_without_auth() {
        let (state, _tmp) = test_state(Some(RbacManager::new()));
        let result = check_rbac(&state, &Method::GET, "site-assets:img", None).await;
        assert!(result.is_none(), "public GET should be allowed anonymously");
    }

    #[tokio::test]
    async fn rbac_public_allows_head_without_auth() {
        let (state, _tmp) = test_state(Some(RbacManager::new()));
        let result = check_rbac(&state, &Method::HEAD, "site-content:blog", None).await;
        assert!(
            result.is_none(),
            "public HEAD should be allowed anonymously"
        );
    }

    #[tokio::test]
    async fn rbac_public_denies_put_without_auth() {
        let (state, _tmp) = test_state(Some(RbacManager::new()));
        let result = check_rbac(&state, &Method::PUT, "site-assets:img", None).await;
        assert!(result.is_some(), "public PUT without auth should be denied");
    }

    #[tokio::test]
    async fn rbac_public_allows_put_for_authenticated_user() {
        let (state, _tmp) = test_state(Some(RbacManager::new()));
        let user = make_user_ctx("vault:user-1");
        let result = check_rbac(&state, &Method::PUT, "site-assets:img", Some(&user)).await;
        assert!(
            result.is_none(),
            "public PUT by authenticated user should be allowed"
        );
    }

    #[tokio::test]
    async fn rbac_public_allows_put_for_admin() {
        use lago_policy::{Permission, Role};

        let mut rbac = RbacManager::new();
        rbac.add_role(Role {
            name: "admin".to_string(),
            permissions: vec![Permission::Admin],
        });
        rbac.assign_role("vault:admin-user", "admin");

        let (state, _tmp) = test_state(Some(rbac));
        let user = make_user_ctx("vault:admin-user");

        let result = check_rbac(&state, &Method::PUT, "site-assets:img", Some(&user)).await;
        assert!(result.is_none(), "public PUT by admin should be allowed");
    }

    #[tokio::test]
    async fn rbac_vault_owner_allowed() {
        let (state, _tmp) = test_state(Some(RbacManager::new()));
        let user = make_user_ctx("vault:user-1");
        let result = check_rbac(&state, &Method::PUT, "vault:user-1", Some(&user)).await;
        assert!(
            result.is_none(),
            "vault owner should be allowed to write own session"
        );
    }

    #[tokio::test]
    async fn rbac_vault_non_owner_denied() {
        let (state, _tmp) = test_state(Some(RbacManager::new()));
        let user = make_user_ctx("vault:user-1");
        let result = check_rbac(&state, &Method::GET, "vault:user-2", Some(&user)).await;
        assert!(
            result.is_some(),
            "non-owner should be denied access to another user's vault"
        );
    }

    #[tokio::test]
    async fn rbac_vault_anonymous_denied() {
        let (state, _tmp) = test_state(Some(RbacManager::new()));
        let result = check_rbac(&state, &Method::GET, "vault:user-1", None).await;
        assert!(
            result.is_some(),
            "anonymous access to vault should be denied"
        );
    }

    #[tokio::test]
    async fn rbac_agent_owner_allowed() {
        let (state, _tmp) = test_state(Some(RbacManager::new()));
        let user = make_user_ctx("agent:arcan-01");
        let result = check_rbac(&state, &Method::PUT, "agent:arcan-01", Some(&user)).await;
        assert!(
            result.is_none(),
            "agent owner should be allowed to access own session"
        );
    }

    #[tokio::test]
    async fn rbac_agent_non_owner_denied() {
        let (state, _tmp) = test_state(Some(RbacManager::new()));
        let user = make_user_ctx("agent:arcan-01");
        let result = check_rbac(&state, &Method::GET, "agent:arcan-02", Some(&user)).await;
        assert!(
            result.is_some(),
            "non-owner should be denied access to another agent's session"
        );
    }

    #[tokio::test]
    async fn rbac_agent_anonymous_denied() {
        let (state, _tmp) = test_state(Some(RbacManager::new()));
        let result = check_rbac(&state, &Method::GET, "agent:arcan-01", None).await;
        assert!(
            result.is_some(),
            "anonymous access to agent session should be denied"
        );
    }

    #[tokio::test]
    async fn rbac_default_tier_allows_all() {
        let (state, _tmp) = test_state(Some(RbacManager::new()));
        // Default-tier sessions have no RBAC restriction
        let result = check_rbac(&state, &Method::PUT, "my-session", None).await;
        assert!(result.is_none(), "default tier should allow all operations");
    }

    #[tokio::test]
    async fn rbac_admin_bypasses_vault_ownership() {
        use lago_policy::{Permission, Role};

        let mut rbac = RbacManager::new();
        rbac.add_role(Role {
            name: "admin".to_string(),
            permissions: vec![Permission::Admin],
        });
        rbac.assign_role("vault:admin-user", "admin");

        let (state, _tmp) = test_state(Some(rbac));
        let user = make_user_ctx("vault:admin-user");

        // Admin accessing someone else's vault
        let result = check_rbac(&state, &Method::PUT, "vault:other-user", Some(&user)).await;
        assert!(
            result.is_none(),
            "admin should bypass vault ownership check"
        );
    }

    #[tokio::test]
    async fn rbac_admin_bypasses_agent_ownership() {
        use lago_policy::{Permission, Role};

        let mut rbac = RbacManager::new();
        rbac.add_role(Role {
            name: "admin".to_string(),
            permissions: vec![Permission::Admin],
        });
        rbac.assign_role("vault:admin-user", "admin");

        let (state, _tmp) = test_state(Some(rbac));
        let user = make_user_ctx("vault:admin-user");

        // Admin accessing an agent session
        let result = check_rbac(&state, &Method::DELETE, "agent:arcan-01", Some(&user)).await;
        assert!(
            result.is_none(),
            "admin should bypass agent ownership check"
        );
    }

    #[tokio::test]
    async fn rbac_public_allows_delete_for_authenticated_user() {
        let (state, _tmp) = test_state(Some(RbacManager::new()));
        let user = make_user_ctx("vault:user-1");
        let result = check_rbac(&state, &Method::DELETE, "site-content:blog", Some(&user)).await;
        assert!(
            result.is_none(),
            "DELETE on public session by authenticated user should be allowed"
        );
    }

    #[tokio::test]
    async fn rbac_public_post_denied_without_admin() {
        let (state, _tmp) = test_state(Some(RbacManager::new()));
        let result = check_rbac(&state, &Method::POST, "site-assets:css", None).await;
        assert!(
            result.is_some(),
            "POST on public session without admin should be denied"
        );
    }
}
