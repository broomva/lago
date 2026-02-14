use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use lago_core::LagoError;
use serde::Serialize;

/// API-level error type that wraps `LagoError` and adds HTTP-specific variants.
#[derive(Debug)]
pub enum ApiError {
    /// Wraps a core `LagoError`.
    Lago(LagoError),
    /// 400 Bad Request with a human-readable message.
    BadRequest(String),
    /// 404 Not Found with a description of what was missing.
    NotFound(String),
    /// 500 Internal Server Error with an opaque message.
    Internal(String),
}

/// JSON body returned for error responses.
#[derive(Serialize)]
struct ErrorBody {
    error: String,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_type, message) = match &self {
            ApiError::Lago(e) => match e {
                LagoError::SessionNotFound(id) => (
                    StatusCode::NOT_FOUND,
                    "session_not_found",
                    format!("session not found: {id}"),
                ),
                LagoError::BranchNotFound(id) => (
                    StatusCode::NOT_FOUND,
                    "branch_not_found",
                    format!("branch not found: {id}"),
                ),
                LagoError::EventNotFound(id) => (
                    StatusCode::NOT_FOUND,
                    "event_not_found",
                    format!("event not found: {id}"),
                ),
                LagoError::BlobNotFound(hash) => (
                    StatusCode::NOT_FOUND,
                    "blob_not_found",
                    format!("blob not found: {hash}"),
                ),
                LagoError::FileNotFound(path) => (
                    StatusCode::NOT_FOUND,
                    "file_not_found",
                    format!("file not found: {path}"),
                ),
                LagoError::InvalidArgument(msg) => {
                    (StatusCode::BAD_REQUEST, "invalid_argument", msg.clone())
                }
                LagoError::SequenceConflict { expected, actual } => (
                    StatusCode::CONFLICT,
                    "sequence_conflict",
                    format!("sequence conflict: expected {expected}, got {actual}"),
                ),
                LagoError::PolicyDenied(msg) => {
                    (StatusCode::FORBIDDEN, "policy_denied", msg.clone())
                }
                LagoError::Serialization(e) => (
                    StatusCode::BAD_REQUEST,
                    "serialization_error",
                    format!("serialization error: {e}"),
                ),
                LagoError::HashLine(e) => (
                    StatusCode::BAD_REQUEST,
                    "hashline_error",
                    format!("hashline error: {e}"),
                ),
                LagoError::Sandbox(msg) => (
                    StatusCode::BAD_REQUEST,
                    "sandbox_error",
                    format!("sandbox error: {msg}"),
                ),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("internal error: {e}"),
                ),
            },
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "bad_request", msg.clone()),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg.clone()),
            ApiError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                msg.clone(),
            ),
        };

        let body = ErrorBody {
            error: error_type.to_string(),
            message,
        };

        (status, axum::Json(body)).into_response()
    }
}

impl From<LagoError> for ApiError {
    fn from(e: LagoError) -> Self {
        ApiError::Lago(e)
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        ApiError::BadRequest(format!("invalid JSON: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    #[test]
    fn api_error_from_lago_session_not_found() {
        let e: ApiError = LagoError::SessionNotFound("S1".into()).into();
        let resp = e.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn api_error_from_lago_branch_not_found() {
        let e: ApiError = LagoError::BranchNotFound("B1".into()).into();
        let resp = e.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn api_error_from_lago_policy_denied() {
        let e: ApiError = LagoError::PolicyDenied("blocked".into()).into();
        let resp = e.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn api_error_from_lago_sequence_conflict() {
        let e: ApiError = LagoError::SequenceConflict {
            expected: 5,
            actual: 3,
        }
        .into();
        let resp = e.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn api_error_from_lago_invalid_argument() {
        let e: ApiError = LagoError::InvalidArgument("bad input".into()).into();
        let resp = e.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn api_error_from_lago_internal() {
        let e: ApiError = LagoError::Journal("disk error".into()).into();
        let resp = e.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn api_error_bad_request() {
        let e = ApiError::BadRequest("bad".into());
        let resp = e.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn api_error_not_found() {
        let e = ApiError::NotFound("missing".into());
        let resp = e.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn api_error_internal() {
        let e = ApiError::Internal("oops".into());
        let resp = e.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn api_error_from_serde_json() {
        let err: Result<serde_json::Value, _> = serde_json::from_str("{bad");
        let e: ApiError = err.unwrap_err().into();
        match e {
            ApiError::BadRequest(msg) => assert!(msg.contains("invalid JSON")),
            _ => panic!("expected BadRequest"),
        }
    }

    #[test]
    fn api_error_from_lago_hashline() {
        let hl_err = lago_core::hashline::HashLineError::LineOutOfBounds {
            line_num: 10,
            total_lines: 5,
        };
        let e: ApiError = LagoError::HashLine(hl_err).into();
        let resp = e.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn api_error_from_lago_sandbox() {
        let e: ApiError = LagoError::Sandbox("container failed".into()).into();
        let resp = e.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
