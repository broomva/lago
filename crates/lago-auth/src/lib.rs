//! # lago-auth
//!
//! JWT-based authentication middleware for lagod. Validates bearer tokens
//! signed with a shared secret (same as broomva.tech `AUTH_SECRET`),
//! extracts user claims, and maps users to Lago sessions.

pub mod jwt;
pub mod middleware;
pub mod session_map;

pub use jwt::BroomvaClaims;
pub use middleware::{AuthLayer, UserContext, auth_middleware};
pub use session_map::SessionMap;
