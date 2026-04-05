use lago_core::event::PolicyDecisionKind;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A named role with a set of permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub permissions: Vec<Permission>,
}

/// Individual permission grant or denial.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum Permission {
    /// Allow a specific tool by name.
    AllowTool(String),
    /// Deny a specific tool by name.
    DenyTool(String),
    /// Allow all tools in a category.
    AllowCategory(String),
    /// Deny all tools in a category.
    DenyCategory(String),
    /// Full admin access — bypasses all checks.
    Admin,
}

/// Manages roles and session-to-role assignments for RBAC.
pub struct RbacManager {
    /// role_name -> Role
    roles: HashMap<String, Role>,
    /// session_id -> list of role names
    assignments: HashMap<String, Vec<String>>,
}

impl RbacManager {
    /// Create a new empty RBAC manager.
    pub fn new() -> Self {
        Self {
            roles: HashMap::new(),
            assignments: HashMap::new(),
        }
    }

    /// Register a role.
    pub fn add_role(&mut self, role: Role) {
        self.roles.insert(role.name.clone(), role);
    }

    /// Assign a role to a session.
    pub fn assign_role(&mut self, session_id: &str, role_name: &str) {
        self.assignments
            .entry(session_id.to_string())
            .or_default()
            .push(role_name.to_string());
    }

    /// Check whether a session is permitted to use the given tool.
    ///
    /// Rules:
    /// - If the session has no roles, default to Allow.
    /// - Admin permission bypasses all checks (Allow).
    /// - Deny takes precedence over Allow.
    /// - If no matching permission is found, default to Allow.
    pub fn check_permission(
        &self,
        session_id: &str,
        tool_name: &str,
        category: Option<&str>,
    ) -> PolicyDecisionKind {
        let role_names = match self.assignments.get(session_id) {
            Some(names) if !names.is_empty() => names,
            _ => return PolicyDecisionKind::Allow,
        };

        let mut has_explicit_allow = false;
        let mut has_explicit_deny = false;

        for role_name in role_names {
            let role = match self.roles.get(role_name) {
                Some(r) => r,
                None => continue,
            };

            for perm in &role.permissions {
                match perm {
                    Permission::Admin => return PolicyDecisionKind::Allow,

                    Permission::AllowTool(name) if name == tool_name => {
                        has_explicit_allow = true;
                    }

                    Permission::DenyTool(name) if name == tool_name => {
                        has_explicit_deny = true;
                    }

                    Permission::AllowCategory(cat) => {
                        if category == Some(cat.as_str()) {
                            has_explicit_allow = true;
                        }
                    }

                    Permission::DenyCategory(cat) => {
                        if category == Some(cat.as_str()) {
                            has_explicit_deny = true;
                        }
                    }

                    _ => {}
                }
            }
        }

        // Deny takes precedence over Allow
        if has_explicit_deny {
            PolicyDecisionKind::Deny
        } else if has_explicit_allow {
            PolicyDecisionKind::Allow
        } else {
            // No matching permission found — default to Allow
            PolicyDecisionKind::Allow
        }
    }

    /// Get all registered roles.
    pub fn roles(&self) -> &HashMap<String, Role> {
        &self.roles
    }

    /// Get all session-to-role assignments.
    pub fn assignments(&self) -> &HashMap<String, Vec<String>> {
        &self.assignments
    }
}

impl Default for RbacManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> RbacManager {
        let mut mgr = RbacManager::new();

        mgr.add_role(Role {
            name: "developer".to_string(),
            permissions: vec![
                Permission::AllowCategory("filesystem".to_string()),
                Permission::DenyTool("exec_shell".to_string()),
            ],
        });

        mgr.add_role(Role {
            name: "admin".to_string(),
            permissions: vec![Permission::Admin],
        });

        mgr.add_role(Role {
            name: "readonly".to_string(),
            permissions: vec![
                Permission::AllowTool("file_read".to_string()),
                Permission::DenyCategory("filesystem".to_string()),
            ],
        });

        mgr
    }

    #[test]
    fn no_roles_defaults_to_allow() {
        let mgr = setup();
        let decision = mgr.check_permission("unknown-session", "any_tool", None);
        assert_eq!(decision, PolicyDecisionKind::Allow);
    }

    #[test]
    fn admin_bypasses_all() {
        let mut mgr = setup();
        mgr.assign_role("sess-1", "admin");

        let decision = mgr.check_permission("sess-1", "exec_shell", None);
        assert_eq!(decision, PolicyDecisionKind::Allow);
    }

    #[test]
    fn deny_takes_precedence() {
        let mut mgr = setup();
        mgr.assign_role("sess-1", "developer");

        // Category allows filesystem, but exec_shell is explicitly denied
        let decision = mgr.check_permission("sess-1", "exec_shell", Some("filesystem"));
        assert_eq!(decision, PolicyDecisionKind::Deny);
    }

    #[test]
    fn category_allow() {
        let mut mgr = setup();
        mgr.assign_role("sess-1", "developer");

        let decision = mgr.check_permission("sess-1", "file_write", Some("filesystem"));
        assert_eq!(decision, PolicyDecisionKind::Allow);
    }

    #[test]
    fn deny_category_precedence_over_allow_tool() {
        let mut mgr = setup();
        mgr.assign_role("sess-1", "readonly");

        // file_read is allowed by tool, but filesystem category is denied
        let decision = mgr.check_permission("sess-1", "file_read", Some("filesystem"));
        assert_eq!(decision, PolicyDecisionKind::Deny);
    }

    #[test]
    fn no_matching_permission_allows() {
        let mut mgr = setup();
        mgr.assign_role("sess-1", "developer");

        // No rule about "network" category or "http_get" tool
        let decision = mgr.check_permission("sess-1", "http_get", Some("network"));
        assert_eq!(decision, PolicyDecisionKind::Allow);
    }
}
