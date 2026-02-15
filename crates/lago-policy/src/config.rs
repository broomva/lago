use lago_core::error::{LagoError, LagoResult};
use lago_core::event::PolicyDecisionKind;
use lago_core::sandbox::SandboxTier;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::engine::PolicyEngine;
use crate::hook::{Hook, HookAction, HookPhase, HookRunner};
use crate::rbac::{Permission, RbacManager, Role};
use crate::rule::{MatchCondition, Rule};

/// Top-level policy configuration, parsed from TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    #[serde(default)]
    pub roles: Vec<RoleConfig>,
    #[serde(default)]
    pub hooks: Vec<HookConfig>,
}

/// TOML-friendly rule configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub priority: u32,
    pub condition: MatchCondition,
    pub decision: PolicyDecisionKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_sandbox: Option<SandboxTier>,
}

/// TOML-friendly role configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleConfig {
    pub name: String,
    pub permissions: Vec<Permission>,
}

/// TOML-friendly hook configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookConfig {
    pub name: String,
    pub phase: HookPhase,
    pub condition: MatchCondition,
    pub action: HookAction,
}

impl PolicyConfig {
    /// Parse a TOML string into a PolicyConfig.
    pub fn from_toml(content: &str) -> LagoResult<Self> {
        toml::from_str(content)
            .map_err(|e| LagoError::InvalidArgument(format!("invalid policy TOML: {e}")))
    }

    /// Load a PolicyConfig from a file path.
    pub fn load(path: &Path) -> LagoResult<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::from_toml(&content)
    }

    /// Convert this config into the runtime policy types.
    pub fn into_engine(self) -> (PolicyEngine, RbacManager, HookRunner) {
        let mut engine = PolicyEngine::new();
        for rule_cfg in self.rules {
            engine.add_rule(Rule {
                id: rule_cfg.id,
                name: rule_cfg.name,
                priority: rule_cfg.priority,
                condition: rule_cfg.condition,
                decision: rule_cfg.decision,
                explanation: rule_cfg.explanation,
                required_sandbox: rule_cfg.required_sandbox,
            });
        }

        let mut rbac = RbacManager::new();
        for role_cfg in self.roles {
            rbac.add_role(Role {
                name: role_cfg.name,
                permissions: role_cfg.permissions,
            });
        }

        let hooks: Vec<Hook> = self
            .hooks
            .into_iter()
            .map(|h| Hook {
                name: h.name,
                phase: h.phase,
                condition: h.condition,
                action: h.action,
            })
            .collect();
        let runner = HookRunner::with_hooks(hooks);

        (engine, rbac, runner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lago_core::event::RiskLevel;

    const SAMPLE_TOML: &str = r#"
[[rules]]
id = "deny-shell"
name = "Deny shell execution"
priority = 1
decision = "deny"
explanation = "Shell access is not permitted"

[rules.condition]
type = "ToolName"
value = "exec_shell"

[[rules]]
id = "approve-critical"
name = "Require approval for critical risk"
priority = 10
decision = "require_approval"

[rules.condition]
type = "RiskAtLeast"
value = "critical"

[[rules]]
id = "allow-all"
name = "Default allow"
priority = 100
decision = "allow"

[rules.condition]
type = "Always"

[[roles]]
name = "developer"

[[roles.permissions]]
type = "AllowCategory"
value = "filesystem"

[[roles.permissions]]
type = "DenyTool"
value = "exec_shell"

[[roles]]
name = "admin"

[[roles.permissions]]
type = "Admin"

[[hooks]]
name = "log-file-ops"
phase = "pre"

[hooks.condition]
type = "ToolPattern"
value = "file_*"

[hooks.action]
type = "Log"
message = "File operation detected"
"#;

    #[test]
    fn parse_toml_config() {
        let config = PolicyConfig::from_toml(SAMPLE_TOML).expect("should parse");
        assert_eq!(config.rules.len(), 3);
        assert_eq!(config.roles.len(), 2);
        assert_eq!(config.hooks.len(), 1);
    }

    #[test]
    fn config_into_engine() {
        let config = PolicyConfig::from_toml(SAMPLE_TOML).expect("should parse");
        let (engine, rbac, runner) = config.into_engine();

        assert_eq!(engine.rules().len(), 3);
        // Priority ordering: deny-shell (1), approve-critical (10), allow-all (100)
        assert_eq!(engine.rules()[0].id, "deny-shell");
        assert_eq!(engine.rules()[1].id, "approve-critical");
        assert_eq!(engine.rules()[2].id, "allow-all");

        assert_eq!(rbac.roles().len(), 2);
        assert!(rbac.roles().contains_key("developer"));
        assert!(rbac.roles().contains_key("admin"));

        assert_eq!(runner.hooks().len(), 1);
        assert_eq!(runner.hooks()[0].name, "log-file-ops");
    }

    #[test]
    fn engine_evaluates_parsed_rules() {
        let config = PolicyConfig::from_toml(SAMPLE_TOML).expect("should parse");
        let (engine, _, _) = config.into_engine();

        use lago_core::policy::PolicyContext;
        use serde_json::json;

        // Shell tool -> denied
        let ctx = PolicyContext {
            tool_name: "exec_shell".to_string(),
            arguments: json!({}),
            category: None,
            risk: None,
            session_id: "s1".to_string(),
            role: None,
            sandbox_tier: None,
        };
        let decision = engine.evaluate(&ctx);
        assert_eq!(decision.decision, PolicyDecisionKind::Deny);

        // Critical risk -> require approval
        let ctx = PolicyContext {
            tool_name: "some_tool".to_string(),
            arguments: json!({}),
            category: None,
            risk: Some(RiskLevel::Critical),
            session_id: "s1".to_string(),
            role: None,
            sandbox_tier: None,
        };
        let decision = engine.evaluate(&ctx);
        assert_eq!(decision.decision, PolicyDecisionKind::RequireApproval);

        // Regular tool -> allowed
        let ctx = PolicyContext {
            tool_name: "file_read".to_string(),
            arguments: json!({}),
            category: None,
            risk: Some(RiskLevel::Low),
            session_id: "s1".to_string(),
            role: None,
            sandbox_tier: None,
        };
        let decision = engine.evaluate(&ctx);
        assert_eq!(decision.decision, PolicyDecisionKind::Allow);
    }

    #[test]
    fn empty_config_parses() {
        let config = PolicyConfig::from_toml("").expect("empty should parse");
        assert!(config.rules.is_empty());
        assert!(config.roles.is_empty());
        assert!(config.hooks.is_empty());
    }

    #[test]
    fn invalid_toml_returns_error() {
        let result = PolicyConfig::from_toml("not valid [[[toml");
        assert!(result.is_err());
    }

    #[test]
    fn default_policy_file_parses() {
        let content = include_str!("../../../default-policy.toml");
        let config = PolicyConfig::from_toml(content).expect("default-policy.toml must parse");
        assert!(
            !config.rules.is_empty(),
            "default policy must have at least one rule"
        );
        assert!(
            !config.roles.is_empty(),
            "default policy must have at least one role"
        );
        assert!(
            !config.hooks.is_empty(),
            "default policy must have at least one hook"
        );

        // Verify the engine can be built from it
        let (engine, rbac, runner) = config.into_engine();
        assert!(engine.rules().len() >= 3);
        assert!(rbac.roles().len() >= 2);
        assert!(!runner.hooks().is_empty());
    }

    #[test]
    fn config_with_required_sandbox() {
        let toml = r#"
[[rules]]
id = "sandbox-shell"
name = "Shell requires container"
priority = 1
decision = "allow"
required_sandbox = "container"

[rules.condition]
type = "ToolName"
value = "exec_shell"
"#;
        let config = PolicyConfig::from_toml(toml).expect("should parse");
        assert_eq!(config.rules.len(), 1);
        assert_eq!(
            config.rules[0].required_sandbox,
            Some(lago_core::sandbox::SandboxTier::Container)
        );

        let (engine, _, _) = config.into_engine();
        assert_eq!(
            engine.rules()[0].required_sandbox,
            Some(lago_core::sandbox::SandboxTier::Container)
        );
    }

    #[test]
    fn config_with_sandbox_tier_at_least_condition() {
        let toml = r#"
[[rules]]
id = "need-sandbox"
name = "Allow only in sandbox"
priority = 1
decision = "allow"

[rules.condition]
type = "SandboxTierAtLeast"
value = "process"
"#;
        let config = PolicyConfig::from_toml(toml).expect("should parse");
        assert_eq!(config.rules.len(), 1);

        let (engine, _, _) = config.into_engine();
        use lago_core::policy::PolicyContext;
        use serde_json::json;

        // Without sandbox -> no match -> default allow (no rules matched)
        let ctx = PolicyContext {
            tool_name: "any_tool".to_string(),
            arguments: json!({}),
            category: None,
            risk: None,
            session_id: "s1".to_string(),
            role: None,
            sandbox_tier: None,
        };
        let decision = engine.evaluate(&ctx);
        // No rules matched (SandboxTierAtLeast doesn't match without tier) -> default allow
        assert!(decision.rule_id.is_none());

        // With Process sandbox -> matches
        let ctx = PolicyContext {
            tool_name: "any_tool".to_string(),
            arguments: json!({}),
            category: None,
            risk: None,
            session_id: "s1".to_string(),
            role: None,
            sandbox_tier: Some(lago_core::sandbox::SandboxTier::Process),
        };
        let decision = engine.evaluate(&ctx);
        assert_eq!(decision.rule_id.as_deref(), Some("need-sandbox"));
    }
}
