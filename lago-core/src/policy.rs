use crate::event::{PolicyDecisionKind, RiskLevel};
use crate::sandbox::SandboxTier;
use serde::{Deserialize, Serialize};

/// Result of a policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub decision: PolicyDecisionKind,
    pub rule_id: Option<String>,
    pub explanation: Option<String>,
    /// If set, the tool must run in a sandbox of at least this tier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_sandbox: Option<SandboxTier>,
}

impl PolicyDecision {
    pub fn allow() -> Self {
        Self {
            decision: PolicyDecisionKind::Allow,
            rule_id: None,
            explanation: None,
            required_sandbox: None,
        }
    }

    pub fn deny(rule_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            decision: PolicyDecisionKind::Deny,
            rule_id: Some(rule_id.into()),
            explanation: Some(reason.into()),
            required_sandbox: None,
        }
    }

    pub fn require_approval(rule_id: impl Into<String>) -> Self {
        Self {
            decision: PolicyDecisionKind::RequireApproval,
            rule_id: Some(rule_id.into()),
            explanation: None,
            required_sandbox: None,
        }
    }
}

/// Context provided to the policy engine for evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    pub tool_name: String,
    pub arguments: serde_json::Value,
    pub category: Option<String>,
    pub risk: Option<RiskLevel>,
    pub session_id: String,
    pub role: Option<String>,
    /// The sandbox tier currently available for this context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_tier: Option<SandboxTier>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::PolicyDecisionKind;

    #[test]
    fn policy_decision_allow() {
        let d = PolicyDecision::allow();
        assert_eq!(d.decision, PolicyDecisionKind::Allow);
        assert!(d.rule_id.is_none());
        assert!(d.explanation.is_none());
    }

    #[test]
    fn policy_decision_deny() {
        let d = PolicyDecision::deny("rule-1", "too risky");
        assert_eq!(d.decision, PolicyDecisionKind::Deny);
        assert_eq!(d.rule_id.as_deref(), Some("rule-1"));
        assert_eq!(d.explanation.as_deref(), Some("too risky"));
    }

    #[test]
    fn policy_decision_require_approval() {
        let d = PolicyDecision::require_approval("rule-2");
        assert_eq!(d.decision, PolicyDecisionKind::RequireApproval);
        assert_eq!(d.rule_id.as_deref(), Some("rule-2"));
        assert!(d.explanation.is_none());
    }

    #[test]
    fn policy_decision_serde_roundtrip() {
        let d = PolicyDecision::deny("r1", "blocked");
        let json = serde_json::to_string(&d).unwrap();
        let back: PolicyDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back.decision, PolicyDecisionKind::Deny);
        assert_eq!(back.rule_id.as_deref(), Some("r1"));
    }

    #[test]
    fn policy_context_construction() {
        let ctx = PolicyContext {
            tool_name: "exec".to_string(),
            arguments: serde_json::json!({"cmd": "ls"}),
            category: Some("shell".to_string()),
            risk: Some(crate::event::RiskLevel::High),
            session_id: "SESS001".to_string(),
            role: Some("admin".to_string()),
            sandbox_tier: Some(SandboxTier::Process),
        };
        assert_eq!(ctx.tool_name, "exec");
        assert_eq!(ctx.risk, Some(crate::event::RiskLevel::High));
        assert_eq!(ctx.sandbox_tier, Some(SandboxTier::Process));
    }

    #[test]
    fn policy_decision_with_required_sandbox() {
        let mut d = PolicyDecision::allow();
        d.required_sandbox = Some(SandboxTier::Container);
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains("\"required_sandbox\":\"container\""));
        let back: PolicyDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back.required_sandbox, Some(SandboxTier::Container));
    }

    #[test]
    fn policy_decision_required_sandbox_default_none() {
        let d = PolicyDecision::allow();
        assert!(d.required_sandbox.is_none());
        let d = PolicyDecision::deny("r1", "reason");
        assert!(d.required_sandbox.is_none());
        let d = PolicyDecision::require_approval("r2");
        assert!(d.required_sandbox.is_none());
    }

    #[test]
    fn policy_context_sandbox_tier_default() {
        // Deserialize without sandbox_tier field — should default to None
        let json = r#"{"tool_name":"x","arguments":{},"session_id":"s"}"#;
        let ctx: PolicyContext = serde_json::from_str(json).unwrap();
        assert!(ctx.sandbox_tier.is_none());
    }
}
