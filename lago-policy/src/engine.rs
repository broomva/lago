use lago_core::event::PolicyDecisionKind;
use lago_core::policy::{PolicyContext, PolicyDecision};

use crate::rule::Rule;

/// Rule-based policy engine that evaluates tool invocations against an ordered
/// set of rules.
pub struct PolicyEngine {
    /// Rules sorted by priority (lower number = higher priority = evaluated first).
    rules: Vec<Rule>,
}

impl PolicyEngine {
    /// Create a new empty policy engine.
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Insert a rule, maintaining sort order by priority.
    pub fn add_rule(&mut self, rule: Rule) {
        let pos = self
            .rules
            .binary_search_by_key(&rule.priority, |r| r.priority)
            .unwrap_or_else(|pos| pos);
        self.rules.insert(pos, rule);
    }

    /// Evaluate the policy context against all rules in priority order.
    /// Returns the decision from the first matching rule.
    /// If no rule matches, defaults to Allow.
    pub fn evaluate(&self, ctx: &PolicyContext) -> PolicyDecision {
        for rule in &self.rules {
            if rule.condition.matches(ctx) {
                return PolicyDecision {
                    decision: rule.decision,
                    rule_id: Some(rule.id.clone()),
                    explanation: rule.explanation.clone(),
                    required_sandbox: rule.required_sandbox,
                };
            }
        }

        // Default: allow if no rules matched
        PolicyDecision {
            decision: PolicyDecisionKind::Allow,
            rule_id: None,
            explanation: None,
            required_sandbox: None,
        }
    }

    /// Remove a rule by its ID. Returns `true` if a rule was removed.
    pub fn remove_rule(&mut self, rule_id: &str) -> bool {
        let len_before = self.rules.len();
        self.rules.retain(|r| r.id != rule_id);
        self.rules.len() < len_before
    }

    /// Get an immutable reference to the current rules.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::MatchCondition;
    use lago_core::event::RiskLevel;
    use serde_json::json;

    fn ctx(tool: &str, risk: Option<RiskLevel>) -> PolicyContext {
        PolicyContext {
            tool_name: tool.to_string(),
            arguments: json!({}),
            category: Some("general".to_string()),
            risk,
            session_id: "sess-1".to_string(),
            role: None,
            sandbox_tier: None,
        }
    }

    #[test]
    fn default_allows_when_no_rules() {
        let engine = PolicyEngine::new();
        let decision = engine.evaluate(&ctx("any_tool", None));
        assert_eq!(decision.decision, PolicyDecisionKind::Allow);
        assert!(decision.rule_id.is_none());
    }

    #[test]
    fn first_matching_rule_wins() {
        let mut engine = PolicyEngine::new();

        engine.add_rule(Rule {
            id: "r1".to_string(),
            name: "deny shell".to_string(),
            priority: 10,
            condition: MatchCondition::ToolName("exec_shell".to_string()),
            decision: PolicyDecisionKind::Deny,
            explanation: Some("shell access denied".to_string()),
            required_sandbox: None,
        });

        engine.add_rule(Rule {
            id: "r2".to_string(),
            name: "allow all".to_string(),
            priority: 100,
            condition: MatchCondition::Always,
            decision: PolicyDecisionKind::Allow,
            explanation: None,
            required_sandbox: None,
        });

        let decision = engine.evaluate(&ctx("exec_shell", None));
        assert_eq!(decision.decision, PolicyDecisionKind::Deny);
        assert_eq!(decision.rule_id.as_deref(), Some("r1"));

        let decision = engine.evaluate(&ctx("file_read", None));
        assert_eq!(decision.decision, PolicyDecisionKind::Allow);
        assert_eq!(decision.rule_id.as_deref(), Some("r2"));
    }

    #[test]
    fn priority_ordering() {
        let mut engine = PolicyEngine::new();

        // Add low priority first
        engine.add_rule(Rule {
            id: "low".to_string(),
            name: "catch-all allow".to_string(),
            priority: 100,
            condition: MatchCondition::Always,
            decision: PolicyDecisionKind::Allow,
            explanation: None,
            required_sandbox: None,
        });

        // Add high priority second
        engine.add_rule(Rule {
            id: "high".to_string(),
            name: "deny critical".to_string(),
            priority: 1,
            condition: MatchCondition::RiskAtLeast(RiskLevel::Critical),
            decision: PolicyDecisionKind::Deny,
            explanation: Some("critical risk denied".to_string()),
            required_sandbox: None,
        });

        // High-risk but not critical -> allow
        let decision = engine.evaluate(&ctx("tool", Some(RiskLevel::High)));
        assert_eq!(decision.decision, PolicyDecisionKind::Allow);

        // Critical risk -> deny (higher priority rule matches first)
        let decision = engine.evaluate(&ctx("tool", Some(RiskLevel::Critical)));
        assert_eq!(decision.decision, PolicyDecisionKind::Deny);
        assert_eq!(decision.rule_id.as_deref(), Some("high"));
    }

    #[test]
    fn remove_rule() {
        let mut engine = PolicyEngine::new();

        engine.add_rule(Rule {
            id: "r1".to_string(),
            name: "test".to_string(),
            priority: 10,
            condition: MatchCondition::Always,
            decision: PolicyDecisionKind::Deny,
            explanation: None,
            required_sandbox: None,
        });

        assert_eq!(engine.rules().len(), 1);
        assert!(engine.remove_rule("r1"));
        assert_eq!(engine.rules().len(), 0);
        assert!(!engine.remove_rule("r1"));
    }

    #[test]
    fn engine_propagates_required_sandbox() {
        use lago_core::sandbox::SandboxTier;

        let mut engine = PolicyEngine::new();
        engine.add_rule(Rule {
            id: "sandboxed".to_string(),
            name: "require container for shell".to_string(),
            priority: 1,
            condition: MatchCondition::ToolName("exec_shell".to_string()),
            decision: PolicyDecisionKind::Allow,
            explanation: None,
            required_sandbox: Some(SandboxTier::Container),
        });

        let decision = engine.evaluate(&ctx("exec_shell", None));
        assert_eq!(decision.decision, PolicyDecisionKind::Allow);
        assert_eq!(decision.required_sandbox, Some(SandboxTier::Container));

        // Rule without sandbox requirement
        engine.add_rule(Rule {
            id: "fallback".to_string(),
            name: "allow all".to_string(),
            priority: 100,
            condition: MatchCondition::Always,
            decision: PolicyDecisionKind::Allow,
            explanation: None,
            required_sandbox: None,
        });

        let decision = engine.evaluate(&ctx("file_read", None));
        assert!(decision.required_sandbox.is_none());
    }
}
