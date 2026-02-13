use lago_core::event::{PolicyDecisionKind, RiskLevel};
use lago_core::policy::PolicyContext;
use serde::{Deserialize, Serialize};

/// A policy rule that maps a condition to a decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    /// Lower priority = evaluated first.
    pub priority: u32,
    pub condition: MatchCondition,
    pub decision: PolicyDecisionKind,
    pub explanation: Option<String>,
}

/// Conditions that can be evaluated against a `PolicyContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum MatchCondition {
    /// Exact match on tool name.
    ToolName(String),
    /// Glob/prefix match on tool name (e.g. "file_*").
    ToolPattern(String),
    /// Match on tool category.
    Category(String),
    /// Match if the context's risk level >= the given threshold.
    RiskAtLeast(RiskLevel),
    /// All sub-conditions must match.
    And(Vec<MatchCondition>),
    /// Any sub-condition must match.
    Or(Vec<MatchCondition>),
    /// Negation of a sub-condition.
    Not(Box<MatchCondition>),
    /// Always matches (catch-all).
    Always,
}

impl MatchCondition {
    /// Evaluate this condition against the given policy context.
    pub fn matches(&self, ctx: &PolicyContext) -> bool {
        match self {
            MatchCondition::ToolName(name) => ctx.tool_name == *name,

            MatchCondition::ToolPattern(pattern) => match_glob(pattern, &ctx.tool_name),

            MatchCondition::Category(cat) => ctx.category.as_deref() == Some(cat.as_str()),

            MatchCondition::RiskAtLeast(threshold) => match &ctx.risk {
                Some(risk) => risk_ord(risk) >= risk_ord(threshold),
                None => false,
            },

            MatchCondition::And(conditions) => conditions.iter().all(|c| c.matches(ctx)),

            MatchCondition::Or(conditions) => conditions.iter().any(|c| c.matches(ctx)),

            MatchCondition::Not(inner) => !inner.matches(ctx),

            MatchCondition::Always => true,
        }
    }
}

// --- Internal helpers

/// Simple glob matching supporting '*' as a wildcard for any sequence of characters.
fn match_glob(pattern: &str, text: &str) -> bool {
    // Split the pattern by '*' and match segments sequentially
    let parts: Vec<&str> = pattern.split('*').collect();

    if parts.len() == 1 {
        // No wildcards — exact match
        return pattern == text;
    }

    let mut pos = 0;

    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }

        if i == 0 {
            // First segment must be a prefix
            if !text.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else if i == parts.len() - 1 {
            // Last segment must be a suffix
            if !text[pos..].ends_with(part) {
                return false;
            }
            pos = text.len();
        } else {
            // Middle segments must appear in order
            match text[pos..].find(part) {
                Some(idx) => pos += idx + part.len(),
                None => return false,
            }
        }
    }

    true
}

/// Map risk levels to numeric ordering for comparison.
fn risk_ord(level: &RiskLevel) -> u8 {
    match level {
        RiskLevel::Low => 0,
        RiskLevel::Medium => 1,
        RiskLevel::High => 2,
        RiskLevel::Critical => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_ctx() -> PolicyContext {
        PolicyContext {
            tool_name: "file_write".to_string(),
            arguments: json!({}),
            category: Some("filesystem".to_string()),
            risk: Some(RiskLevel::Medium),
            session_id: "test-session".to_string(),
            role: Some("developer".to_string()),
        }
    }

    #[test]
    fn tool_name_exact_match() {
        let cond = MatchCondition::ToolName("file_write".to_string());
        assert!(cond.matches(&test_ctx()));

        let cond = MatchCondition::ToolName("file_read".to_string());
        assert!(!cond.matches(&test_ctx()));
    }

    #[test]
    fn tool_pattern_glob_match() {
        let cond = MatchCondition::ToolPattern("file_*".to_string());
        assert!(cond.matches(&test_ctx()));

        let cond = MatchCondition::ToolPattern("net_*".to_string());
        assert!(!cond.matches(&test_ctx()));

        let cond = MatchCondition::ToolPattern("*write".to_string());
        assert!(cond.matches(&test_ctx()));
    }

    #[test]
    fn category_match() {
        let cond = MatchCondition::Category("filesystem".to_string());
        assert!(cond.matches(&test_ctx()));

        let cond = MatchCondition::Category("network".to_string());
        assert!(!cond.matches(&test_ctx()));
    }

    #[test]
    fn risk_at_least() {
        let cond = MatchCondition::RiskAtLeast(RiskLevel::Low);
        assert!(cond.matches(&test_ctx()));

        let cond = MatchCondition::RiskAtLeast(RiskLevel::Medium);
        assert!(cond.matches(&test_ctx()));

        let cond = MatchCondition::RiskAtLeast(RiskLevel::High);
        assert!(!cond.matches(&test_ctx()));
    }

    #[test]
    fn and_condition() {
        let cond = MatchCondition::And(vec![
            MatchCondition::ToolPattern("file_*".to_string()),
            MatchCondition::Category("filesystem".to_string()),
        ]);
        assert!(cond.matches(&test_ctx()));

        let cond = MatchCondition::And(vec![
            MatchCondition::ToolPattern("file_*".to_string()),
            MatchCondition::Category("network".to_string()),
        ]);
        assert!(!cond.matches(&test_ctx()));
    }

    #[test]
    fn or_condition() {
        let cond = MatchCondition::Or(vec![
            MatchCondition::ToolName("exec_shell".to_string()),
            MatchCondition::ToolName("file_write".to_string()),
        ]);
        assert!(cond.matches(&test_ctx()));
    }

    #[test]
    fn not_condition() {
        let cond =
            MatchCondition::Not(Box::new(MatchCondition::ToolName("exec_shell".to_string())));
        assert!(cond.matches(&test_ctx()));

        let cond =
            MatchCondition::Not(Box::new(MatchCondition::ToolName("file_write".to_string())));
        assert!(!cond.matches(&test_ctx()));
    }

    #[test]
    fn always_matches() {
        let cond = MatchCondition::Always;
        assert!(cond.matches(&test_ctx()));
    }

    #[test]
    fn glob_edge_cases() {
        assert!(match_glob("*", "anything"));
        assert!(match_glob("file_*", "file_write"));
        assert!(match_glob("file_*", "file_"));
        assert!(match_glob("*_write", "file_write"));
        assert!(match_glob("file_write", "file_write"));
        assert!(!match_glob("file_write", "file_read"));
        assert!(match_glob("f*_w*e", "file_write"));
    }
}
