use lago_core::policy::PolicyContext;
use serde::{Deserialize, Serialize};

use crate::rule::MatchCondition;

/// Phase at which a hook executes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HookPhase {
    Pre,
    Post,
}

/// Action to perform when a hook fires.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum HookAction {
    /// Log a message when the hook fires.
    Log { message: String },
    /// Send a notification to a channel.
    Notify { channel: String },
    /// Apply a transformation script (placeholder for future use).
    Transform { script: String },
}

/// A policy hook that runs before or after tool execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hook {
    pub name: String,
    pub phase: HookPhase,
    pub condition: MatchCondition,
    pub action: HookAction,
}

/// Result of running a single hook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookResult {
    pub hook_name: String,
    pub success: bool,
    pub message: Option<String>,
}

/// Manages and executes pre/post hooks.
pub struct HookRunner {
    hooks: Vec<Hook>,
}

impl HookRunner {
    /// Create a new empty hook runner.
    pub fn new() -> Self {
        Self { hooks: Vec::new() }
    }

    /// Create a hook runner with a pre-configured set of hooks.
    pub fn with_hooks(hooks: Vec<Hook>) -> Self {
        Self { hooks }
    }

    /// Add a hook.
    pub fn add_hook(&mut self, hook: Hook) {
        self.hooks.push(hook);
    }

    /// Run all pre-execution hooks that match the given context.
    pub fn run_pre_hooks(&self, ctx: &PolicyContext) -> Vec<HookResult> {
        self.run_hooks(HookPhase::Pre, ctx, None)
    }

    /// Run all post-execution hooks that match the given context.
    pub fn run_post_hooks(
        &self,
        ctx: &PolicyContext,
        result: &serde_json::Value,
    ) -> Vec<HookResult> {
        self.run_hooks(HookPhase::Post, ctx, Some(result))
    }

    /// Get all registered hooks.
    pub fn hooks(&self) -> &[Hook] {
        &self.hooks
    }

    // --- Internal

    fn run_hooks(
        &self,
        phase: HookPhase,
        ctx: &PolicyContext,
        _result: Option<&serde_json::Value>,
    ) -> Vec<HookResult> {
        let mut results = Vec::new();

        for hook in &self.hooks {
            if hook.phase != phase {
                continue;
            }

            if !hook.condition.matches(ctx) {
                continue;
            }

            let hook_result = self.execute_action(hook);
            results.push(hook_result);
        }

        results
    }

    fn execute_action(&self, hook: &Hook) -> HookResult {
        match &hook.action {
            HookAction::Log { message } => {
                tracing::info!(hook = %hook.name, "{}", message);
                HookResult {
                    hook_name: hook.name.clone(),
                    success: true,
                    message: Some(message.clone()),
                }
            }

            HookAction::Notify { channel } => {
                tracing::info!(hook = %hook.name, channel = %channel, "notification triggered");
                HookResult {
                    hook_name: hook.name.clone(),
                    success: true,
                    message: Some(format!("notification sent to {}", channel)),
                }
            }

            HookAction::Transform { script } => {
                // Transform is a placeholder — log the script name and succeed.
                tracing::info!(hook = %hook.name, script = %script, "transform triggered");
                HookResult {
                    hook_name: hook.name.clone(),
                    success: true,
                    message: Some(format!("transform script '{}' executed", script)),
                }
            }
        }
    }
}

impl Default for HookRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lago_core::event::RiskLevel;
    use serde_json::json;

    fn test_ctx() -> PolicyContext {
        PolicyContext {
            tool_name: "file_write".to_string(),
            arguments: json!({}),
            category: Some("filesystem".to_string()),
            risk: Some(RiskLevel::Medium),
            session_id: "test-session".to_string(),
            role: None,
            sandbox_tier: None,
        }
    }

    #[test]
    fn pre_hooks_fire_for_matching_conditions() {
        let runner = HookRunner::with_hooks(vec![
            Hook {
                name: "log-writes".to_string(),
                phase: HookPhase::Pre,
                condition: MatchCondition::ToolPattern("file_*".to_string()),
                action: HookAction::Log {
                    message: "file operation starting".to_string(),
                },
            },
            Hook {
                name: "log-shell".to_string(),
                phase: HookPhase::Pre,
                condition: MatchCondition::ToolName("exec_shell".to_string()),
                action: HookAction::Log {
                    message: "shell execution".to_string(),
                },
            },
        ]);

        let results = runner.run_pre_hooks(&test_ctx());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].hook_name, "log-writes");
        assert!(results[0].success);
    }

    #[test]
    fn post_hooks_fire_separately() {
        let runner = HookRunner::with_hooks(vec![
            Hook {
                name: "pre-hook".to_string(),
                phase: HookPhase::Pre,
                condition: MatchCondition::Always,
                action: HookAction::Log {
                    message: "pre".to_string(),
                },
            },
            Hook {
                name: "post-hook".to_string(),
                phase: HookPhase::Post,
                condition: MatchCondition::Always,
                action: HookAction::Notify {
                    channel: "audit".to_string(),
                },
            },
        ]);

        let pre = runner.run_pre_hooks(&test_ctx());
        assert_eq!(pre.len(), 1);
        assert_eq!(pre[0].hook_name, "pre-hook");

        let post = runner.run_post_hooks(&test_ctx(), &json!({"ok": true}));
        assert_eq!(post.len(), 1);
        assert_eq!(post[0].hook_name, "post-hook");
    }

    #[test]
    fn no_hooks_returns_empty() {
        let runner = HookRunner::new();
        assert!(runner.run_pre_hooks(&test_ctx()).is_empty());
        assert!(runner.run_post_hooks(&test_ctx(), &json!(null)).is_empty());
    }
}
