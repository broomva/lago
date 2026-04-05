# Policy Engine

The policy engine (`lago-policy`) provides rule-based governance for AI agent tool execution. It evaluates whether tool invocations should be allowed, denied, or require human approval based on configurable rules, role-based access control, and execution hooks.

## Architecture

```
Tool Invocation
      |
      v
  Pre-Hooks (logging, notifications)
      |
      v
  PolicyEngine::evaluate(context)
      |
      +-- Rule matching (priority-ordered)
      +-- RBAC permission check
      |
      v
  PolicyDecision { Allow | Deny | RequireApproval }
      |
      v
  Post-Hooks (audit, metrics)
```

## Rule Engine

### Rule Structure

```rust
pub struct Rule {
    pub id: String,
    pub name: String,
    pub priority: u32,              // Lower = higher priority
    pub condition: MatchCondition,  // When this rule applies
    pub decision: PolicyDecisionKind, // What to do
    pub explanation: Option<String>,  // Why
}
```

Rules are evaluated in priority order (lowest number first). The first matching rule wins.

### Match Conditions

| Condition | Description | Example |
|-----------|-------------|---------|
| `ToolName(String)` | Exact tool name match | `"exec_shell"` |
| `ToolPattern(String)` | Glob pattern match | `"file_*"` |
| `Category(String)` | Tool category match | `"filesystem"` |
| `RiskLevel(RiskLevel)` | Risk threshold | `High`, `Critical` |
| `And(Vec<MatchCondition>)` | All conditions must match | Logical AND |
| `Or(Vec<MatchCondition>)` | Any condition matches | Logical OR |
| `Not(Box<MatchCondition>)` | Negation | Logical NOT |
| `Always` | Always matches | Catch-all rule |

### Evaluation

```rust
pub struct PolicyEngine {
    rules: Vec<Rule>,  // Sorted by priority
}

impl PolicyEngine {
    pub fn evaluate(&self, ctx: &PolicyContext) -> PolicyDecision
}
```

The engine iterates rules in priority order and returns the decision of the first matching rule. If no rule matches, the default is `Allow`.

## RBAC (Role-Based Access Control)

### Roles and Permissions

```rust
pub struct Role {
    pub name: String,
    pub permissions: Vec<Permission>,
}

pub enum Permission {
    AllowTool(String),      // Allow specific tool by name
    DenyTool(String),       // Deny specific tool by name
    AllowCategory(String),  // Allow all tools in category
    DenyCategory(String),   // Deny all tools in category
    Admin,                  // Allow everything
}
```

### RBAC Manager

```rust
pub struct RbacManager {
    roles: HashMap<String, Role>,
    session_roles: HashMap<String, Vec<String>>,
}

impl RbacManager {
    pub fn add_role(&mut self, role: Role);
    pub fn assign_role(&mut self, session_id: &str, role_name: &str);
    pub fn check_permission(&self, session_id: &str, tool_name: &str, category: Option<&str>)
        -> PolicyDecisionKind;
}
```

Permission evaluation order:
1. Check `Admin` — allows everything
2. Check explicit `DenyTool` / `DenyCategory` — deny wins over allow
3. Check explicit `AllowTool` / `AllowCategory` — explicit allow
4. Default: `Allow` (if no matching permission found)

## Hooks

Hooks execute side effects before or after tool execution without affecting the policy decision.

### Hook Structure

```rust
pub struct Hook {
    pub name: String,
    pub phase: HookPhase,          // Pre or Post
    pub condition: MatchCondition, // Same conditions as rules
    pub action: HookAction,
}

pub enum HookPhase {
    Pre,   // Before tool execution
    Post,  // After tool execution
}

pub enum HookAction {
    Log { message: String },        // Log via tracing
    Notify { channel: String },     // Send notification
    Transform { script: String },   // Placeholder for scripting
}
```

### Hook Runner

```rust
pub struct HookRunner {
    hooks: Vec<Hook>,
}

impl HookRunner {
    pub fn run_pre_hooks(&self, ctx: &PolicyContext) -> Vec<HookResult>;
    pub fn run_post_hooks(&self, ctx: &PolicyContext, result: &serde_json::Value) -> Vec<HookResult>;
}
```

Hooks execute all matching hooks (not just the first match, unlike rules). Each returns a `HookResult`:

```rust
pub struct HookResult {
    pub hook_name: String,
    pub success: bool,
    pub message: Option<String>,
}
```

## TOML Configuration

Policy rules, roles, and hooks are configured via TOML files.

### Example Configuration

```toml
# Rules (evaluated in priority order)
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
id = "approve-destructive"
name = "Require approval for destructive operations"
priority = 10
decision = "require_approval"
explanation = "Destructive operations need human approval"
[rules.condition]
type = "RiskLevel"
value = "high"

[[rules]]
id = "allow-filesystem"
name = "Allow filesystem operations"
priority = 100
decision = "allow"
[rules.condition]
type = "Category"
value = "filesystem"

# Roles
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

# Hooks
[[hooks]]
name = "log-file-ops"
phase = "pre"
[hooks.condition]
type = "ToolPattern"
value = "file_*"
[hooks.action]
type = "Log"
message = "File operation detected"

[[hooks]]
name = "notify-approvals"
phase = "post"
[hooks.condition]
type = "RiskLevel"
value = "critical"
[hooks.action]
type = "Notify"
channel = "security-alerts"
```

### Configuration Loading

```rust
pub struct PolicyConfig {
    pub rules: Vec<RuleConfig>,
    pub roles: Vec<RoleConfig>,
    pub hooks: Vec<HookConfig>,
}

impl PolicyConfig {
    pub fn from_toml(content: &str) -> LagoResult<Self>;
    pub fn load(path: &Path) -> LagoResult<Self>;
    pub fn into_engine(self) -> (PolicyEngine, RbacManager, HookRunner);
}
```

The `into_engine()` method converts the parsed configuration into the three runtime components, ready for use.

### Condition Types in TOML

| `type` | `value` | Matches |
|--------|---------|---------|
| `"ToolName"` | `"exec_shell"` | Exact tool name |
| `"ToolPattern"` | `"file_*"` | Glob pattern on tool name |
| `"Category"` | `"filesystem"` | Tool category string |
| `"RiskLevel"` | `"low"` / `"medium"` / `"high"` / `"critical"` | Risk threshold |
| `"Always"` | (ignored) | Always matches |

### Decision Values in TOML

| Value | PolicyDecisionKind |
|-------|-------------------|
| `"allow"` | `Allow` |
| `"deny"` | `Deny` |
| `"require_approval"` | `RequireApproval` |
