# Lago - Event-Sourced Agent Persistence Layer

Event-sourced storage backbone for long-lived AI agents. All state changes
(tool use, file writes, messages, memory) flow through an append-only journal.

## Build & Verify
```bash
cargo fmt && cargo clippy --workspace && cargo test --workspace
```

## Stack
Rust 2024 | redb v2 | tonic+prost (gRPC) | axum (HTTP/SSE) | ULID | SHA-256+zstd

## Crates
- `lago-core` - Types, traits, errors (zero external deps)
- `lago-journal` - Event journal (redb). Use `spawn_blocking` for all redb ops.
- `lago-store` - Content-addressed blob storage (SHA-256 + zstd)
- `lago-fs` - Filesystem manifest, branching, diffs
- `lago-ingest` - gRPC streaming ingest (protobuf on wire, JSON in storage)
- `lago-api` - REST + SSE (OpenAI/Anthropic/Vercel/Lago format adapters) + auth-protected `/v1/memory/*` routes
- `lago-policy` - RBAC + rule-based tool governance (TOML config)
- `lago-knowledge` - Knowledge index engine (frontmatter parsing, wikilink extraction, scored search, BFS graph traversal)
- `lago-auth` - JWT auth middleware (shared-secret validation, user→session mapping)
- `lago-cli` / `lagod` - CLI and daemon binaries. CLI includes `lago memory` subcommands.

## Context Engine (Memory API)

Lago serves as the persistence substrate for user memory vaults via `/v1/memory/*` routes:

- **Auth**: JWT bearer tokens signed with `AUTH_SECRET` (shared with broomva.tech). Configure via `LAGO_JWT_SECRET` env var or `[auth] jwt_secret` in `lago.toml`.
- **Per-user sessions**: Each authenticated user gets a Lago session named `vault:{user_id}`.
- **Knowledge index**: `lago-knowledge` parses YAML frontmatter, extracts `[[wikilinks]]`, builds scored search with name/body/tag boosting, and provides BFS graph traversal.
- **CLI**: `lago memory {status,ls,search,read,store,ingest,delete}` — token resolved from `BROOMVA_API_TOKEN` env or `~/.broomva/config.json`.

## Critical Patterns
- Journal trait uses `BoxFuture` for dyn-compatibility (`Arc<dyn Journal>`)
- Event compound key: session(26B) + branch(26B) + seq(8B BE) = 60 bytes
- `use redb::ReadableTable` required for `.get()`, `.iter()`, `.range()`

## Rules
See `.claude/rules/` for detailed conventions: @.claude/rules/

## Self-Learning & Status Evolution

Agents working on Lago must continuously improve documentation and track progress. Knowledge discovered during development becomes durable guidance.

### When to Update Documentation

| Trigger | What to update | Where |
|---------|---------------|-------|
| New tests added | Test counts per crate | `../docs/STATUS.md` (Lago section) |
| Gap closed (feature implemented) | Check off gap, move to "complete" | `../docs/STATUS.md` Known Gaps |
| New gap discovered | Add to appropriate priority tier | `../docs/STATUS.md` Known Gaps |
| Architecture changed | Update diagrams and data flow | `../docs/ARCHITECTURE.md` |
| Roadmap milestone completed | Mark complete, note date | `../docs/ROADMAP.md` |
| New test strategy or pattern | Add to testing plan | `../docs/TESTING.md` |
| Tricky error fixed | Add troubleshooting entry | This file (below) |
| New pattern established | Document pattern | This file or `.claude/rules/` |
| Performance finding | Document bottleneck + solution | This file |

### Update Protocol

1. **Identify**: Pinpoint the specific gap in knowledge or the status change.
2. **Formulate**: Create a concise, actionable update.
   - *Bad*: "Fixed a bug."
   - *Good*: "lago-journal: When using `range()` on redb, always import `ReadableTable` — compile error otherwise."
3. **Locate**: Choose the right file:
   - **Project status, test counts, gaps**: `../docs/STATUS.md`
   - **Roadmap progress**: `../docs/ROADMAP.md`
   - **Critical patterns for Lago**: This file (CLAUDE.md)
   - **Code conventions**: `.claude/rules/`
   - **Architecture decisions**: `../docs/ARCHITECTURE.md`
4. **Verify**: Ensure the update doesn't contradict existing rules.
5. **Keep concise**: This file stays high-level. Link to detailed docs for depth.

### Rule Format for Technical Rules

- **Context**: When this applies.
- **Action**: What to do.
- **Reason**: Why it matters.

*Example*:
> **Context**: When querying redb tables in lago-journal.
> **Action**: Always import `use redb::ReadableTable` in scope.
> **Reason**: `.get()`, `.iter()`, `.range()` are trait methods and won't compile without the import.

### After Completing Any Feature or Fix

Run the validation and update status:
```bash
cargo fmt && cargo clippy --workspace && cargo test --workspace
```
Then update `../docs/STATUS.md` with:
- New test count for affected crate(s)
- Any gaps that were closed
- Any new gaps discovered during implementation

## Troubleshooting

*(Add entries here when fixing confusing errors. Format: Error → Cause → Fix)*
