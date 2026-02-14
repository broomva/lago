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
- `lago-api` - REST + SSE (OpenAI/Anthropic/Vercel/Lago format adapters)
- `lago-policy` - RBAC + rule-based tool governance (TOML config)
- `lago-cli` / `lagod` - CLI and daemon binaries

## Critical Patterns
- Journal trait uses `BoxFuture` for dyn-compatibility (`Arc<dyn Journal>`)
- Event compound key: session(26B) + branch(26B) + seq(8B BE) = 60 bytes
- `use redb::ReadableTable` required for `.get()`, `.iter()`, `.range()`

## Rules
See `.claude/rules/` for detailed conventions: @.claude/rules/

## Self-Learning
- **Refinement**: Update this file (CLAUDE.md) when you learn new project patterns, fix tricky errors, or make architectural decisions.
- **Errors**: If you fix a confusing error, add a "Troubleshooting" section with the error solution.
- **Performance**: Document any performance bottlenecks or optimizations you discover.
- **Evolution**: As the stack evolves, update the "Stack" and "Crates" sections.
- **Conciseness**: Keep this file high-level and concise. Link to detailed docs if needed.
