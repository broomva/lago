# Lago Documentation

**Lago** is an event-sourced persistence layer for long-lived AI agents. It consolidates all agent state changes — tool use, file writes, messages, memory — into a single append-only journal with streaming I/O compatible with OpenAI, Anthropic, and Vercel AI SDK APIs.

## Documentation Index

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | System architecture, design decisions, crate structure |
| [Type System & Schemas](type-system.md) | Core types, event model, ID system, trait definitions |
| [Storage Engine](storage-engine.md) | redb journal, compound keys, blob store, snapshots |
| [API Reference](api-reference.md) | REST endpoints, gRPC service, SSE format adapters |
| [Policy Engine](policy-engine.md) | Rule evaluation, RBAC, hooks, TOML configuration |
| [AI-Native Design](ai-native-design.md) | Agent-first philosophy, tool spans, branching, streaming |
| [Development Guide](development-guide.md) | Testing, CI/CD, release tooling, CLI reference |

## Quick Start

```bash
# Build the entire workspace
cargo build --workspace

# Run all tests (187 tests across 9 crates)
cargo test --workspace

# Full validation pipeline
cargo fmt && cargo clippy --workspace && cargo test --workspace

# Initialize a project and start the daemon
lago init .
lago serve --grpc-port 50051 --http-port 8080
```

## System Overview

```
Agents/Tools ──gRPC──> lago-ingest ──> WAL ──> lago-journal (redb)
                                                      |
                                    +-----------------+-----------------+
                                    v                 v                 v
                             lago-fs           lago-policy        lago-api
                          (manifest +       (security hooks,    (HTTP REST +
                           branching)          RBAC, audit)     SSE streaming)
                                    |                              |
                                    v                              v
                             lago-store                    OpenAI / Anthropic /
                          (content-addressed               Vercel AI SDK format
                            blob storage)                     SSE output
```

## Technology Stack

| Component | Choice | Version |
|-----------|--------|---------|
| Language | Rust (2024 edition) | MSRV 1.85 |
| Embedded DB | redb | 2.x |
| gRPC | tonic + prost | 0.14.x |
| HTTP/SSE | axum + tower | 0.8.x |
| Hashing | sha2 (SHA-256) | 0.10.x |
| Compression | zstd | 0.13.x |
| IDs | ulid | 1.x |
| Async runtime | tokio | 1.x |
| CLI | clap (derive) | 4.x |
| Serialization | serde_json (storage), prost (wire) | 1.x / 0.14.x |
