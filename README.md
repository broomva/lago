# Lago

[![CI](https://github.com/broomva/lago/actions/workflows/ci.yml/badge.svg)](https://github.com/broomva/lago/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/lago-core.svg)](https://crates.io/crates/lago-core)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Event-sourced persistence layer for long-lived AI agents.**

Lago consolidates all agent state changes — tool use, file writes, messages, memory — into a single event-sourced, versioned system with streaming I/O.

## Features

- **Event sourcing** — All state derived from an append-only journal
- **Content-addressed blobs** — SHA-256 hashing with zstd compression
- **Filesystem branching** — Git-like branching and diffing for agent workspaces
- **gRPC streaming ingest** — Bidirectional streaming via tonic
- **HTTP REST + SSE** — Axum-based API with Server-Sent Events
- **Multi-format SSE** — OpenAI, Anthropic, Vercel AI SDK compatible
- **Policy engine** — Rule-based tool governance with RBAC
- **Embedded storage** — redb (ACID, pure Rust, zero external dependencies)

## Architecture

```
lago-cli / lagod           Binaries (CLI + daemon)
  ├── lago-api             HTTP REST + SSE streaming (axum)
  ├── lago-ingest          gRPC bidirectional streaming (tonic)
  ├── lago-policy          Policy engine + RBAC
  ├── lago-fs              Filesystem manifest + branching
  ├── lago-journal         Event journal (redb-backed)
  ├── lago-store           Content-addressed blob storage
  └── lago-core            Foundation types, traits, errors
```

## Installation

### From GitHub Releases

```bash
curl -fsSL https://raw.githubusercontent.com/broomva/lago/main/install.sh | bash
```

### From Source

```bash
cargo install lago
```

### From crates.io (library crates)

```toml
[dependencies]
lago-core = "0.1"
lago-journal = "0.1"
lago-store = "0.1"
```

## Quick Start

```bash
# Start the daemon
lagod --config lago.toml

# Create a session
lago session create --name my-agent

# List sessions
lago session list

# Stream events via SSE
curl -N http://localhost:3000/v1/sessions/<id>/events
```

## Development

```bash
# Build
cargo build --workspace

# Test (187 tests)
cargo test --workspace

# Lint
cargo clippy --workspace

# Format
cargo fmt --all

# Check dependencies
cargo deny check
```

## Crates

| Crate | Description |
|-------|-------------|
| [`lago-core`](crates/lago-core) | Foundation types, traits, and error definitions |
| [`lago-journal`](crates/lago-journal) | Event journal backed by redb |
| [`lago-store`](crates/lago-store) | Content-addressed blob storage (SHA-256 + zstd) |
| [`lago-fs`](crates/lago-fs) | Filesystem manifest with branching and diffing |
| [`lago-ingest`](crates/lago-ingest) | gRPC streaming ingest service |
| [`lago-api`](crates/lago-api) | HTTP REST API + SSE streaming |
| [`lago-policy`](crates/lago-policy) | Policy engine with rule-based tool governance |
| [`lago`](crates/lago-cli) | CLI tool |
| [`lagod`](crates/lagod) | Daemon binary |

## License

[MIT](LICENSE)
