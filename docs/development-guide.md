# Development Guide

## Build & Verify

```bash
# Full validation pipeline (run before every commit)
cargo fmt && cargo clippy --workspace && cargo test --workspace

# Quick check (faster iteration)
cargo check --workspace

# Release build
cargo build --release --workspace
```

## Test Coverage

**295 tests** across all 10 crates, all passing:

| Crate | Tests | Coverage |
|-------|-------|----------|
| `lago-core` | 118 | IDs, events, errors, journal query, session, policy, tool_span, canonical protocol alignment |
| `lago-api` | 62 | SSE formats (OpenAI, Anthropic, Vercel, Lago), REST/session APIs, error mapping |
| `lago-fs` | 30 | Manifest, branch, diff, projection, tree operations |
| `lago-policy` | 34 | Engine rules, RBAC, hooks, TOML config parsing |
| `lago-journal` | 24 | Key encoding, redb CRUD, sessions, snapshots, notifications |
| `lago-store` | 17 | Blob put/get, SHA-256 hashing, zstd compression |
| `lago-ingest` | 10 | Proto codec roundtrips, ack/heartbeat construction |
| `lago-aios-eventstore-adapter` | 0 | Canonical adapter is covered through cross-project conformance and integration paths |
| `lago-cli` | 0 | Primarily validated via integration flows and manual CLI verification |
| `lagod` | 0 | Primarily validated via API/integration and daemon smoke paths |

### Test Patterns

**Unit tests** are placed in `#[cfg(test)] mod tests` within the source file:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_id_new_is_unique() {
        let a = EventId::new();
        let b = EventId::new();
        assert_ne!(a, b);
    }
}
```

**Async tests** use `#[tokio::test]` for redb and network operations:

```rust
#[tokio::test]
async fn append_and_read_single_event() {
    let (_dir, journal) = setup();
    let event = make_test_event(1);
    journal.append(event.clone()).await.unwrap();
    let events = journal.read(EventQuery::new()).await.unwrap();
    assert_eq!(events.len(), 1);
}
```

**Manual mocks** are preferred over `mockall` for simplicity. Traits like `Journal` and `SseFormat` enable dependency injection.

**Test databases** use `tempfile::TempDir` for isolated redb instances:

```rust
fn setup() -> (TempDir, RedbJournal) {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.redb");
    let journal = RedbJournal::open(&db_path).unwrap();
    (dir, journal)
}
```

## CI/CD Pipeline

### GitHub Actions CI (`.github/workflows/ci.yml`)

Triggered on push to `main` and pull requests:

| Job | Command | Purpose |
|-----|---------|---------|
| `check` | `cargo check --workspace --all-targets` | Compilation check |
| `test` | `cargo test --workspace` | Run all tests |
| `clippy` | `cargo clippy --workspace --all-targets -- -D warnings` | Lint (warnings = errors) |
| `fmt` | `cargo fmt --all -- --check` | Format check (nightly rustfmt) |
| `deny` | `cargo-deny` | Dependency audit |

Environment: `RUSTFLAGS: -Dwarnings` (treat warnings as errors), `CARGO_TERM_COLOR: always`

All jobs install `protoc` for proto compilation.

### Release Pipeline (`.github/workflows/release.yml`)

Triggered on tag push matching `v*`:

1. **Changelog generation** via `git-cliff`
2. **Multi-platform builds**:

| Target | OS | Architecture | Asset Name |
|--------|----|-------------|------------|
| `x86_64-unknown-linux-gnu` | Ubuntu | x86_64 | `lago-linux-amd64` |
| `x86_64-apple-darwin` | macOS | x86_64 | `lago-darwin-amd64` |
| `aarch64-apple-darwin` | macOS | ARM64 | `lago-darwin-arm64` |
| `x86_64-pc-windows-msvc` | Windows | x86_64 | `lago-windows-amd64.exe` |

3. **GitHub Release** created with changelog body and binary assets

### Publishing to crates.io

```bash
# Dry run
./publish.sh

# Actual publish
./publish.sh --execute
```

Publishes crates in dependency order:
1. `lago-core` → 2. `lago-store` → 3. `lago-journal` → 4. `lago-fs` → 5. `lago-policy` → 6. `lago-ingest` → 7. `lago-api` → 8. `lagod` → 9. `lago` (CLI)

### Installation

```bash
# From GitHub releases
curl -fsSL https://github.com/broomva/lago/raw/main/install.sh | bash

# From source
cargo install --path crates/lago-cli
```

## CLI Reference

### `lago init [PATH]`

Initialize a new Lago project. Creates `.lago/` data directory, `.lago/blobs/` blob store, and `lago.toml` config file.

### `lago serve [OPTIONS]`

Start the daemon (gRPC + HTTP servers).

| Flag | Default | Description |
|------|---------|-------------|
| `--grpc-port` | `50051` | gRPC ingest port |
| `--http-port` | `8080` | HTTP/REST API port |
| `--data-dir` | `.lago` | Data directory |

### `lago session create --name NAME`

Create a new agent session. Returns session ID (ULID).

### `lago session list`

List all sessions with name, creation time, and branch count.

### `lago session show ID`

Show detailed session info including configuration and branches.

### `lago branch create --session ID --name NAME [--fork-at SEQ]`

Fork a new branch from an existing session. Defaults to forking at the current head.

### `lago branch list --session ID`

List all branches with fork points and head sequences.

### `lago log --session ID [--branch BRANCH] [--limit N] [--after SEQ]`

View the event log. Displays formatted events with type-specific fields. Default limit: 50.

### `lago cat PATH --session ID [--branch BRANCH]`

Print file contents from the virtual filesystem. Reconstructs the manifest from events and retrieves the blob.

## Daemon Configuration

`lago.toml` (TOML format):

```toml
[daemon]
grpc_port = 50051
http_port = 8080
data_dir = ".lago"

[wal]
flush_interval_ms = 100
flush_threshold = 1000

[snapshot]
interval = 10000
```

| Setting | Default | Description |
|---------|---------|-------------|
| `daemon.grpc_port` | `50051` | gRPC server port |
| `daemon.http_port` | `8080` | HTTP server port |
| `daemon.data_dir` | `.lago` | Data directory path |
| `wal.flush_interval_ms` | `100` | WAL flush interval |
| `wal.flush_threshold` | `1000` | WAL flush event threshold |
| `snapshot.interval` | `10000` | Events between snapshots |

CLI flags override config file values.

## Workspace Dependencies

All shared dependencies are declared in the root `Cargo.toml` and inherited by crates:

| Dependency | Version | Purpose |
|-----------|---------|---------|
| `serde` | 1.x | Serialization framework |
| `serde_json` | 1.x | JSON serialization |
| `ulid` | 1.x | Time-sortable unique IDs |
| `sha2` | 0.10.x | SHA-256 hashing |
| `thiserror` | 2.x | Library error types |
| `redb` | 2.x | Embedded ACID database |
| `zstd` | 0.13.x | Blob compression |
| `tokio` | 1.x | Async runtime |
| `tokio-stream` | 0.1.x | Async stream utilities |
| `futures` | 0.3.x | Future combinators |
| `tonic` | 0.14.x | gRPC framework |
| `prost` | 0.14.x | Protobuf codegen |
| `axum` | 0.8.x | HTTP framework |
| `tower` | 0.5.x | Middleware framework |
| `tower-http` | 0.6.x | HTTP middleware (CORS, trace) |
| `clap` | 4.x | CLI argument parsing |
| `toml` | 0.9.x | Config file parsing |
| `tracing` | 0.1.x | Structured logging |

## Code Style

- **Rust 2024 Edition** with MSRV 1.85
- **`rustfmt`** for formatting, **`clippy`** for linting (warnings = errors in CI)
- **snake_case** for files/functions, **PascalCase** for types, **SCREAMING_SNAKE_CASE** for constants
- **`thiserror`** for library errors, **`anyhow`** for binary errors
- No `unsafe` unless absolutely necessary
- Public API items documented with `///` doc comments

## Project Metadata

- **Version**: 0.1.0
- **License**: MIT
- **Repository**: https://github.com/broomva/lago
- **Authors**: Broomva Tech <contact@broomva.tech>
- **Keywords**: agent, event-sourcing, persistence, ai, runtime
- **Categories**: database-implementations, development-tools
