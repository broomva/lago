# Security Rules

## Secrets & Configuration

- Never commit `.env`, credentials, or API keys.
- Use environment variables for runtime secrets, not hardcoded values.
- Never log secrets or tokens at any log level.

## Input Validation

- Validate all external input at system boundaries (gRPC handlers, HTTP endpoints, CLI args).
- Use strong types rather than raw strings for IDs (ULID), paths, and keys.
- Bound all user-supplied sizes (event payloads, blob sizes) to prevent resource exhaustion.

## Storage

- redb transactions provide ACID guarantees — do not bypass with raw file I/O.
- Content-addressed blobs are immutable after write; never allow overwrite by hash.
- Sanitize file paths in `lago-fs` to prevent path traversal.

## Dependencies

- Prefer pure-Rust crates to minimize supply chain risk.
- Audit new dependencies before adding (`cargo audit`).
- Pin workspace dependency versions in root `Cargo.toml`.
