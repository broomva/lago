# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-01-01

### Features

- Event-sourced journal backed by redb
- Content-addressed blob storage with SHA-256 and zstd compression
- Filesystem manifest with branching and diffing
- gRPC bidirectional streaming ingest via tonic
- HTTP REST API + SSE streaming via axum
- Multi-format SSE adapters (OpenAI, Anthropic, Vercel AI SDK, Lago)
- Policy engine with rule-based tool governance and RBAC
- CLI tool for session management
- Daemon binary with configurable TOML settings

### Initial Release

- 9 workspace crates with clear dependency hierarchy
- 187 passing tests across all crates
- Proto definitions for common types and ingest service
