---
name: life-lago
description: Agent-facing interface to the Lago knowledge substrate. Provides Karpathy-style wiki operations (ingest, search, read, write, lint, wake-up, query) on top of Lago's event-sourced, content-addressed filesystem.
version: 0.1.0
---

# life-lago -- Lago Knowledge Substrate Skill

Universal agent brain stem built on Lago's event-sourced persistence layer.

## Operations

| Command | Description | Lago Primitive | Event Emitted |
|---|---|---|---|
| `lago wiki init` | Initialize a wiki session | Create session + BlobStore + KnowledgeIndex | SessionCreated |
| `lago wiki ingest <path>` | Ingest source document | lago-knowledge ingest -> BlobStore.put -> index rebuild | ObservationAppended |
| `lago wiki search <query>` | Hybrid search (BM25 + graph) | KnowledgeIndex.search_hybrid() | -- |
| `lago wiki read <slug>` | Read entity page with provenance | KnowledgeIndex.get_note() | -- |
| `lago wiki write <slug>` | Create/update wiki page | BlobStore.put -> manifest update -> index rebuild | MemoryProposed -> MemoryCommitted |
| `lago wiki lint` | Check health (contradictions, orphans, gaps) | KnowledgeIndex.lint() | StateEstimated |
| `lago wiki wake-up` | Assemble L0+L1 context (~900 tokens) | MemCube::assemble() + generate_index() | -- |
| `lago wiki log` | Show recent knowledge operations | Journal.read() filtered to knowledge events | -- |
| `lago wiki query <q>` | Search, synthesize, optionally file back | search + optional MemoryCommitted | MemoryCommitted (if filed) |
| `lago wiki diff` | Show what changed since last session | diff_manifests() | -- |

## Three-Layer Model

| Layer | Directory | Lago Backing | Mutability |
|---|---|---|---|
| Raw Sources | `raw/` | BlobStore (SHA-256 + zstd, immutable) | Never modified |
| Wiki | `wiki/` | KnowledgeIndex + MemCubes | LLM-maintained via write |
| Schema | `CLAUDE.md` + `.control/` | Policy gates + setpoints | Co-evolved by user + LLM |

## Graceful Degradation

When the Lago daemon isn't running, all operations fall back to direct filesystem access on markdown files. The skill detects Lago availability by checking LAGO_URL or localhost:3001.

## Access Model

- **Life/Arcan agents**: Native Rust access via lago-knowledge crate
- **Any other agent** (Claude Code, Codex, Cursor): This skill provides the same capabilities through CLI commands + markdown output

## Event Protocol

All write operations emit canonical aios-protocol EventKind events:
- `ObservationAppended` for new knowledge ingested
- `MemoryProposed` -> `MemoryCommitted` for wiki page writes
- `PolicyEvaluated` for Nous gate scoring decisions
- `StateEstimated` for lint health assessments

## Integration with Control Kernel

The knowledge substrate feeds the control loop:
- **Belief state** includes wiki context from wake-up + relevant entity pages
- **Nous evaluators** score knowledge operations (freshness, coherence, coverage, provenance)
- **EGRI** can optimize scoring thresholds, search weights, and promotion criteria
- **Policy gates** enforce knowledge governance (no entity without provenance, no promotion below Nous gate)

## Configuration

Environment variables:
- `LAGO_URL` -- Lago daemon URL (default: http://localhost:3001)
- `LAGO_DATA_DIR` -- Data directory for standalone mode
- `LAGO_WIKI_DIR` -- Wiki directory for filesystem fallback

## Dependencies

Rust crates used:
- `lago-knowledge` (BM25, graph, lint, index, ingest)
- `lago-core` (MemCubes, events, cognitive types)
- `lago-store` (BlobStore, manifest diff)
- `lago-journal` (event persistence)
