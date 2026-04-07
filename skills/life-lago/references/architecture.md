# life-lago Architecture

## Two-Access-Path Model

The Lago knowledge substrate is accessible through two complementary paths,
ensuring every agent -- whether native Rust or external CLI-based -- can
read, write, search, and maintain the knowledge graph.

### Path 1: Native Rust (Life/Arcan agents)

Arcan and other Life ecosystem agents link directly against the Lago Rust
crates. This path offers:

- **Zero-copy access** to MemCubes, BlobStore, and the KnowledgeIndex
- **In-process event emission** via lago-journal (no network hop)
- **Full type safety** through aios-protocol event kinds
- **Sub-millisecond search** via the in-memory BM25 + graph index

```
Arcan agent loop
  |
  +-- arcan-lago bridge
        |
        +-- lago-knowledge   (search, lint, ingest, index)
        +-- lago-store        (blob put/get)
        +-- lago-journal      (event append/read)
        +-- lago-fs           (manifest + branching)
```

### Path 2: Skill CLI (Claude Code, Codex, Cursor, etc.)

External agents invoke the `lago wiki` CLI commands. The skill translates
each command into the equivalent Rust API call, serializing results as
markdown for LLM consumption.

```
External agent (Claude Code)
  |
  +-- `lago wiki search "event sourcing"`
        |
        +-- lago-cli binary
              |
              +-- lago-knowledge::search_hybrid()
              +-- format as markdown table
              +-- stdout
```

### Why two paths?

The native path is optimized for tight integration within the Life agent
loop -- events flow synchronously, search results are typed structs, and
the agent can chain operations without serialization overhead.

The CLI path democratizes access: any agent with shell access can operate
on the knowledge substrate without compiling Rust code. The markdown output
is designed for LLM context windows (structured, concise, token-efficient).

Both paths share the same underlying data: the BlobStore, KnowledgeIndex,
and Journal are the single source of truth regardless of access method.

## Data Flow

```
Source document (JSONL / Markdown / PlainText)
  |
  +-- lago-knowledge::ingest
        |
        +-- detect_format()     -- identify source type
        +-- chunk (strategy)    -- split into pieces
        +-- noise_filter()      -- drop system reminders, tool results
        +-- redact_pii()        -- strip API keys, tokens
        |
        +-- Vec<MemCube>
              |
              +-- BlobStore.put()            -- content-addressed storage
              +-- Journal.append()           -- ObservationAppended event
              +-- KnowledgeIndex.rebuild()   -- update search index
```

## Filesystem Fallback

When the Lago daemon is unavailable (no LAGO_URL, localhost:3001 not
responding), the skill degrades gracefully to direct filesystem operations:

| Operation | Daemon mode | Fallback mode |
|---|---|---|
| search | BM25 + graph hybrid | grep over wiki/ directory |
| read | KnowledgeIndex.get_note() | cat wiki/{slug}.md |
| write | BlobStore + manifest + event | write to wiki/{slug}.md |
| lint | KnowledgeIndex.lint() | basic wikilink check via regex |
| ingest | Full pipeline with MemCubes | Copy to raw/ + index rebuild |

The fallback ensures agents are never blocked by infrastructure issues.
When the daemon comes back online, a reconciliation pass imports any
filesystem-only changes into the event journal.

## Event Lifecycle

Every write operation follows the two-phase commit pattern from aios-protocol:

1. **Propose**: `MemoryProposed` event with content hash and metadata
2. **Commit**: `MemoryCommitted` event after successful blob store write
3. **Index**: KnowledgeIndex rebuilds to include the new content

Read operations (search, read, wake-up) are side-effect-free and emit no events.

Lint and query operations may emit `StateEstimated` or `MemoryCommitted`
events respectively, depending on whether they produce actionable output.
