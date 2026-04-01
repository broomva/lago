# Lago Lakehouse Architecture — Delta Lake + DuckDB + Lance

> **Date**: 2026-04-01
> **Status**: Proposed
> **Vision**: Lago is the AI-native lakehouse — Delta Lake for agent data, DuckDB for analytics, Lance for vectors.

## Strategic Position

```
Databricks analogy:
  Spark          = Life/Arcan (compute engine)
  Delta Lake     = lago-delta (storage layer)
  Unity Catalog  = lago-knowledge (metadata + search)
  Databricks SQL = lago-query / DuckDB (analytical queries)
  Mosaic ML      = Lance vectors (embeddings + similarity)
  Platform       = lago-platform (managed SaaS)
```

Lago replaces the entire Databricks stack for **agentic data workloads** — event journals, session replay, governed memory, knowledge graphs, vector search, cross-session analytics.

## Current State (redb)

```
lago-journal (RedbJournal)
  ├── Single-process exclusive lock
  ├── Key-value range scans only
  ├── No time travel
  ├── No concurrent access
  ├── No columnar compression
  ├── No SQL queries
  └── No vector search
```

redb served as a solid prototype — ACID, crash-safe, pure Rust. But it's a key-value store, not a lakehouse.

## Target State (Delta + DuckDB + Lance)

```
lago-delta (DeltaJournal)
  ├── Multi-writer via optimistic concurrency (no file locks)
  ├── Parquet columnar storage (10-100x compression)
  ├── Time travel (session replay = read at version N)
  ├── ACID transactions
  ├── Schema evolution (new event fields without breaking old data)
  └── Ecosystem: DuckDB, Spark, Polars, DataFusion all read natively

lago-query (DuckDB)
  ├── Full analytical SQL over Delta tables
  ├── Cross-session aggregations
  ├── Window functions, joins, CTEs
  ├── Embedded (no server needed)
  └── Parquet-native (zero copy from Delta)

lago-vectors (Lance)
  ├── AI-native vector store
  ├── Embedding storage + ANN search
  ├── Version-controlled (like Delta for vectors)
  ├── Metadata filtering + vector search combined
  └── DataFusion integration (SQL + vectors)
```

## Crate Architecture

```
lago-core (traits, types, errors — unchanged)
│
├── lago-delta           ← NEW: Delta Lake storage backend
│   ├── DeltaJournal         implements Journal trait
│   ├── DeltaEventStore      Parquet-backed event table
│   ├── Schema definitions   EventEnvelope → Arrow schema
│   └── Time travel API      read_at_version(), history()
│
├── lago-query           ← NEW: DuckDB analytical engine
│   ├── QueryEngine          SQL over Delta tables
│   ├── SessionAnalytics     cross-session aggregations
│   ├── CostAnalytics        token/cost tracking
│   └── EventSearch          full-text search on events
│
├── lago-vectors         ← NEW: Lance vector store
│   ├── VectorStore          embedding storage + ANN
│   ├── MemoryIndex          semantic search over memories
│   ├── EventEmbedder        embed events for search
│   └── KnowledgeVectors     embed knowledge graph nodes
│
├── lago-journal         ← KEEP: RedbJournal (backward compat)
│   └── Deprecated for new deployments, still works
│
├── lago-store           ← KEEP: Blob storage (SHA-256 + zstd)
│
├── lago-knowledge       ← KEEP: Knowledge index (frontmatter, wikilinks)
│   └── Future: backed by Lance vectors for semantic search
│
├── lago-api             ← EVOLVE: REST + SSE + SQL endpoint
│   └── Add /v1/query for DuckDB SQL queries
│
└── lago-fs              ← KEEP: Filesystem manifests
```

## Delta Lake Event Schema

```sql
-- Events table (append-only Delta table)
CREATE TABLE events (
    event_id        VARCHAR PRIMARY KEY,  -- ULID
    session_id      VARCHAR NOT NULL,
    branch_id       VARCHAR NOT NULL,
    seq             BIGINT NOT NULL,
    timestamp_us    BIGINT NOT NULL,      -- microseconds since epoch
    parent_id       VARCHAR,
    run_id          VARCHAR,
    schema_version  INT DEFAULT 1,

    -- Event payload (typed)
    event_type      VARCHAR NOT NULL,     -- 'message', 'tool_call_completed', 'memory_proposed', etc.
    payload         VARCHAR NOT NULL,     -- JSON-encoded EventPayload

    -- Metadata
    metadata        VARCHAR,              -- JSON key-value pairs

    -- Partitioning
    dt              DATE GENERATED ALWAYS AS (CAST(FROM_UNIXTIME(timestamp_us / 1000000) AS DATE))
)
PARTITIONED BY (dt, session_id);

-- Sessions table
CREATE TABLE sessions (
    session_id      VARCHAR PRIMARY KEY,
    config_json     VARCHAR NOT NULL,
    created_at      BIGINT NOT NULL,
    branches        VARCHAR NOT NULL      -- JSON array of branch IDs
);
```

**Partitioning by date + session_id** enables efficient pruning for session replay (only read one session's partition) and time-range queries.

## DuckDB Analytics Examples

```sql
-- Total cost across all sessions this week
SELECT
    session_id,
    COUNT(*) as events,
    SUM(CAST(json_extract(payload, '$.token_usage.total_tokens') AS INT)) as total_tokens,
    SUM(CAST(json_extract(payload, '$.token_usage.prompt_tokens') AS INT)) * 3.0 / 1e6 +
    SUM(CAST(json_extract(payload, '$.token_usage.completion_tokens') AS INT)) * 15.0 / 1e6 as cost_usd
FROM events
WHERE event_type = 'message'
    AND json_extract(payload, '$.role') = 'assistant'
    AND dt >= CURRENT_DATE - INTERVAL 7 DAY
GROUP BY session_id
ORDER BY cost_usd DESC;

-- Tool usage patterns
SELECT
    json_extract_string(payload, '$.tool_name') as tool,
    COUNT(*) as calls,
    AVG(CAST(json_extract(payload, '$.duration_ms') AS DOUBLE)) as avg_ms,
    SUM(CASE WHEN event_type = 'tool_call_failed' THEN 1 ELSE 0 END) as failures
FROM events
WHERE event_type IN ('tool_call_completed', 'tool_call_failed')
GROUP BY tool
ORDER BY calls DESC;

-- Memory evolution over time
SELECT
    dt,
    json_extract_string(payload, '$.role') as memory_type,
    COUNT(*) as entries
FROM events
WHERE event_type = 'memory_committed'
GROUP BY dt, memory_type
ORDER BY dt;
```

## Lance Vector Search Examples

```rust
// Semantic search over all memories
let results = vector_store.search(
    "authentication middleware pattern",
    SearchOptions {
        limit: 10,
        filter: "event_type = 'memory_committed'",
        metric: DistanceMetric::Cosine,
    }
).await?;

// Find similar sessions
let results = vector_store.search(
    session_embedding,
    SearchOptions {
        limit: 5,
        filter: "event_type = 'session_summary'",
    }
).await?;
```

## Journal Trait Implementation

```rust
// lago-delta/src/journal.rs
pub struct DeltaJournal {
    table_path: PathBuf,
    runtime: tokio::runtime::Handle,
}

impl DeltaJournal {
    pub async fn open(path: impl AsRef<Path>) -> LagoResult<Self> {
        // Open or create Delta table with event schema
        let table = deltalake::open_table(path.as_ref()).await
            .or_else(|_| create_events_table(path.as_ref())).await?;
        Ok(Self { table_path: path.as_ref().to_path_buf(), runtime: Handle::current() })
    }
}

impl Journal for DeltaJournal {
    fn append(&self, event: EventEnvelope) -> BoxFuture<'_, LagoResult<SeqNo>> {
        Box::pin(async move {
            // Convert EventEnvelope → Arrow RecordBatch
            let batch = event_to_record_batch(&event)?;
            // Append to Delta table (optimistic concurrency, no locks)
            let mut writer = deltalake::writer::RecordBatchWriter::for_table(&self.table)?;
            writer.write(batch).await?;
            writer.flush_and_commit(&mut self.table).await?;
            Ok(event.seq)
        })
    }

    fn read(&self, query: EventQuery) -> BoxFuture<'_, LagoResult<Vec<EventEnvelope>>> {
        Box::pin(async move {
            // Use DataFusion to query the Delta table
            let ctx = SessionContext::new();
            let table = deltalake::open_table(&self.table_path).await?;
            ctx.register_table("events", Arc::new(table))?;

            let sql = build_query_sql(&query);
            let df = ctx.sql(&sql).await?;
            let batches = df.collect().await?;

            record_batches_to_events(batches)
        })
    }

    // Time travel — unique to Delta
    fn read_at_version(&self, query: EventQuery, version: i64) -> BoxFuture<'_, LagoResult<Vec<EventEnvelope>>> {
        Box::pin(async move {
            let table = deltalake::open_table_with_version(&self.table_path, version).await?;
            // ... query at that version
        })
    }
}
```

## Migration Path

### Phase 1: lago-delta crate (foundation)
- Implement `DeltaJournal` with `Journal` trait
- Arrow schema for `EventEnvelope`
- Parquet read/write
- DataFusion SQL queries
- Time travel API
- Tests: parity with RedbJournal test suite

### Phase 2: Wire into arcan
- Shared workspace journal uses `DeltaJournal`
- Per-session journals keep `RedbJournal` (or migrate to Delta too)
- Config: `journal_backend = "delta" | "redb"`

### Phase 3: lago-query (DuckDB analytics)
- SQL endpoint on lago-api
- Cross-session analytics
- Cost tracking, tool usage patterns
- CLI: `lago query "SELECT ..."`

### Phase 4: lago-vectors (Lance)
- Embed events and memories
- Semantic search API
- Knowledge graph vectorization
- CLI: `lago search "authentication patterns"`

### Phase 5: lago-platform integration
- Delta tables readable by external tools (Spark, Polars, pandas)
- S3-compatible object storage backend
- Catalog API (Unity Catalog equivalent)
- Multi-tenant isolation

## Dependencies

```toml
# lago-delta
[dependencies]
deltalake = { version = "0.24", features = ["datafusion"] }
arrow = "54"
parquet = "54"
datafusion = "44"
tokio = { version = "1", features = ["full"] }

# lago-query
[dependencies]
duckdb = "1.2"

# lago-vectors
[dependencies]
lance = "0.20"
lance-index = "0.20"
```

## Why This Matters

Every AI agent system needs:
1. **Event history** — what happened (Delta: append-only, time travel)
2. **Analytics** — what patterns emerge (DuckDB: SQL over events)
3. **Semantic search** — find relevant context (Lance: vector ANN)
4. **Shared state** — multiple agents collaborate (Delta: multi-writer)

No existing platform provides all four for agentic workloads. Lago does.

This is the **Databricks for agents** — the storage and analytics layer that makes agent systems production-ready.
