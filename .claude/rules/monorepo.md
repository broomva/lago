# Workspace Conventions

## Crate Dependency Order (bottom-up)

```
lago-core        (zero deps — foundation types, traits, errors)
lago-store       (depends on lago-core)
lago-journal     (depends on lago-core)
lago-fs          (depends on lago-core)
lago-policy      (depends on lago-core)
lago-knowledge   (depends on lago-core, lago-store)
lago-auth        (depends on lago-core, axum, jsonwebtoken)
lago-ingest      (depends on lago-core, lago-journal)
lago-api         (depends on lago-core, lago-journal, lago-store, lago-fs, lago-policy, lago-knowledge, lago-auth)
lago-cli         (depends on lago-api, lago-journal, lago-store)
lagod            (depends on all crates — daemon binary)
```

## Rules

- **lago-core is dependency-free**: Never add external deps to lago-core beyond std + serde + ulid + thiserror.
- **Binary crates** (`lago-cli`, `lagod`) may use `anyhow`; library crates use `thiserror`.
- **Workspace dependencies**: All shared deps are declared in the root `Cargo.toml` `[workspace.dependencies]` and inherited via `{ workspace = true }`.
- **Build scope**: Always use `--workspace` for build/test/clippy commands.
- **Proto files**: Live in `proto/lago/v1/`, compiled by `lago-ingest/build.rs`.
