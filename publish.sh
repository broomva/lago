#!/bin/bash
set -euo pipefail

# Publish order respects the dependency graph.
# cargo waits for index availability automatically (no manual sleep needed).
CRATES=(
    lago-core
    lago-store
    lago-journal
    lago-fs
    lago-policy
    lago-ingest
    lago-api
    lagod
    lago
)

DRY_RUN=true
if [[ "${1:-}" == "--execute" ]]; then
    DRY_RUN=false
fi

echo "Publishing Lago crates to crates.io..."
echo ""

for crate in "${CRATES[@]}"; do
    if $DRY_RUN; then
        echo "=== $crate (dry run) ==="
        cargo publish -p "$crate" --dry-run --allow-dirty 2>&1 || true
    else
        echo "=== Publishing $crate ==="
        cargo publish -p "$crate"
    fi
    echo ""
done

if $DRY_RUN; then
    echo "Dry run complete. Use --execute to publish for real."
else
    echo "All crates published!"
fi
