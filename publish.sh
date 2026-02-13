#!/bin/bash
set -e

# Order is important due to dependencies
CRATES=(
    "crates/lago-core"
    "crates/lago-store"
    "crates/lago-journal"
    "crates/lago-fs"
    "crates/lago-policy"
    "crates/lago-ingest"
    "crates/lago-api"
    "crates/lagod"
    "crates/lago-cli"
)

echo "Publishing Lago crates to crates.io..."

for crate in "${CRATES[@]}"; do
    echo "Processing $crate..."
    (cd "$crate" && cargo publish --dry-run)
    # To actually publish, run with --execute argument
    if [[ "$1" == "--execute" ]]; then
        echo "Publishing $crate..."
        (cd "$crate" && cargo publish)
        # Wait a bit for crates.io index to update
        sleep 20
    else
        echo "Dry run successful for $crate. Use --execute to publish."
    fi
done

echo "Done!"
