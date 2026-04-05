#!/usr/bin/env bash
# MIG-1: Asset inventory and hash mapping
#
# Scans broomva.tech static assets, computes SHA-256 hashes,
# detects MIME types, and cross-references .mdx files to find
# which posts use which assets.
#
# Output: JSON mapping {path → {hash, size, content_type, referencing_posts[]}}

set -euo pipefail

SITE_ROOT="${1:-$HOME/broomva/broomva.tech}"
ASSET_DIRS=(
    "apps/chat/public/images/writing"
    "apps/chat/public/audio/writing"
    "apps/chat/public/images/projects"
    "apps/chat/public/audio/projects"
    "apps/chat/public/audio/notes"
)
MDX_DIR="$SITE_ROOT/apps/chat/content"

echo "{"
first=true

for asset_dir in "${ASSET_DIRS[@]}"; do
    full_dir="$SITE_ROOT/$asset_dir"
    [ -d "$full_dir" ] || continue

    while IFS= read -r -d '' file; do
        # Relative path from site root
        rel_path="${file#$SITE_ROOT/}"
        # Path as referenced in MDX (from public/ root)
        public_path="/${rel_path#apps/chat/public/}"

        # SHA-256 hash
        hash=$(shasum -a 256 "$file" | awk '{print $1}')

        # File size
        size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null)

        # MIME type via file command
        mime=$(file --mime-type -b "$file")

        # Find referencing .mdx files
        refs="[]"
        if [ -d "$MDX_DIR" ]; then
            # Search for references to this asset path in .mdx files
            matching_posts=$(grep -rl "$public_path" "$MDX_DIR" 2>/dev/null || true)
            if [ -n "$matching_posts" ]; then
                refs="["
                ref_first=true
                while IFS= read -r post; do
                    post_rel="${post#$MDX_DIR/}"
                    post_slug="${post_rel%.mdx}"
                    if [ "$ref_first" = true ]; then
                        ref_first=false
                    else
                        refs="$refs,"
                    fi
                    refs="$refs\"$post_slug\""
                done <<< "$matching_posts"
                refs="$refs]"
            fi
        fi

        if [ "$first" = true ]; then
            first=false
        else
            echo ","
        fi

        printf '  "%s": {"hash": "%s", "size": %s, "content_type": "%s", "public_path": "%s", "referencing_posts": %s}' \
            "$rel_path" "$hash" "$size" "$mime" "$public_path" "$refs"

    done < <(find "$full_dir" -type f -print0 | sort -z)
done

echo ""
echo "}"
