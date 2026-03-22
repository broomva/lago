#!/usr/bin/env bash
# INT-2: Ingest site content (MDX files) into lagod for RAG search
#
# Creates a site-content:public session and uploads all .mdx files
# from broomva.tech's content directories into it.
#
# Usage: ./ingest-site-content.sh <lagod-url> [site-root]

set -euo pipefail

LAGO_URL="${1:?Usage: ingest-site-content.sh <lagod-url> [site-root]}"
SITE_ROOT="${2:-$HOME/broomva/broomva.tech}"
CONTENT_DIR="$SITE_ROOT/apps/chat/content"

echo "=== Lago Site Content Ingestion ==="
echo "  Target:  $LAGO_URL"
echo "  Content: $CONTENT_DIR"
echo ""

# Step 1: Create session
echo "--- Creating session: site-content:public"
curl -s -X POST "$LAGO_URL/v1/sessions" \
    -H "Content-Type: application/json" \
    -d '{"name": "site-content:public"}' > /dev/null 2>&1 || true

# Find session ID
SESSION_ID=$(curl -s "$LAGO_URL/v1/sessions" | \
    python3 -c "import json,sys; sessions=json.load(sys.stdin); matches=[s for s in sessions if s['name']=='site-content:public']; print(matches[0]['session_id'] if matches else '')" 2>/dev/null || echo "")

if [ -z "$SESSION_ID" ]; then
    echo "Error: could not find site-content:public session"
    exit 1
fi
echo "  Session ID: $SESSION_ID"
echo ""

# Step 2: Upload all .mdx files
TOTAL=0
UPLOADED=0

for kind in writing projects notes prompts; do
    kind_dir="$CONTENT_DIR/$kind"
    [ -d "$kind_dir" ] || continue

    echo "--- Processing: $kind/"

    for file in "$kind_dir"/*.mdx "$kind_dir"/*.md; do
        [ -f "$file" ] || continue
        TOTAL=$((TOTAL + 1))

        filename=$(basename "$file")
        virtual_path="/$kind/$filename"

        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
            -X PUT "$LAGO_URL/v1/sessions/$SESSION_ID/files/$virtual_path" \
            -H "Content-Type: text/markdown" \
            --data-binary "@$file")

        if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
            echo "  OK: $virtual_path"
            UPLOADED=$((UPLOADED + 1))
        else
            echo "  FAIL ($HTTP_CODE): $virtual_path"
        fi
    done
done

echo ""
echo "=== Ingestion complete ==="
echo "  Total:    $TOTAL"
echo "  Uploaded: $UPLOADED"
