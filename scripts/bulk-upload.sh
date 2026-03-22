#!/usr/bin/env bash
# MIG-2: Bulk upload assets to lagod
#
# Reads the asset inventory JSON and uploads all assets to lagod,
# creating the site-assets:public session and emitting FileWrite events.
#
# Usage: ./bulk-upload.sh <lagod-url> [inventory-json]
#
# Example: ./bulk-upload.sh https://lago.broomva.tech scripts/asset-inventory.json

set -euo pipefail

LAGO_URL="${1:?Usage: bulk-upload.sh <lagod-url> [inventory-json]}"
INVENTORY="${2:-$(dirname "$0")/asset-inventory.json}"
SITE_ROOT="${3:-$HOME/broomva/broomva.tech}"

if [ ! -f "$INVENTORY" ]; then
    echo "Error: inventory file not found: $INVENTORY"
    echo "Run asset-inventory.sh first to generate it."
    exit 1
fi

echo "=== Lago Bulk Asset Upload ==="
echo "  Target:    $LAGO_URL"
echo "  Inventory: $INVENTORY"
echo "  Site root: $SITE_ROOT"
echo ""

# Step 1: Create the site-assets:public session
echo "--- Creating session: site-assets:public"
SESSION_RESP=$(curl -s -X POST "$LAGO_URL/v1/sessions" \
    -H "Content-Type: application/json" \
    -d '{"name": "site-assets:public"}')
SESSION_ID=$(echo "$SESSION_RESP" | python3 -c "import json,sys; print(json.load(sys.stdin).get('session_id',''))" 2>/dev/null || echo "")

if [ -z "$SESSION_ID" ]; then
    echo "  Session may already exist, continuing..."
    # Try to find existing session
    SESSION_ID=$(curl -s "$LAGO_URL/v1/sessions" | \
        python3 -c "import json,sys; sessions=json.load(sys.stdin); matches=[s for s in sessions if s['name']=='site-assets:public']; print(matches[0]['session_id'] if matches else '')" 2>/dev/null || echo "")
    if [ -z "$SESSION_ID" ]; then
        echo "  Error: could not create or find session"
        exit 1
    fi
fi
echo "  Session ID: $SESSION_ID"

# Step 2: Upload each asset
TOTAL=$(python3 -c "import json; d=json.load(open('$INVENTORY')); print(len(d))")
UPLOADED=0
SKIPPED=0
FAILED=0

echo ""
echo "--- Uploading $TOTAL assets..."
echo ""

python3 -c "
import json
with open('$INVENTORY') as f:
    data = json.load(f)
for rel_path, info in data.items():
    print(f'{rel_path}\t{info[\"hash\"]}\t{info[\"public_path\"]}\t{info[\"content_type\"]}')
" | while IFS=$'\t' read -r rel_path hash public_path content_type; do
    full_path="$SITE_ROOT/$rel_path"

    if [ ! -f "$full_path" ]; then
        echo "  SKIP (missing): $rel_path"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    # Upload blob
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X PUT "$LAGO_URL/v1/blobs/$hash" \
        -H "Content-Type: application/octet-stream" \
        --data-binary "@$full_path")

    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        echo "  OK: $public_path ($hash)"
    else
        echo "  FAIL ($HTTP_CODE): $public_path"
        FAILED=$((FAILED + 1))
        continue
    fi

    # Emit FileWrite event
    curl -s -o /dev/null -X PUT "$LAGO_URL/v1/sessions/$SESSION_ID/files/$public_path" \
        -H "Content-Type: application/octet-stream" \
        --data-binary "@$full_path" || true

    UPLOADED=$((UPLOADED + 1))
done

echo ""
echo "=== Upload complete ==="
echo "  Uploaded: $UPLOADED"
echo "  Skipped:  $SKIPPED"
echo "  Failed:   $FAILED"
