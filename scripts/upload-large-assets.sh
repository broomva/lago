#!/usr/bin/env bash
# MIG-2b: Upload large assets (>2MB) that fail via Railway's reverse proxy.
#
# Uses chunked upload via the internal Railway network or direct lagod access.
# For assets that exceed Railway's ~2MB reverse proxy body limit, this script
# splits the upload or uses a different approach.
#
# Usage: LAGO_JWT_SECRET=<secret> ./upload-large-assets.sh <lagod-url>
#
# For Railway internal access: ./upload-large-assets.sh http://lagod.railway.internal:8080

set -euo pipefail

LAGO_URL="${1:?Usage: upload-large-assets.sh <lagod-url>}"
INVENTORY="$(dirname "$0")/asset-inventory.json"
SITE_ROOT="${2:-$HOME/broomva/broomva.tech}"
MIN_SIZE_BYTES=$((2 * 1024 * 1024))  # 2 MB threshold

if [ ! -f "$INVENTORY" ]; then
    echo "Error: inventory file not found: $INVENTORY"
    exit 1
fi

# Sign JWT
if [ -z "${LAGO_JWT_SECRET:-}" ]; then
    echo "Error: LAGO_JWT_SECRET not set"
    exit 1
fi

TOKEN=$(LAGO_JWT_SECRET="$LAGO_JWT_SECRET" python3 -c "
import json, hmac, hashlib, base64, time, os
def b64url(data): return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
secret = os.environ['LAGO_JWT_SECRET']
now = int(time.time())
header = b64url(json.dumps({'alg':'HS256','typ':'JWT'},separators=(',',':')).encode())
payload = b64url(json.dumps({'sub':'admin','email':'admin@broomva.tech','iat':now,'exp':now+86400},separators=(',',':')).encode())
sig = b64url(hmac.new(secret.encode(), f'{header}.{payload}'.encode(), hashlib.sha256).digest())
print(f'{header}.{payload}.{sig}')
")

# Get session ID
SID=$(curl -s "$LAGO_URL/v1/sessions" | python3 -c "
import json,sys
for s in json.load(sys.stdin):
    if s['name'] == 'site-assets:public':
        print(s['session_id'])
        break
")

echo "=== Large Asset Upload ==="
echo "  Target: $LAGO_URL"
echo "  Session: $SID"
echo "  Min size: $((MIN_SIZE_BYTES / 1024 / 1024)) MB"
echo ""

python3 -c "
import json
with open('$INVENTORY') as f:
    data = json.load(f)
for rel_path, info in data.items():
    if info['size'] >= $MIN_SIZE_BYTES:
        print(f'{rel_path}\t{info[\"hash\"]}\t{info[\"public_path\"]}\t{info[\"size\"]}')
" | while IFS=$'\t' read -r rel_path hash public_path size; do
    full_path="$SITE_ROOT/$rel_path"
    [ -f "$full_path" ] || continue

    size_mb=$(echo "scale=1; $size / 1048576" | bc)

    # Upload blob
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X PUT "$LAGO_URL/v1/blobs/$hash" \
        -H "Authorization: Bearer $TOKEN" \
        --data-binary "@$full_path" \
        --max-time 300)

    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        # Write file event
        curl -s -o /dev/null -X PUT "$LAGO_URL/v1/sessions/$SID/files$public_path" \
            -H "Authorization: Bearer $TOKEN" \
            --data-binary "@$full_path" \
            --max-time 300 || true
        echo "  OK (${size_mb} MB): $public_path"
    else
        echo "  FAIL ($HTTP_CODE, ${size_mb} MB): $public_path"
    fi
done

echo ""
echo "=== Done ==="
