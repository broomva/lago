#!/usr/bin/env bash
# MIG-4: Remove migrated static assets from git
#
# ONLY RUN AFTER verifying all content renders correctly from Lago (1+ week soak).
#
# Prerequisites:
#   1. All assets uploaded to lagod (MIG-2 complete)
#   2. Content transformer active in broomva.tech (MIG-3 verified)
#   3. Blog posts render correctly with Lago-served assets
#   4. No broken images/audio reported for 1+ week
#
# This script:
#   1. Adds asset directories to .gitignore
#   2. Removes cached files from git tracking
#   3. Creates a commit (does NOT push — review first)

set -euo pipefail

SITE_ROOT="${1:-$HOME/broomva/broomva.tech}"

echo "=== MIG-4: Remove Static Assets from Git ==="
echo ""
echo "WARNING: This removes ~170 MB of static assets from git tracking."
echo "Assets will be served from Lago (lago.broomva.tech) instead."
echo ""
echo "Press Enter to continue or Ctrl+C to abort..."
read -r

cd "$SITE_ROOT"

# Step 1: Add to .gitignore
echo "--- Adding to .gitignore ---"
cat >> .gitignore << 'EOF'

# Static assets migrated to Lago (lago.broomva.tech)
# See: core/life/lago/docs/RUNBOOK.md
apps/chat/public/images/writing/
apps/chat/public/audio/writing/
apps/chat/public/images/projects/
apps/chat/public/audio/projects/
apps/chat/public/audio/notes/
EOF
echo "  .gitignore updated"

# Step 2: Remove from git tracking (keeps files on disk)
echo "--- Removing from git tracking ---"
git rm -r --cached apps/chat/public/images/writing/ 2>/dev/null || true
git rm -r --cached apps/chat/public/audio/writing/ 2>/dev/null || true
git rm -r --cached apps/chat/public/images/projects/ 2>/dev/null || true
git rm -r --cached apps/chat/public/audio/projects/ 2>/dev/null || true
git rm -r --cached apps/chat/public/audio/notes/ 2>/dev/null || true

echo ""
echo "--- Git status ---"
git status --short | head -20
echo ""

SIZE_BEFORE=$(git count-objects -v | grep size-pack | awk '{print $2}')
echo "Current pack size: ${SIZE_BEFORE} KB"
echo ""
echo "=== Done ==="
echo ""
echo "Review the changes, then commit:"
echo "  git add .gitignore"
echo "  git commit -m 'chore: remove static assets from git (served from Lago)'"
echo ""
echo "After pushing, run 'git gc --aggressive' to reclaim space."
