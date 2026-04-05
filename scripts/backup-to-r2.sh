#!/usr/bin/env bash
# INF-2: Lago volume backup to Cloudflare R2 (S3-compatible)
#
# Copies journal.redb and blobs/ from the Lago data directory to an
# S3-compatible bucket (Cloudflare R2, MinIO, AWS S3, etc.).
#
# Uses rclone for the transfer. Falls back to aws s3 sync if rclone
# is not available.
#
# Environment variables (required):
#   R2_ENDPOINT          — S3-compatible endpoint URL
#                          e.g. https://<account-id>.r2.cloudflarestorage.com
#   R2_BUCKET            — Target bucket name
#   R2_ACCESS_KEY_ID     — Access key ID
#   R2_SECRET_ACCESS_KEY — Secret access key
#
# Optional:
#   LAGO_DATA_DIR        — Path to Lago data directory (default: /data/.lago)
#   BACKUP_RETENTION     — Number of daily backups to keep (default: 7)
#
# Usage:
#   ./backup-to-r2.sh
#   LAGO_DATA_DIR=/tmp/lago-data ./backup-to-r2.sh
#
# Restore procedure:
#   See restore-from-r2.sh for the full restore workflow.
#
# Cron (Railway):
#   Deploy as a cron service using backup.Dockerfile with schedule "0 3 * * *".
#   See backup.Dockerfile and the Railway cron documentation section below.

set -euo pipefail

# --- Configuration -----------------------------------------------------------

LAGO_DATA_DIR="${LAGO_DATA_DIR:-/data/.lago}"
BACKUP_RETENTION="${BACKUP_RETENTION:-7}"
DATE="$(date -u +%Y-%m-%d)"
BACKUP_PREFIX="lago-backup"
REMOTE_PATH="s3://${R2_BUCKET:?R2_BUCKET is required}/${BACKUP_PREFIX}/${DATE}"

# Validate required env vars
: "${R2_ENDPOINT:?R2_ENDPOINT is required}"
: "${R2_ACCESS_KEY_ID:?R2_ACCESS_KEY_ID is required}"
: "${R2_SECRET_ACCESS_KEY:?R2_SECRET_ACCESS_KEY is required}"

echo "=== Lago Backup to R2 ==="
echo "  Date:      ${DATE}"
echo "  Source:    ${LAGO_DATA_DIR}"
echo "  Target:    ${REMOTE_PATH}"
echo "  Retention: ${BACKUP_RETENTION} days"
echo ""

# --- Validate source ----------------------------------------------------------

if [ ! -d "${LAGO_DATA_DIR}" ]; then
    echo "ERROR: Data directory not found: ${LAGO_DATA_DIR}"
    exit 1
fi

JOURNAL="${LAGO_DATA_DIR}/journal.redb"
BLOBS="${LAGO_DATA_DIR}/blobs"

if [ ! -f "${JOURNAL}" ]; then
    echo "WARNING: journal.redb not found at ${JOURNAL}"
    echo "  This may be a fresh instance with no data yet."
fi

# --- Select transfer tool -----------------------------------------------------

use_rclone() {
    command -v rclone >/dev/null 2>&1
}

use_aws_cli() {
    command -v aws >/dev/null 2>&1
}

if use_rclone; then
    TOOL="rclone"
    echo "  Tool:      rclone"
elif use_aws_cli; then
    TOOL="aws"
    echo "  Tool:      aws s3"
else
    echo "ERROR: Neither rclone nor aws CLI found. Install one of them."
    exit 1
fi

echo ""

# --- Backup with rclone -------------------------------------------------------

do_rclone_backup() {
    # Configure rclone on-the-fly via env vars (no config file needed)
    export RCLONE_CONFIG_R2_TYPE="s3"
    export RCLONE_CONFIG_R2_PROVIDER="Cloudflare"
    export RCLONE_CONFIG_R2_ACCESS_KEY_ID="${R2_ACCESS_KEY_ID}"
    export RCLONE_CONFIG_R2_SECRET_ACCESS_KEY="${R2_SECRET_ACCESS_KEY}"
    export RCLONE_CONFIG_R2_ENDPOINT="${R2_ENDPOINT}"
    export RCLONE_CONFIG_R2_ACL="private"
    export RCLONE_CONFIG_R2_NO_CHECK_BUCKET="true"

    RCLONE_DEST="r2:${R2_BUCKET}/${BACKUP_PREFIX}/${DATE}"

    # Upload journal.redb
    if [ -f "${JOURNAL}" ]; then
        echo "--- Uploading journal.redb..."
        rclone copyto "${JOURNAL}" "${RCLONE_DEST}/journal.redb" --progress
        echo "  [ok] journal.redb uploaded"
    fi

    # Upload blobs/ directory
    if [ -d "${BLOBS}" ]; then
        echo "--- Uploading blobs/..."
        rclone sync "${BLOBS}" "${RCLONE_DEST}/blobs/" --progress
        echo "  [ok] blobs/ uploaded"
    else
        echo "  [skip] blobs/ directory not found"
    fi
}

# --- Backup with aws s3 -------------------------------------------------------

do_aws_backup() {
    export AWS_ACCESS_KEY_ID="${R2_ACCESS_KEY_ID}"
    export AWS_SECRET_ACCESS_KEY="${R2_SECRET_ACCESS_KEY}"
    export AWS_DEFAULT_REGION="auto"

    S3_DEST="s3://${R2_BUCKET}/${BACKUP_PREFIX}/${DATE}"

    # Upload journal.redb
    if [ -f "${JOURNAL}" ]; then
        echo "--- Uploading journal.redb..."
        aws s3 cp "${JOURNAL}" "${S3_DEST}/journal.redb" \
            --endpoint-url "${R2_ENDPOINT}"
        echo "  [ok] journal.redb uploaded"
    fi

    # Upload blobs/ directory
    if [ -d "${BLOBS}" ]; then
        echo "--- Uploading blobs/..."
        aws s3 sync "${BLOBS}" "${S3_DEST}/blobs/" \
            --endpoint-url "${R2_ENDPOINT}"
        echo "  [ok] blobs/ uploaded"
    else
        echo "  [skip] blobs/ directory not found"
    fi
}

# --- Retention policy ----------------------------------------------------------

do_rclone_retention() {
    RCLONE_PREFIX="r2:${R2_BUCKET}/${BACKUP_PREFIX}/"

    echo ""
    echo "--- Enforcing retention policy (keep last ${BACKUP_RETENTION} backups)..."

    # List all backup date directories, sorted
    DIRS=$(rclone lsf "${RCLONE_PREFIX}" --dirs-only 2>/dev/null | sort)
    COUNT=$(echo "${DIRS}" | grep -c . 2>/dev/null || echo "0")

    if [ "${COUNT}" -le "${BACKUP_RETENTION}" ]; then
        echo "  [ok] ${COUNT} backups found, within retention limit"
        return
    fi

    # Calculate how many to remove
    REMOVE_COUNT=$((COUNT - BACKUP_RETENTION))
    echo "  Found ${COUNT} backups, removing oldest ${REMOVE_COUNT}..."

    echo "${DIRS}" | head -n "${REMOVE_COUNT}" | while IFS= read -r dir; do
        dir_name="${dir%/}"
        echo "  Deleting: ${dir_name}"
        rclone purge "${RCLONE_PREFIX}${dir_name}" 2>/dev/null || true
    done

    echo "  [ok] Retention enforced"
}

do_aws_retention() {
    export AWS_ACCESS_KEY_ID="${R2_ACCESS_KEY_ID}"
    export AWS_SECRET_ACCESS_KEY="${R2_SECRET_ACCESS_KEY}"
    export AWS_DEFAULT_REGION="auto"

    S3_PREFIX="s3://${R2_BUCKET}/${BACKUP_PREFIX}/"

    echo ""
    echo "--- Enforcing retention policy (keep last ${BACKUP_RETENTION} backups)..."

    # List unique date prefixes
    DIRS=$(aws s3 ls "${S3_PREFIX}" --endpoint-url "${R2_ENDPOINT}" 2>/dev/null \
        | awk '/PRE/{print $2}' | sed 's|/||' | sort)
    COUNT=$(echo "${DIRS}" | grep -c . 2>/dev/null || echo "0")

    if [ "${COUNT}" -le "${BACKUP_RETENTION}" ]; then
        echo "  [ok] ${COUNT} backups found, within retention limit"
        return
    fi

    REMOVE_COUNT=$((COUNT - BACKUP_RETENTION))
    echo "  Found ${COUNT} backups, removing oldest ${REMOVE_COUNT}..."

    echo "${DIRS}" | head -n "${REMOVE_COUNT}" | while IFS= read -r dir; do
        echo "  Deleting: ${dir}"
        aws s3 rm "${S3_PREFIX}${dir}/" --recursive \
            --endpoint-url "${R2_ENDPOINT}" 2>/dev/null || true
    done

    echo "  [ok] Retention enforced"
}

# --- Execute ------------------------------------------------------------------

if [ "${TOOL}" = "rclone" ]; then
    do_rclone_backup
    do_rclone_retention
else
    do_aws_backup
    do_aws_retention
fi

echo ""
echo "=== Backup complete ==="
echo "  Backup location: ${REMOTE_PATH}"
echo "  Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
