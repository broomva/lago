#!/usr/bin/env bash
# INF-2: Lago volume restore from Cloudflare R2 (S3-compatible)
#
# Downloads the latest (or specified) backup from R2 and restores
# journal.redb and blobs/ to the Lago data directory.
#
# IMPORTANT: Stop lagod before restoring. The journal.redb file must not
# be written to by lagod during a restore.
#
# Environment variables (required):
#   R2_ENDPOINT          — S3-compatible endpoint URL
#   R2_BUCKET            — Source bucket name
#   R2_ACCESS_KEY_ID     — Access key ID
#   R2_SECRET_ACCESS_KEY — Secret access key
#
# Optional:
#   LAGO_DATA_DIR        — Path to Lago data directory (default: /data/.lago)
#
# Usage:
#   # Restore from the latest backup:
#   ./restore-from-r2.sh
#
#   # Restore from a specific date:
#   ./restore-from-r2.sh 2026-03-15
#
# Full restore procedure (Railway):
#   1. Scale lagod service to 0 replicas (or stop the service)
#   2. SSH into the volume or run this script from a one-off Railway service:
#        railway run --service lago-backup ./scripts/restore-from-r2.sh
#   3. Verify the restored files:
#        ls -la /data/.lago/journal.redb
#        ls -la /data/.lago/blobs/
#   4. Scale lagod back to 1 replica
#   5. Verify health: curl https://lago.broomva.tech/health
#
# Full restore procedure (local development):
#   1. Stop the local lagod process
#   2. Run: LAGO_DATA_DIR=/tmp/lago-data ./restore-from-r2.sh
#   3. Start lagod with --data-dir /tmp/lago-data

set -euo pipefail

# --- Configuration -----------------------------------------------------------

LAGO_DATA_DIR="${LAGO_DATA_DIR:-/data/.lago}"
BACKUP_PREFIX="lago-backup"
RESTORE_DATE="${1:-}"   # Optional: specific date to restore (YYYY-MM-DD)

# Validate required env vars
: "${R2_ENDPOINT:?R2_ENDPOINT is required}"
: "${R2_BUCKET:?R2_BUCKET is required}"
: "${R2_ACCESS_KEY_ID:?R2_ACCESS_KEY_ID is required}"
: "${R2_SECRET_ACCESS_KEY:?R2_SECRET_ACCESS_KEY is required}"

echo "=== Lago Restore from R2 ==="
echo "  Target dir: ${LAGO_DATA_DIR}"
echo ""

# --- Select transfer tool -----------------------------------------------------

use_rclone() {
    command -v rclone >/dev/null 2>&1
}

use_aws_cli() {
    command -v aws >/dev/null 2>&1
}

if use_rclone; then
    TOOL="rclone"
    echo "  Tool: rclone"
elif use_aws_cli; then
    TOOL="aws"
    echo "  Tool: aws s3"
else
    echo "ERROR: Neither rclone nor aws CLI found. Install one of them."
    exit 1
fi

# --- Configure rclone env vars ------------------------------------------------

setup_rclone() {
    export RCLONE_CONFIG_R2_TYPE="s3"
    export RCLONE_CONFIG_R2_PROVIDER="Cloudflare"
    export RCLONE_CONFIG_R2_ACCESS_KEY_ID="${R2_ACCESS_KEY_ID}"
    export RCLONE_CONFIG_R2_SECRET_ACCESS_KEY="${R2_SECRET_ACCESS_KEY}"
    export RCLONE_CONFIG_R2_ENDPOINT="${R2_ENDPOINT}"
    export RCLONE_CONFIG_R2_ACL="private"
    export RCLONE_CONFIG_R2_NO_CHECK_BUCKET="true"
}

setup_aws() {
    export AWS_ACCESS_KEY_ID="${R2_ACCESS_KEY_ID}"
    export AWS_SECRET_ACCESS_KEY="${R2_SECRET_ACCESS_KEY}"
    export AWS_DEFAULT_REGION="auto"
}

# --- Find the backup to restore -----------------------------------------------

find_restore_date_rclone() {
    setup_rclone
    RCLONE_PREFIX="r2:${R2_BUCKET}/${BACKUP_PREFIX}/"

    if [ -n "${RESTORE_DATE}" ]; then
        # Verify the specified date exists
        if rclone lsf "${RCLONE_PREFIX}${RESTORE_DATE}/" >/dev/null 2>&1; then
            echo "  Restoring from specified date: ${RESTORE_DATE}"
        else
            echo "ERROR: No backup found for date: ${RESTORE_DATE}"
            echo "  Available backups:"
            rclone lsf "${RCLONE_PREFIX}" --dirs-only 2>/dev/null | sort | sed 's|/||; s|^|    |'
            exit 1
        fi
    else
        # Find the latest backup
        RESTORE_DATE=$(rclone lsf "${RCLONE_PREFIX}" --dirs-only 2>/dev/null | sort | tail -1 | sed 's|/||')
        if [ -z "${RESTORE_DATE}" ]; then
            echo "ERROR: No backups found in ${RCLONE_PREFIX}"
            exit 1
        fi
        echo "  Latest backup: ${RESTORE_DATE}"
    fi
}

find_restore_date_aws() {
    setup_aws
    S3_PREFIX="s3://${R2_BUCKET}/${BACKUP_PREFIX}/"

    if [ -n "${RESTORE_DATE}" ]; then
        # Verify the specified date exists
        COUNT=$(aws s3 ls "${S3_PREFIX}${RESTORE_DATE}/" --endpoint-url "${R2_ENDPOINT}" 2>/dev/null | wc -l | tr -d ' ')
        if [ "${COUNT}" = "0" ]; then
            echo "ERROR: No backup found for date: ${RESTORE_DATE}"
            echo "  Available backups:"
            aws s3 ls "${S3_PREFIX}" --endpoint-url "${R2_ENDPOINT}" 2>/dev/null \
                | awk '/PRE/{print $2}' | sed 's|/||; s|^|    |'
            exit 1
        fi
        echo "  Restoring from specified date: ${RESTORE_DATE}"
    else
        RESTORE_DATE=$(aws s3 ls "${S3_PREFIX}" --endpoint-url "${R2_ENDPOINT}" 2>/dev/null \
            | awk '/PRE/{print $2}' | sed 's|/||' | sort | tail -1)
        if [ -z "${RESTORE_DATE}" ]; then
            echo "ERROR: No backups found in ${S3_PREFIX}"
            exit 1
        fi
        echo "  Latest backup: ${RESTORE_DATE}"
    fi
}

# --- Restore -------------------------------------------------------------------

do_rclone_restore() {
    setup_rclone
    RCLONE_SRC="r2:${R2_BUCKET}/${BACKUP_PREFIX}/${RESTORE_DATE}"

    # Create data directory if needed
    mkdir -p "${LAGO_DATA_DIR}"

    # Restore journal.redb
    echo ""
    echo "--- Restoring journal.redb..."
    if rclone lsf "${RCLONE_SRC}/journal.redb" >/dev/null 2>&1; then
        rclone copyto "${RCLONE_SRC}/journal.redb" "${LAGO_DATA_DIR}/journal.redb" --progress
        echo "  [ok] journal.redb restored"
    else
        echo "  [warn] journal.redb not found in backup"
    fi

    # Restore blobs/
    echo ""
    echo "--- Restoring blobs/..."
    if rclone lsf "${RCLONE_SRC}/blobs/" >/dev/null 2>&1; then
        mkdir -p "${LAGO_DATA_DIR}/blobs"
        rclone sync "${RCLONE_SRC}/blobs/" "${LAGO_DATA_DIR}/blobs/" --progress
        echo "  [ok] blobs/ restored"
    else
        echo "  [warn] blobs/ not found in backup"
    fi
}

do_aws_restore() {
    setup_aws
    S3_SRC="s3://${R2_BUCKET}/${BACKUP_PREFIX}/${RESTORE_DATE}"

    # Create data directory if needed
    mkdir -p "${LAGO_DATA_DIR}"

    # Restore journal.redb
    echo ""
    echo "--- Restoring journal.redb..."
    if aws s3 ls "${S3_SRC}/journal.redb" --endpoint-url "${R2_ENDPOINT}" >/dev/null 2>&1; then
        aws s3 cp "${S3_SRC}/journal.redb" "${LAGO_DATA_DIR}/journal.redb" \
            --endpoint-url "${R2_ENDPOINT}"
        echo "  [ok] journal.redb restored"
    else
        echo "  [warn] journal.redb not found in backup"
    fi

    # Restore blobs/
    echo ""
    echo "--- Restoring blobs/..."
    COUNT=$(aws s3 ls "${S3_SRC}/blobs/" --endpoint-url "${R2_ENDPOINT}" 2>/dev/null | wc -l | tr -d ' ')
    if [ "${COUNT}" != "0" ]; then
        mkdir -p "${LAGO_DATA_DIR}/blobs"
        aws s3 sync "${S3_SRC}/blobs/" "${LAGO_DATA_DIR}/blobs/" \
            --endpoint-url "${R2_ENDPOINT}"
        echo "  [ok] blobs/ restored"
    else
        echo "  [warn] blobs/ not found in backup"
    fi
}

# --- Execute ------------------------------------------------------------------

if [ "${TOOL}" = "rclone" ]; then
    find_restore_date_rclone
    do_rclone_restore
else
    find_restore_date_aws
    do_aws_restore
fi

echo ""
echo "=== Restore complete ==="
echo "  Restored from: ${BACKUP_PREFIX}/${RESTORE_DATE}"
echo "  Data dir:      ${LAGO_DATA_DIR}"
echo ""
echo "  Next steps:"
echo "    1. Verify files:  ls -la ${LAGO_DATA_DIR}/"
echo "    2. Start lagod:   lagod --data-dir ${LAGO_DATA_DIR}"
echo "    3. Check health:  curl http://localhost:8080/health"
