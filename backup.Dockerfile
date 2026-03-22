# Lightweight backup image for Lago volume backup to R2/S3
#
# Runs backup-to-r2.sh on a cron schedule via Railway cron services.
#
# Railway cron service setup:
#   1. Create a new service in your Railway project
#   2. Set the source to this repo, with root directory: core/life/lago
#   3. Set the Dockerfile path: backup.Dockerfile
#   4. Set the schedule (cron expression): 0 3 * * *   (daily at 3 AM UTC)
#   5. Configure environment variables:
#        R2_ENDPOINT=https://<account-id>.r2.cloudflarestorage.com
#        R2_BUCKET=lago-backups
#        R2_ACCESS_KEY_ID=<your-access-key>
#        R2_SECRET_ACCESS_KEY=<your-secret-key>
#        LAGO_DATA_DIR=/data/.lago
#        BACKUP_RETENTION=7
#   6. Mount the SAME volume as the lagod service at /data
#      (Railway allows sharing volumes between services in the same project)
#
# The cron service will:
#   - Run daily at 3 AM UTC
#   - Copy journal.redb and blobs/ to the R2 bucket
#   - Enforce the retention policy (keep last 7 daily backups)
#   - Exit after completion (Railway cron services are ephemeral)

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        rclone \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/backup-to-r2.sh /usr/local/bin/backup-to-r2.sh
COPY scripts/restore-from-r2.sh /usr/local/bin/restore-from-r2.sh
RUN chmod +x /usr/local/bin/backup-to-r2.sh /usr/local/bin/restore-from-r2.sh

CMD ["/usr/local/bin/backup-to-r2.sh"]
