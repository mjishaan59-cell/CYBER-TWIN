#!/usr/bin/env bash
# ==============================================================================
# Cyber Digital Twin - Automated Database Backup Script
# Creates compressed PostgreSQL dumps with automatic retention management.
# ==============================================================================

set -euo pipefail

# Configuration
BACKUP_DIR="${BACKUP_DIR:-/opt/cyber-twin/backups}"
RETENTION_DAYS="${RETENTION_DAYS:-7}"
TIMESTAMP="$(date +'%Y%m%d_%H%M%S')"
BACKUP_FILE="${BACKUP_DIR}/cybertwin_backup_${TIMESTAMP}.sql.gz"

DB_HOST="${DB_HOST:-postgres}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-cyber_twin_db}"
DB_USER="${DB_USER:-cyber_admin}"

# Logging helper
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [BACKUP] $1"
}

mkdir -p "${BACKUP_DIR}"

log "Starting database backup for ${DB_NAME} at ${DB_HOST}:${DB_PORT}..."

if command -v docker &> /dev/null && docker ps --format '{{.Names}}' | grep -q 'cyber_twin_postgres'; then
    log "Executing pg_dump via Docker container: cyber_twin_postgres"
    docker exec -t cyber_twin_postgres pg_dump -U "${DB_USER}" -d "${DB_NAME}" --clean --if-exists | gzip -9 > "${BACKUP_FILE}"
else
    log "Executing native pg_dump..."
    pg_dump -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" --clean --if-exists | gzip -9 > "${BACKUP_FILE}"
fi

BACKUP_SIZE="$(du -h "${BACKUP_FILE}" | cut -f1)"
log "Backup completed successfully: ${BACKUP_FILE} (${BACKUP_SIZE})"

# Prune old backups older than RETENTION_DAYS
log "Pruning backups older than ${RETENTION_DAYS} days in ${BACKUP_DIR}..."
find "${BACKUP_DIR}" -name "cybertwin_backup_*.sql.gz" -type f -mtime +"${RETENTION_DAYS}" -exec rm -vf {} \;

log "Database backup and retention cycle complete."
exit 0
