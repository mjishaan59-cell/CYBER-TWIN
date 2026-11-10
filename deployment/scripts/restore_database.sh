#!/usr/bin/env bash
# ==============================================================================
# Cyber Digital Twin - Automated Database Restore Script
# Restores compressed PostgreSQL backup archives to target database.
# ==============================================================================

set -euo pipefail

# Logging helper
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [RESTORE] $1"
}

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <path_to_backup_file.sql.gz>"
    exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "${BACKUP_FILE}" ]; then
    echo "Error: Backup file '${BACKUP_FILE}' does not exist."
    exit 1
fi

DB_HOST="${DB_HOST:-postgres}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-cyber_twin_db}"
DB_USER="${DB_USER:-cyber_admin}"

log "Preparing to restore database '${DB_NAME}' from '${BACKUP_FILE}'..."

read -p "WARNING: This will overwrite tables in ${DB_NAME}. Proceed? (y/N): " -r CONFIRM
if [[ ! "${CONFIRM}" =~ ^[Yy]$ ]]; then
    log "Database restore aborted by operator."
    exit 0
fi

if command -v docker &> /dev/null && docker ps --format '{{.Names}}' | grep -q 'cyber_twin_postgres'; then
    log "Streaming backup into Docker container: cyber_twin_postgres..."
    gunzip -c "${BACKUP_FILE}" | docker exec -i cyber_twin_postgres psql -U "${DB_USER}" -d "${DB_NAME}"
else
    log "Streaming backup into native PostgreSQL target..."
    gunzip -c "${BACKUP_FILE}" | psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}"
fi

log "Database restoration completed successfully from ${BACKUP_FILE}."
exit 0
