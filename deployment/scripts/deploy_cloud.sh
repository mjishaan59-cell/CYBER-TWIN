#!/usr/bin/env bash
# ==============================================================================
# Cyber Digital Twin - Cloud Deployment Automation Script
# Builds images, initializes database, runs migrations, and checks health.
# ==============================================================================

set -euo pipefail

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [DEPLOY] $1"
}

log "Starting Cyber Digital Twin cloud deployment pipeline..."

# 1. Environment validation
if [ ! -f ".env" ]; then
    log "Warning: .env file not found. Creating default template..."
    cat <<EOF > .env
ENVIRONMENT=production
DB_USER=cyber_admin
DB_PASSWORD=cyber_secure_password_2026
DB_NAME=cyber_twin_db
DB_HOST=postgres
DB_PORT=5432
JWT_SECRET=$(openssl rand -hex 32 2>/dev/null || echo "cyber_twin_production_secret_key_fixed_entropy_99182")
BACKEND_PORT=8000
FRONTEND_PORT=80
EOF
    log ".env configuration generated."
fi

# 2. Build and launch containers
log "Pulling and building container images with docker-compose..."
docker compose build --pull

log "Launching core services (PostgreSQL, Backend API, Frontend Nginx)..."
docker compose up -d

# 3. Wait for database and backend readiness
log "Waiting for services to report healthy status..."
MAX_ATTEMPTS=30
ATTEMPT=0
HEALTHY=0

while [ "${ATTEMPT}" -lt "${MAX_ATTEMPTS}" ]; do
    ATTEMPT=$((ATTEMPT + 1))
    if curl -s -f "http://localhost:80/health" > /dev/null 2>&1 || curl -s -f "http://localhost:8000/health" > /dev/null 2>&1; then
        HEALTHY=1
        break
    fi
    log "Waiting for API gateway / health check... (${ATTEMPT}/${MAX_ATTEMPTS})"
    sleep 2
done

if [ "${HEALTHY}" -eq 1 ]; then
    log "Cyber Digital Twin deployed and healthy!"
    log "Frontend Dashboard: http://localhost:80"
    log "Backend API: http://localhost:8000"
    log "API Documentation: http://localhost:8000/docs"
else
    log "Health check timed out. Inspecting container logs:"
    docker compose logs --tail=50
    exit 1
fi

log "Cloud deployment sequence completed successfully."
exit 0
