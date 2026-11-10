-- ============================================================
-- PHASE 24: FILE INTEGRITY MONITORING (FIM) SUBSYSTEM
-- ============================================================

CREATE TABLE IF NOT EXISTS fim_baselines (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(100) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    sha256_hash VARCHAR(64) NOT NULL,
    file_size_bytes BIGINT DEFAULT 0,
    permissions VARCHAR(10) DEFAULT '0644',
    owner_uid INTEGER DEFAULT 0,
    group_gid INTEGER DEFAULT 0,
    owner_name VARCHAR(50) DEFAULT 'root',
    group_name VARCHAR(50) DEFAULT 'root',
    is_directory BOOLEAN DEFAULT FALSE,
    baseline_version INTEGER DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_fim_baseline_host_file UNIQUE (hostname, file_path)
);

CREATE INDEX IF NOT EXISTS ix_fim_baselines_host ON fim_baselines(hostname);
CREATE INDEX IF NOT EXISTS ix_fim_baselines_file ON fim_baselines(file_path);

CREATE TABLE IF NOT EXISTS fim_events (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(100) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    change_type VARCHAR(30) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    old_sha256 VARCHAR(64),
    new_sha256 VARCHAR(64),
    old_permissions VARCHAR(10),
    new_permissions VARCHAR(10),
    old_owner VARCHAR(50),
    new_owner VARCHAR(50),
    details VARCHAR(500),
    acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_fim_change_type CHECK (
        change_type IN ('CREATED', 'MODIFIED', 'DELETED', 'PERMISSION_CHANGED', 'OWNERSHIP_CHANGED')
    ),
    CONSTRAINT chk_fim_severity CHECK (
        severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    )
);

CREATE INDEX IF NOT EXISTS ix_fim_events_host_time ON fim_events(hostname, detected_at DESC);
CREATE INDEX IF NOT EXISTS ix_fim_events_severity ON fim_events(severity);

CREATE TABLE IF NOT EXISTS fim_config (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(100) UNIQUE NOT NULL,
    monitored_paths VARCHAR(2000) NOT NULL,
    scan_interval_seconds INTEGER DEFAULT 300,
    baseline_hash_seal VARCHAR(64),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_scan_at TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
