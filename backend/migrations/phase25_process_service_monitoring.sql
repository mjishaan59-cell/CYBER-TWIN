-- ============================================================
-- PHASE 25: PROCESS AND SERVICE MONITORING SUBSYSTEM
-- ============================================================

CREATE TABLE IF NOT EXISTS monitored_processes (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(100) NOT NULL,
    pid INTEGER NOT NULL,
    ppid INTEGER DEFAULT 0,
    username VARCHAR(50) NOT NULL,
    process_name VARCHAR(100) NOT NULL,
    cmdline VARCHAR(1000) DEFAULT '',
    cpu_percent DOUBLE PRECISION DEFAULT 0.0,
    memory_percent DOUBLE PRECISION DEFAULT 0.0,
    status VARCHAR(20) DEFAULT 'R',
    is_suspicious BOOLEAN DEFAULT FALSE,
    threat_category VARCHAR(50) DEFAULT 'BENIGN',
    captured_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_monitored_procs_host_time ON monitored_processes(hostname, captured_at DESC);
CREATE INDEX IF NOT EXISTS ix_monitored_procs_suspicious ON monitored_processes(is_suspicious);

CREATE TABLE IF NOT EXISTS systemd_services (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(100) NOT NULL,
    service_name VARCHAR(100) NOT NULL,
    load_state VARCHAR(30) DEFAULT 'loaded',
    active_state VARCHAR(30) DEFAULT 'active',
    sub_state VARCHAR(30) DEFAULT 'running',
    description VARCHAR(255) DEFAULT '',
    is_failed BOOLEAN DEFAULT FALSE,
    restart_count INTEGER DEFAULT 0,
    last_checked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_systemd_host_service UNIQUE (hostname, service_name)
);

CREATE INDEX IF NOT EXISTS ix_systemd_services_host_status ON systemd_services(hostname, is_failed);

CREATE TABLE IF NOT EXISTS process_security_alerts (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(100) NOT NULL,
    alert_type VARCHAR(60) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    process_name VARCHAR(100) NOT NULL,
    pid INTEGER NOT NULL,
    details VARCHAR(500) NOT NULL,
    recommendation VARCHAR(500) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_process_alerts_host_time ON process_security_alerts(hostname, created_at DESC);
