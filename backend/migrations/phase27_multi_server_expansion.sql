-- Phase 27: Multi-Server Expansion Migration

CREATE TABLE IF NOT EXISTS managed_servers (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(120) NOT NULL,
    ip_address VARCHAR(50) NOT NULL,
    ssh_port INTEGER DEFAULT 22,
    ssh_username VARCHAR(50) DEFAULT 'root',
    auth_method VARCHAR(20) DEFAULT 'key',
    environment VARCHAR(30) DEFAULT 'production',
    host_group VARCHAR(50) DEFAULT 'general',
    os_flavor VARCHAR(80) DEFAULT 'Linux Enterprise 9',
    status VARCHAR(20) DEFAULT 'ONLINE',
    latency_ms DOUBLE PRECISION DEFAULT 1.5,
    cpu_usage DOUBLE PRECISION DEFAULT 15.0,
    memory_usage DOUBLE PRECISION DEFAULT 32.0,
    disk_usage DOUBLE PRECISION DEFAULT 45.0,
    tags VARCHAR(255) DEFAULT '',
    notes TEXT DEFAULT '',
    is_active BOOLEAN DEFAULT TRUE,
    last_heartbeat_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_managed_host ON managed_servers(hostname);
CREATE INDEX IF NOT EXISTS idx_managed_env ON managed_servers(environment);
CREATE INDEX IF NOT EXISTS idx_managed_grp ON managed_servers(host_group);
CREATE INDEX IF NOT EXISTS idx_managed_status ON managed_servers(status);

CREATE TABLE IF NOT EXISTS server_health_heartbeats (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(100) NOT NULL,
    status VARCHAR(20) DEFAULT 'ONLINE',
    latency_ms DOUBLE PRECISION DEFAULT 0.0,
    is_reachable BOOLEAN DEFAULT TRUE,
    error_message VARCHAR(255) DEFAULT '',
    probed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_heartbeat_host ON server_health_heartbeats(hostname);
CREATE INDEX IF NOT EXISTS idx_heartbeat_time ON server_health_heartbeats(probed_at);
