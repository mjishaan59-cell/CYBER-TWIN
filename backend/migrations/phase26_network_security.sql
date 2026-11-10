-- Phase 26: Network Security Monitoring Migration

CREATE TABLE IF NOT EXISTS network_interface_snapshots (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(100) NOT NULL,
    interface_name VARCHAR(50) NOT NULL,
    bytes_sent BIGINT DEFAULT 0,
    bytes_recv BIGINT DEFAULT 0,
    packets_sent BIGINT DEFAULT 0,
    packets_recv BIGINT DEFAULT 0,
    errin INTEGER DEFAULT 0,
    errout INTEGER DEFAULT 0,
    dropin INTEGER DEFAULT 0,
    dropout INTEGER DEFAULT 0,
    is_up BOOLEAN DEFAULT TRUE,
    speed_mbps INTEGER DEFAULT 1000,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_net_iface_host ON network_interface_snapshots(hostname);
CREATE INDEX IF NOT EXISTS idx_net_iface_time ON network_interface_snapshots(recorded_at);

CREATE TABLE IF NOT EXISTS network_connection_records (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(100) NOT NULL,
    protocol VARCHAR(10) DEFAULT 'tcp',
    local_address VARCHAR(100) NOT NULL,
    local_port INTEGER NOT NULL,
    remote_address VARCHAR(100) DEFAULT '',
    remote_port INTEGER DEFAULT 0,
    status VARCHAR(30) DEFAULT 'ESTABLISHED',
    pid INTEGER DEFAULT 0,
    process_name VARCHAR(100) DEFAULT '',
    is_suspicious BOOLEAN DEFAULT FALSE,
    risk_score INTEGER DEFAULT 0,
    threat_description VARCHAR(255) DEFAULT '',
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_net_conn_host ON network_connection_records(hostname);
CREATE INDEX IF NOT EXISTS idx_net_conn_suspicious ON network_connection_records(is_suspicious);
CREATE INDEX IF NOT EXISTS idx_net_conn_remote ON network_connection_records(remote_address, remote_port);

CREATE TABLE IF NOT EXISTS listening_port_records (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(100) NOT NULL,
    protocol VARCHAR(10) DEFAULT 'tcp',
    bind_address VARCHAR(100) NOT NULL,
    port INTEGER NOT NULL,
    pid INTEGER DEFAULT 0,
    process_name VARCHAR(100) DEFAULT '',
    is_authorized BOOLEAN DEFAULT TRUE,
    service_hint VARCHAR(50) DEFAULT '',
    risk_level VARCHAR(20) DEFAULT 'LOW',
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_listen_port_host ON listening_port_records(hostname);
CREATE INDEX IF NOT EXISTS idx_listen_port_num ON listening_port_records(port);

CREATE TABLE IF NOT EXISTS network_security_alerts (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(100) NOT NULL,
    alert_type VARCHAR(60) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    source_ip VARCHAR(50) DEFAULT '',
    source_port INTEGER DEFAULT 0,
    destination_ip VARCHAR(50) DEFAULT '',
    destination_port INTEGER DEFAULT 0,
    protocol VARCHAR(10) DEFAULT 'TCP',
    mitre_technique VARCHAR(50) DEFAULT '',
    description VARCHAR(500) NOT NULL,
    recommendation VARCHAR(500) DEFAULT '',
    resolved BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_net_alert_host ON network_security_alerts(hostname);
CREATE INDEX IF NOT EXISTS idx_net_alert_type ON network_security_alerts(alert_type);
