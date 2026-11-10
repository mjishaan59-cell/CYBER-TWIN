-- ============================================================
-- PHASE 22: AI THREAT INTELLIGENCE SUBSYSTEM
-- ============================================================

-- 1. Threat Indicators (IOCs)
CREATE TABLE IF NOT EXISTS threat_indicators (
    id SERIAL PRIMARY KEY,
    indicator_value VARCHAR(255) UNIQUE NOT NULL,
    indicator_type VARCHAR(30) NOT NULL,
    threat_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    confidence_score INTEGER NOT NULL DEFAULT 70,
    source_feed VARCHAR(100) NOT NULL,
    mitre_attack_id VARCHAR(20),
    mitre_tactic VARCHAR(50),
    description VARCHAR(500),
    tags VARCHAR(255) DEFAULT '',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_ioc_type CHECK (indicator_type IN ('IP', 'DOMAIN', 'SHA256', 'URL')),
    CONSTRAINT chk_ioc_severity CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT chk_ioc_confidence CHECK (confidence_score >= 0 AND confidence_score <= 100)
);

CREATE INDEX IF NOT EXISTS ix_threat_indicators_value ON threat_indicators(indicator_value);
CREATE INDEX IF NOT EXISTS ix_threat_indicators_type ON threat_indicators(indicator_type);
CREATE INDEX IF NOT EXISTS ix_threat_indicators_severity ON threat_indicators(severity);

-- 2. Threat Lookup Audit
CREATE TABLE IF NOT EXISTS threat_lookup_audit (
    id SERIAL PRIMARY KEY,
    indicator_value VARCHAR(255) NOT NULL,
    matched BOOLEAN NOT NULL DEFAULT FALSE,
    threat_score INTEGER NOT NULL DEFAULT 0,
    severity VARCHAR(20) NOT NULL DEFAULT 'LOW',
    queried_by VARCHAR(100) DEFAULT 'system',
    context VARCHAR(255) DEFAULT '',
    lookup_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_threat_lookup_value ON threat_lookup_audit(indicator_value);
CREATE INDEX IF NOT EXISTS ix_threat_lookup_time ON threat_lookup_audit(lookup_time DESC);

-- 3. Threat Feed Synchronization Status
CREATE TABLE IF NOT EXISTS threat_feed_sync (
    id SERIAL PRIMARY KEY,
    feed_name VARCHAR(100) UNIQUE NOT NULL,
    feed_url VARCHAR(255) NOT NULL,
    indicator_count INTEGER NOT NULL DEFAULT 0,
    last_sync_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sync_status VARCHAR(30) NOT NULL DEFAULT 'PENDING',
    error_message VARCHAR(500)
);

-- Seed initial feeds metadata
INSERT INTO threat_feed_sync (feed_name, feed_url, indicator_count, sync_status)
VALUES 
    ('Abuse.ch Feodo Tracker', 'https://feodotracker.abuse.ch/downloads/ipblocklist.json', 0, 'INITIALIZED'),
    ('Abuse.ch URLhaus', 'https://urlhaus.abuse.ch/downloads/json_recent/', 0, 'INITIALIZED'),
    ('AlienVault OTX', 'https://otx.alienvault.com/api/v1/indicators', 0, 'INITIALIZED'),
    ('Tor Exit Nodes Feed', 'https://check.torproject.org/torbulkexitlist', 0, 'INITIALIZED')
ON CONFLICT (feed_name) DO NOTHING;
