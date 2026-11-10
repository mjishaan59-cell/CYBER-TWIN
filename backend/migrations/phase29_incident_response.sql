-- Phase 29: Advanced Incident Response & Playbooks Migration

CREATE TABLE IF NOT EXISTS playbook_execution_audits (
    id SERIAL PRIMARY KEY,
    execution_id VARCHAR(64) UNIQUE NOT NULL,
    playbook_id VARCHAR(60) NOT NULL,
    playbook_name VARCHAR(120) NOT NULL,
    incident_id VARCHAR(64) DEFAULT '',
    target_hostname VARCHAR(100) NOT NULL,
    executed_by VARCHAR(50) DEFAULT 'admin',
    mode VARCHAR(20) DEFAULT 'DRY_RUN',
    safeguards_passed BOOLEAN DEFAULT TRUE,
    safeguard_notes VARCHAR(255) DEFAULT 'All safeguard checks passed',
    status VARCHAR(30) DEFAULT 'SUCCESS',
    parameters JSON DEFAULT '{}'::json,
    execution_log JSON DEFAULT '[]'::json,
    result_summary TEXT DEFAULT '',
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_playbook_exec_id ON playbook_execution_audits(execution_id);
CREATE INDEX IF NOT EXISTS idx_playbook_id ON playbook_execution_audits(playbook_id);
CREATE INDEX IF NOT EXISTS idx_playbook_target ON playbook_execution_audits(target_hostname);
CREATE INDEX IF NOT EXISTS idx_playbook_incident ON playbook_execution_audits(incident_id);

CREATE TABLE IF NOT EXISTS incident_evidence_artifacts (
    id SERIAL PRIMARY KEY,
    artifact_id VARCHAR(64) UNIQUE NOT NULL,
    incident_id VARCHAR(64) NOT NULL,
    artifact_type VARCHAR(50) NOT NULL,
    file_name VARCHAR(120) NOT NULL,
    file_hash_sha256 VARCHAR(64) DEFAULT '',
    description VARCHAR(255) DEFAULT '',
    collected_by VARCHAR(50) DEFAULT 'analyst',
    metadata_json JSON DEFAULT '{}'::json,
    collected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_evidence_artifact_id ON incident_evidence_artifacts(artifact_id);
CREATE INDEX IF NOT EXISTS idx_evidence_incident ON incident_evidence_artifacts(incident_id);

CREATE TABLE IF NOT EXISTS incident_timeline_events (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    title VARCHAR(150) NOT NULL,
    source VARCHAR(60) DEFAULT 'SYSTEM',
    severity VARCHAR(20) DEFAULT 'INFO',
    details TEXT DEFAULT '',
    event_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_timeline_incident ON incident_timeline_events(incident_id);
CREATE INDEX IF NOT EXISTS idx_timeline_time ON incident_timeline_events(event_timestamp);
