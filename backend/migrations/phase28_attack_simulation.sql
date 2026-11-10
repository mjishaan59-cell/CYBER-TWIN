-- Phase 28: What-If Attack Simulation Migration

CREATE TABLE IF NOT EXISTS attack_simulation_runs (
    id SERIAL PRIMARY KEY,
    simulation_id VARCHAR(64) UNIQUE NOT NULL,
    scenario_id VARCHAR(60) NOT NULL,
    scenario_name VARCHAR(120) NOT NULL,
    target_hostname VARCHAR(100) NOT NULL,
    mitre_technique VARCHAR(50) NOT NULL,
    tactics VARCHAR(80) DEFAULT 'Initial Access',
    simulated_by VARCHAR(50) DEFAULT 'admin',
    status VARCHAR(30) DEFAULT 'COMPLETED',
    risk_score INTEGER DEFAULT 50,
    impact_level VARCHAR(20) DEFAULT 'MEDIUM',
    predicted_containment_probability DOUBLE PRECISION DEFAULT 85.0,
    estimated_mttd_seconds INTEGER DEFAULT 15,
    estimated_mttr_seconds INTEGER DEFAULT 120,
    defensive_recommendations JSON DEFAULT '[]'::json,
    impact_summary TEXT DEFAULT '',
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sim_run_id ON attack_simulation_runs(simulation_id);
CREATE INDEX IF NOT EXISTS idx_sim_scenario ON attack_simulation_runs(scenario_id);
CREATE INDEX IF NOT EXISTS idx_sim_target ON attack_simulation_runs(target_hostname);
CREATE INDEX IF NOT EXISTS idx_sim_started ON attack_simulation_runs(started_at);

CREATE TABLE IF NOT EXISTS simulation_step_logs (
    id SERIAL PRIMARY KEY,
    simulation_id VARCHAR(64) NOT NULL,
    step_number INTEGER NOT NULL,
    step_name VARCHAR(120) NOT NULL,
    mitre_subtechnique VARCHAR(50) DEFAULT '',
    action_type VARCHAR(50) DEFAULT 'SYNTHETIC_PROBE',
    observed_telemetry VARCHAR(255) DEFAULT '',
    detection_status VARCHAR(30) DEFAULT 'DETECTED',
    details TEXT DEFAULT '',
    logged_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sim_step_sim_id ON simulation_step_logs(simulation_id);
