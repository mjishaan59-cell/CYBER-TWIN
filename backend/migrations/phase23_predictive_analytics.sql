-- ============================================================
-- PHASE 23: PREDICTIVE ANALYTICS SUBSYSTEM
-- ============================================================

CREATE TABLE IF NOT EXISTS predictive_forecasts (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(100) NOT NULL,
    metric_name VARCHAR(50) NOT NULL,
    current_value DOUBLE PRECISION NOT NULL,
    predicted_15m DOUBLE PRECISION NOT NULL,
    predicted_1h DOUBLE PRECISION NOT NULL,
    predicted_6h DOUBLE PRECISION NOT NULL,
    trend_direction VARCHAR(20) NOT NULL,
    rate_of_change_per_hour DOUBLE PRECISION DEFAULT 0.0,
    time_to_exhaustion_hours DOUBLE PRECISION,
    confidence_pct DOUBLE PRECISION NOT NULL DEFAULT 85.0,
    model_type VARCHAR(50) DEFAULT 'Polynomial Trend Regression',
    rmse DOUBLE PRECISION DEFAULT 0.0,
    r2_score DOUBLE PRECISION DEFAULT 0.0,
    generated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_predictive_forecasts_host_metric 
ON predictive_forecasts(hostname, metric_name, generated_at DESC);

CREATE TABLE IF NOT EXISTS predictive_alerts (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(100) NOT NULL,
    alert_type VARCHAR(60) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    metric_name VARCHAR(50) NOT NULL,
    time_horizon_minutes INTEGER NOT NULL,
    current_value DOUBLE PRECISION NOT NULL,
    projected_value DOUBLE PRECISION NOT NULL,
    confidence_pct DOUBLE PRECISION NOT NULL,
    recommendation VARCHAR(500) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_predictive_alerts_host_time 
ON predictive_alerts(hostname, created_at DESC);
