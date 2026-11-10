"""
Automated Test Suite for Phase 23 - Predictive Analytics Subsystem
Tests:
- ResourceForecaster ML trend extrapolation (CPU, Memory, Disk, Network)
- Model evaluation metrics (RMSE, R2 score, Confidence percentage)
- Confidence interval bounds (lower, predicted, upper)
- Low-data baseline fallback model
- Storage time-to-exhaustion estimation
- Anomaly trend likelihood forecasting
- Predictive saturation alerts triggering
- Predictive Analytics REST API Endpoints
"""

import pytest
from fastapi.testclient import TestClient
from backend.api.main import app
from backend.analytics.predictive_engine import (
    ResourceForecaster,
    PredictiveAnalyticsEngine,
    predictive_engine
)
from backend.auth.jwt_handler import create_access_token


@pytest.fixture
def auth_headers():
    token = create_access_token({
        "sub": "testadmin",
        "role": "admin"
    })
    return {"Authorization": f"Bearer {token}"}


def test_resource_forecaster_fit_and_predict():
    """Verify ML regression forecasting on continuous series."""
    forecaster = ResourceForecaster()
    # Linear rising series from 40 to 60 over 20 steps
    history = [40.0 + i * 1.0 for i in range(20)]
    res = forecaster.fit_and_predict(history, forecast_steps=12)

    assert res["model_type"] == "Ridge Trend Extrapolation"
    assert res["current_value"] == 59.0
    assert res["trend_direction"] == "RISING"
    assert res["predicted_15m"] > 59.0
    assert res["predicted_1h"] > res["predicted_15m"]
    assert res["confidence_pct"] >= 70.0
    assert res["rmse"] >= 0.0
    assert len(res["predictions_series"]) == 12
    assert len(res["lower_bounds"]) == 12
    assert len(res["upper_bounds"]) == 12

    # Check confidence bounds
    for lower, pred, upper in zip(res["lower_bounds"], res["predictions_series"], res["upper_bounds"]):
        assert lower <= pred
        assert pred <= upper


def test_resource_forecaster_baseline_fallback():
    """Verify fallback when fewer than 5 data points exist."""
    forecaster = ResourceForecaster()
    short_history = [30.0, 32.0, 31.0]
    res = forecaster.fit_and_predict(short_history, forecast_steps=6)

    assert res["model_type"] == "Statistical Drift Baseline"
    assert res["current_value"] == 31.0
    assert res["confidence_pct"] == 65.0
    assert len(res["predictions_series"]) == 6


def test_time_to_exhaustion():
    """Verify disk exhaustion time estimation."""
    forecaster = ResourceForecaster()
    # Rising disk usage: 80% climbing by 1% per 5 min step (12% per hour)
    climbing_disk = [70.0 + i * 1.0 for i in range(15)]
    res = forecaster.fit_and_predict(climbing_disk, forecast_steps=12, step_interval_seconds=300)

    assert res["trend_direction"] == "RISING"
    assert res["time_to_exhaustion_hours"] is not None
    assert res["time_to_exhaustion_hours"] > 0.0


def test_predictive_alerts_generation():
    """Verify proactive saturation alert generation."""
    engine = PredictiveAnalyticsEngine()
    # High rising CPU series
    critical_cpu = [75.0 + i * 1.5 for i in range(15)]
    cpu_f = engine.forecaster.fit_and_predict(critical_cpu)
    mem_f = engine.forecaster.fit_and_predict([50.0] * 15)
    disk_f = engine.forecaster.fit_and_predict([60.0] * 15)

    alerts = engine._generate_predictive_alerts("test-server", cpu_f, mem_f, disk_f)
    assert len(alerts) >= 1
    cpu_alert = next((a for a in alerts if a["alert_type"] == "PREDICTED_CPU_SATURATION"), None)
    assert cpu_alert is not None
    assert cpu_alert["severity"] in ("HIGH", "CRITICAL")
    assert "throttle" in cpu_alert["recommendation"] or "autoscaling" in cpu_alert["recommendation"]


def test_anomaly_trend_likelihood():
    """Verify anomaly trend probability calculation."""
    engine = PredictiveAnalyticsEngine()
    cpu_f = {"trend_direction": "RISING", "predicted_1h": 88.0}
    mem_f = {"trend_direction": "RISING", "predicted_1h": 85.0}
    disk_f = {"time_to_exhaustion_hours": 36.0}

    trend = engine._predict_anomaly_trend(cpu_f, mem_f, disk_f)
    assert trend["probability_pct"] >= 75.0
    assert trend["status"] == "CRITICAL_ANOMALY_LIKELY"


def test_predictive_api_endpoints(auth_headers):
    """Test REST API endpoints for Predictive Analytics."""
    client = TestClient(app)

    # 1. GET /predictive-analytics/forecast
    resp = client.get("/predictive-analytics/forecast?hostname=prac-server", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "cpu" in data
    assert "memory" in data
    assert "disk" in data
    assert "network" in data
    assert "anomaly_trend" in data
    assert "predictive_alerts" in data
    assert data["hostname"] == "prac-server"

    # 2. GET /predictive-analytics/metrics/cpu
    metric_resp = client.get("/predictive-analytics/metrics/cpu?hostname=prac-server", headers=auth_headers)
    assert metric_resp.status_code == 200
    metric_data = metric_resp.json()
    assert metric_data["metric_name"] == "cpu"
    assert "forecast" in metric_data
    assert "confidence_pct" in metric_data

    # 3. GET /predictive-analytics/exhaustion
    ex_resp = client.get("/predictive-analytics/exhaustion?hostname=prac-server", headers=auth_headers)
    assert ex_resp.status_code == 200
    ex_data = ex_resp.json()
    assert "disk_current_pct" in ex_data
    assert "disk_exhaustion_status" in ex_data

    # 4. GET /predictive-analytics/alerts
    alerts_resp = client.get("/predictive-analytics/alerts?hostname=prac-server", headers=auth_headers)
    assert alerts_resp.status_code == 200
    assert "alerts" in alerts_resp.json()

    # 5. POST /predictive-analytics/retrain
    retrain_resp = client.post("/predictive-analytics/retrain?hostname=prac-server", headers=auth_headers)
    assert retrain_resp.status_code == 200
    retrain_data = retrain_resp.json()
    assert retrain_data["status"] == "RETRAINED"
    assert "models_evaluated" in retrain_data
