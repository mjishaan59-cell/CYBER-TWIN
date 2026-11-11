"""
Predictive Analytics FastAPI Router
Phase 23 - Machine Learning Resource Forecasting, Anomaly Trend Prediction,
and Predictive Alert Management for Linux Infrastructure.
"""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import text
import pandas as pd

from backend.database import engine, is_database_online
from backend.auth.dependencies import get_current_user, require_roles
from backend.analytics.predictive_engine import predictive_engine

router = APIRouter(
    prefix="/predictive-analytics",
    tags=["Predictive Analytics"]
)


def fetch_host_metrics(hostname: str, limit: int = 100) -> List[Dict[str, Any]]:
    """Retrieve recent time-series telemetry for a host."""
    if not is_database_online():
        return []

    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text("""
                    SELECT hostname, cpu_usage, memory_usage, disk_usage, collected_at
                    FROM system_metrics
                    WHERE hostname = :hostname
                      AND cpu_usage IS NOT NULL
                    ORDER BY collected_at ASC
                    LIMIT :limit
                """),
                {"hostname": hostname, "limit": limit}
            ).mappings().all()
            return [dict(r) for r in rows]
    except Exception:
        return []


@router.get("/forecast")
def get_resource_forecast(
    hostname: str = Query("prac-server", description="Target Linux host"),
    limit: int = Query(60, ge=10, le=500),
    current_user = Depends(get_current_user)
):
    """
    Generate comprehensive multi-resource ML forecasts (CPU, Memory, Disk, Network),
    anomaly trend likelihood, and predictive saturation alerts.
    """
    history = fetch_host_metrics(hostname, limit=limit)
    forecast_data = predictive_engine.generate_host_forecasts(hostname, history)
    return forecast_data


@router.get("/metrics/{metric_name}")
def get_metric_projection(
    metric_name: str,
    hostname: str = Query("prac-server", description="Target Linux host"),
    forecast_steps: int = Query(12, ge=3, le=48),
    current_user = Depends(get_current_user)
):
    """
    Detailed time-series projection with upper/lower confidence intervals for a specific metric.
    """
    metric_norm = metric_name.lower().strip()
    valid_metrics = ["cpu", "memory", "disk", "network"]
    if metric_norm not in valid_metrics:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid metric '{metric_name}'. Must be one of {valid_metrics}"
        )

    history = fetch_host_metrics(hostname, limit=100)
    all_forecasts = predictive_engine.generate_host_forecasts(hostname, history)
    metric_result = all_forecasts.get(metric_norm)

    return {
        "hostname": hostname,
        "metric_name": metric_norm,
        "forecast": metric_result,
        "confidence_pct": metric_result["confidence_pct"],
        "trend_direction": metric_result["trend_direction"]
    }


@router.get("/exhaustion")
def get_time_to_exhaustion(
    hostname: str = Query("prac-server", description="Target Linux host"),
    current_user = Depends(get_current_user)
):
    """
    Calculate estimated hours/days until storage and memory reach critical capacity thresholds (95%).
    """
    history = fetch_host_metrics(hostname, limit=100)
    forecasts = predictive_engine.generate_host_forecasts(hostname, history)

    disk_hours = forecasts["disk"]["time_to_exhaustion_hours"]
    mem_hours = forecasts["memory"]["time_to_exhaustion_hours"]

    return {
        "hostname": hostname,
        "disk_current_pct": forecasts["disk"]["current_value"],
        "disk_rate_per_hour": forecasts["disk"]["rate_per_hour"],
        "disk_exhaustion_hours": disk_hours,
        "disk_exhaustion_status": (
            "CRITICAL_URGENT" if disk_hours and disk_hours <= 24 else (
                "WARNING_ELEVATED" if disk_hours and disk_hours <= 72 else "STABLE"
            )
        ),
        "memory_current_pct": forecasts["memory"]["current_value"],
        "memory_rate_per_hour": forecasts["memory"]["rate_per_hour"],
        "memory_exhaustion_hours": mem_hours,
        "memory_leak_suspected": bool(forecasts["memory"]["rate_per_hour"] > 2.0)
    }


@router.get("/alerts")
def get_predictive_alerts(
    hostname: str = Query("prac-server", description="Target Linux host"),
    current_user = Depends(get_current_user)
):
    """
    Retrieve automated predictive capacity and saturation alerts.
    """
    history = fetch_host_metrics(hostname, limit=100)
    forecasts = predictive_engine.generate_host_forecasts(hostname, history)
    return {
        "hostname": hostname,
        "total_predictive_alerts": len(forecasts["predictive_alerts"]),
        "alerts": forecasts["predictive_alerts"]
    }


@router.post("/retrain")
def retrain_predictive_models(
    hostname: str = Query("prac-server", description="Target Linux host"),
    current_user = Depends(require_roles({"admin", "analyst"}))
):
    """
    Trigger manual model retraining on latest system telemetry and return performance metrics.
    """
    history = fetch_host_metrics(hostname, limit=200)
    forecasts = predictive_engine.generate_host_forecasts(hostname, history)

    return {
        "status": "RETRAINED",
        "hostname": hostname,
        "models_evaluated": {
            "cpu": {
                "model": forecasts["cpu"]["model_type"],
                "rmse": forecasts["cpu"]["rmse"],
                "r2_score": forecasts["cpu"]["r2_score"],
                "confidence_pct": forecasts["cpu"]["confidence_pct"]
            },
            "memory": {
                "model": forecasts["memory"]["model_type"],
                "rmse": forecasts["memory"]["rmse"],
                "r2_score": forecasts["memory"]["r2_score"],
                "confidence_pct": forecasts["memory"]["confidence_pct"]
            },
            "disk": {
                "model": forecasts["disk"]["model_type"],
                "rmse": forecasts["disk"]["rmse"],
                "r2_score": forecasts["disk"]["r2_score"],
                "confidence_pct": forecasts["disk"]["confidence_pct"]
            }
        }
    }
