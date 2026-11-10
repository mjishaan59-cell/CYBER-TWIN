"""
Predictive Analytics SQLAlchemy Models
Phase 23 - Predictive Analytics Subsystem
"""

from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Boolean,
    TIMESTAMP,
    text
)
from backend.models.system_metrics import Base


class PredictiveForecast(Base):
    __tablename__ = "predictive_forecasts"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(100), nullable=False, index=True)
    metric_name = Column(String(50), nullable=False, index=True)   # cpu, memory, disk, network
    current_value = Column(Float, nullable=False)
    predicted_15m = Column(Float, nullable=False)
    predicted_1h = Column(Float, nullable=False)
    predicted_6h = Column(Float, nullable=False)
    trend_direction = Column(String(20), nullable=False)           # RISING, FALLING, STABLE
    rate_of_change_per_hour = Column(Float, default=0.0)
    time_to_exhaustion_hours = Column(Float, nullable=True)        # Hours until 95% threshold
    confidence_pct = Column(Float, nullable=False, default=85.0)
    model_type = Column(String(50), default="Polynomial Trend Regression")
    rmse = Column(Float, default=0.0)
    r2_score = Column(Float, default=0.0)
    generated_at = Column(TIMESTAMP, server_default=text("CURRENT_TIMESTAMP"))


class PredictiveAlert(Base):
    __tablename__ = "predictive_alerts"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(100), nullable=False, index=True)
    alert_type = Column(String(60), nullable=False)               # CAPACITY_EXHAUSTION, CPU_SATURATION, etc.
    severity = Column(String(20), nullable=False, default="MEDIUM") # LOW, MEDIUM, HIGH, CRITICAL
    metric_name = Column(String(50), nullable=False)
    time_horizon_minutes = Column(Integer, nullable=False)
    current_value = Column(Float, nullable=False)
    projected_value = Column(Float, nullable=False)
    confidence_pct = Column(Float, nullable=False)
    recommendation = Column(String(500), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(TIMESTAMP, server_default=text("CURRENT_TIMESTAMP"))
