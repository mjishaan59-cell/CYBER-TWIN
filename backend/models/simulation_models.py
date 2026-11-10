"""
Database Models for Phase 28 - What-If Attack Simulation Subsystem
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Boolean,
    DateTime,
    Text,
    JSON,
    Index
)
from backend.database import Base


class AttackSimulationRun(Base):
    """
    Record of a synthetic What-If attack simulation execution.
    """
    __tablename__ = "attack_simulation_runs"

    id = Column(Integer, primary_key=True, index=True)
    simulation_id = Column(String(64), unique=True, nullable=False, index=True)
    scenario_id = Column(String(60), nullable=False, index=True)
    scenario_name = Column(String(120), nullable=False)
    target_hostname = Column(String(100), nullable=False, index=True)
    mitre_technique = Column(String(50), nullable=False)
    tactics = Column(String(80), default="Initial Access")
    simulated_by = Column(String(50), default="admin")
    status = Column(String(30), default="COMPLETED")  # RUNNING, COMPLETED, FAILED
    risk_score = Column(Integer, default=50)  # 0 - 100
    impact_level = Column(String(20), default="MEDIUM")  # LOW, MEDIUM, HIGH, CRITICAL
    predicted_containment_probability = Column(Float, default=85.0)  # percentage
    estimated_mttd_seconds = Column(Integer, default=15)
    estimated_mttr_seconds = Column(Integer, default=120)
    defensive_recommendations = Column(JSON, default=list)
    impact_summary = Column(Text, default="")
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    completed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class SimulationStepLog(Base):
    """
    Granular step-by-step progress events for an attack simulation run.
    """
    __tablename__ = "simulation_step_logs"

    id = Column(Integer, primary_key=True, index=True)
    simulation_id = Column(String(64), nullable=False, index=True)
    step_number = Column(Integer, nullable=False)
    step_name = Column(String(120), nullable=False)
    mitre_subtechnique = Column(String(50), default="")
    action_type = Column(String(50), default="SYNTHETIC_PROBE")
    observed_telemetry = Column(String(255), default="")
    detection_status = Column(String(30), default="DETECTED")  # DETECTED, EVADED, BLOCKED
    details = Column(Text, default="")
    logged_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
