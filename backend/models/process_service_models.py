"""
Process & Systemd Service Monitoring SQLAlchemy Models
Phase 25 - Process and Service Monitoring Subsystem
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


class MonitoredProcess(Base):
    __tablename__ = "monitored_processes"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(100), nullable=False, index=True)
    pid = Column(Integer, nullable=False)
    ppid = Column(Integer, default=0)
    username = Column(String(50), nullable=False)
    process_name = Column(String(100), nullable=False, index=True)
    cmdline = Column(String(1000), default="")
    cpu_percent = Column(Float, default=0.0)
    memory_percent = Column(Float, default=0.0)
    status = Column(String(20), default="R")
    is_suspicious = Column(Boolean, default=False, index=True)
    threat_category = Column(String(50), default="BENIGN")
    captured_at = Column(TIMESTAMP, server_default=text("CURRENT_TIMESTAMP"))


class SystemdServiceUnit(Base):
    __tablename__ = "systemd_services"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(100), nullable=False, index=True)
    service_name = Column(String(100), nullable=False, index=True)
    load_state = Column(String(30), default="loaded")
    active_state = Column(String(30), default="active")
    sub_state = Column(String(30), default="running")
    description = Column(String(255), default="")
    is_failed = Column(Boolean, default=False, index=True)
    restart_count = Column(Integer, default=0)
    last_checked_at = Column(TIMESTAMP, server_default=text("CURRENT_TIMESTAMP"))


class ProcessSecurityAlert(Base):
    __tablename__ = "process_security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(100), nullable=False, index=True)
    alert_type = Column(String(60), nullable=False)               # CRYPTOMINER_DETECTED, REVERSE_SHELL, etc.
    severity = Column(String(20), nullable=False, default="MEDIUM") # LOW, MEDIUM, HIGH, CRITICAL
    process_name = Column(String(100), nullable=False)
    pid = Column(Integer, nullable=False)
    details = Column(String(500), nullable=False)
    recommendation = Column(String(500), nullable=False)
    created_at = Column(TIMESTAMP, server_default=text("CURRENT_TIMESTAMP"))
