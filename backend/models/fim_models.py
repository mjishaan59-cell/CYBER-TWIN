"""
File Integrity Monitoring (FIM) SQLAlchemy Models
Phase 24 - File Integrity Monitoring Subsystem
"""

from sqlalchemy import (
    Column,
    Integer,
    String,
    BigInteger,
    Boolean,
    TIMESTAMP,
    text
)
from backend.models.system_metrics import Base


class FimBaseline(Base):
    __tablename__ = "fim_baselines"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(100), nullable=False, index=True)
    file_path = Column(String(500), nullable=False, index=True)
    sha256_hash = Column(String(64), nullable=False)
    file_size_bytes = Column(BigInteger, default=0)
    permissions = Column(String(10), default="0644")
    owner_uid = Column(Integer, default=0)
    group_gid = Column(Integer, default=0)
    owner_name = Column(String(50), default="root")
    group_name = Column(String(50), default="root")
    is_directory = Column(Boolean, default=False)
    baseline_version = Column(Integer, default=1)
    created_at = Column(TIMESTAMP, server_default=text("CURRENT_TIMESTAMP"))


class FimEvent(Base):
    __tablename__ = "fim_events"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(100), nullable=False, index=True)
    file_path = Column(String(500), nullable=False, index=True)
    change_type = Column(String(30), nullable=False, index=True)   # CREATED, MODIFIED, DELETED, PERMISSION, OWNERSHIP
    severity = Column(String(20), nullable=False, default="MEDIUM") # LOW, MEDIUM, HIGH, CRITICAL
    old_sha256 = Column(String(64))
    new_sha256 = Column(String(64))
    old_permissions = Column(String(10))
    new_permissions = Column(String(10))
    old_owner = Column(String(50))
    new_owner = Column(String(50))
    details = Column(String(500))
    acknowledged = Column(Boolean, default=False)
    detected_at = Column(TIMESTAMP, server_default=text("CURRENT_TIMESTAMP"))


class FimConfig(Base):
    __tablename__ = "fim_config"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(100), unique=True, nullable=False)
    monitored_paths = Column(String(2000), nullable=False)
    scan_interval_seconds = Column(Integer, default=300)
    baseline_hash_seal = Column(String(64))
    is_active = Column(Boolean, default=True)
    last_scan_at = Column(TIMESTAMP)
    updated_at = Column(TIMESTAMP, server_default=text("CURRENT_TIMESTAMP"))
