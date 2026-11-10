"""
Database Models for Phase 29 - Advanced Incident Response & Playbooks Subsystem
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


class PlaybookExecutionAudit(Base):
    """
    Audit log of playbook executions, safeguards, parameters, and results.
    """
    __tablename__ = "playbook_execution_audits"

    id = Column(Integer, primary_key=True, index=True)
    execution_id = Column(String(64), unique=True, nullable=False, index=True)
    playbook_id = Column(String(60), nullable=False, index=True)
    playbook_name = Column(String(120), nullable=False)
    incident_id = Column(String(64), index=True, default="")
    target_hostname = Column(String(100), nullable=False, index=True)
    executed_by = Column(String(50), default="admin")
    mode = Column(String(20), default="DRY_RUN")  # DRY_RUN, LIVE
    safeguards_passed = Column(Boolean, default=True)
    safeguard_notes = Column(String(255), default="All safeguard checks passed")
    status = Column(String(30), default="SUCCESS")  # SUCCESS, BLOCKED_BY_SAFEGUARD, FAILED
    parameters = Column(JSON, default=dict)
    execution_log = Column(JSON, default=list)
    result_summary = Column(Text, default="")
    executed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


class IncidentEvidenceArtifact(Base):
    """
    Forensic evidence artifact attached to an incident investigation.
    """
    __tablename__ = "incident_evidence_artifacts"

    id = Column(Integer, primary_key=True, index=True)
    artifact_id = Column(String(64), unique=True, nullable=False, index=True)
    incident_id = Column(String(64), nullable=False, index=True)
    artifact_type = Column(String(50), nullable=False)  # PCAP, MEMORY_DUMP, LOG_SNIPPET, FILE_HASH, IOC
    file_name = Column(String(120), nullable=False)
    file_hash_sha256 = Column(String(64), default="")
    description = Column(String(255), default="")
    collected_by = Column(String(50), default="analyst")
    metadata_json = Column(JSON, default=dict)
    collected_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


class IncidentTimelineEvent(Base):
    """
    Chronological forensics event on an incident timeline.
    """
    __tablename__ = "incident_timeline_events"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(64), nullable=False, index=True)
    event_type = Column(String(50), nullable=False)  # ALERT, TELEMETRY, PLAYBOOK, NOTE, STATUS_CHANGE
    title = Column(String(150), nullable=False)
    source = Column(String(60), default="SYSTEM")
    severity = Column(String(20), default="INFO")
    details = Column(Text, default="")
    event_timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
