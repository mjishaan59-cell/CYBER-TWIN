"""
Threat Intelligence SQLAlchemy Models
Phase 22 - AI Threat Intelligence Subsystem
"""

from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    TIMESTAMP,
    text
)
from backend.models.system_metrics import Base


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id = Column(Integer, primary_key=True, index=True)
    indicator_value = Column(String(255), unique=True, nullable=False, index=True)
    indicator_type = Column(String(30), nullable=False, index=True)  # IP, DOMAIN, SHA256, URL
    threat_type = Column(String(50), nullable=False)                 # BRUTE_FORCE, MALWARE_C2, SCANNER, etc.
    severity = Column(String(20), nullable=False, default="MEDIUM")   # LOW, MEDIUM, HIGH, CRITICAL
    confidence_score = Column(Integer, nullable=False, default=70)    # 0-100
    source_feed = Column(String(100), nullable=False)
    mitre_attack_id = Column(String(20))                             # e.g. T1110
    mitre_tactic = Column(String(50))                                # e.g. Credential Access
    description = Column(String(500))
    tags = Column(String(255), default="")
    is_active = Column(Boolean, nullable=False, default=True)
    first_seen = Column(TIMESTAMP, server_default=text("CURRENT_TIMESTAMP"))
    last_seen = Column(TIMESTAMP, server_default=text("CURRENT_TIMESTAMP"))


class ThreatLookupAudit(Base):
    __tablename__ = "threat_lookup_audit"

    id = Column(Integer, primary_key=True, index=True)
    indicator_value = Column(String(255), nullable=False, index=True)
    matched = Column(Boolean, nullable=False, default=False)
    threat_score = Column(Integer, nullable=False, default=0)
    severity = Column(String(20), nullable=False, default="LOW")
    queried_by = Column(String(100), default="system")
    context = Column(String(255), default="")
    lookup_time = Column(TIMESTAMP, server_default=text("CURRENT_TIMESTAMP"))


class ThreatFeedSync(Base):
    __tablename__ = "threat_feed_sync"

    id = Column(Integer, primary_key=True, index=True)
    feed_name = Column(String(100), unique=True, nullable=False)
    feed_url = Column(String(255), nullable=False)
    indicator_count = Column(Integer, nullable=False, default=0)
    last_sync_at = Column(TIMESTAMP, server_default=text("CURRENT_TIMESTAMP"))
    sync_status = Column(String(30), nullable=False, default="PENDING")
    error_message = Column(String(500))
