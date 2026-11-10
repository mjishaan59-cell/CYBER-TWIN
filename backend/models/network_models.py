"""
Database Models for Phase 26 - Network Security Monitoring Subsystem
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Boolean,
    DateTime,
    BigInteger,
    Index
)
from backend.database import Base


class NetworkInterfaceSnapshot(Base):
    """
    Periodic snapshot of network interface metrics and traffic.
    """
    __tablename__ = "network_interface_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(100), nullable=False, index=True)
    interface_name = Column(String(50), nullable=False)
    bytes_sent = Column(BigInteger, default=0)
    bytes_recv = Column(BigInteger, default=0)
    packets_sent = Column(BigInteger, default=0)
    packets_recv = Column(BigInteger, default=0)
    errin = Column(Integer, default=0)
    errout = Column(Integer, default=0)
    dropin = Column(Integer, default=0)
    dropout = Column(Integer, default=0)
    is_up = Column(Boolean, default=True)
    speed_mbps = Column(Integer, default=1000)
    recorded_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


class NetworkConnectionRecord(Base):
    """
    Active socket connections recorded on the host.
    """
    __tablename__ = "network_connection_records"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(100), nullable=False, index=True)
    protocol = Column(String(10), default="tcp")  # tcp, udp
    local_address = Column(String(100), nullable=False)
    local_port = Column(Integer, nullable=False)
    remote_address = Column(String(100), default="")
    remote_port = Column(Integer, default=0)
    status = Column(String(30), default="ESTABLISHED")  # ESTABLISHED, LISTEN, TIME_WAIT, SYN_SENT, etc.
    pid = Column(Integer, default=0)
    process_name = Column(String(100), default="")
    is_suspicious = Column(Boolean, default=False, index=True)
    risk_score = Column(Integer, default=0)
    threat_description = Column(String(255), default="")
    recorded_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    __table_args__ = (
        Index("idx_net_conn_remote", "remote_address", "remote_port"),
    )


class ListeningPortRecord(Base):
    """
    Open listening network sockets on monitored systems.
    """
    __tablename__ = "listening_port_records"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(100), nullable=False, index=True)
    protocol = Column(String(10), default="tcp")
    bind_address = Column(String(100), nullable=False)  # 0.0.0.0, 127.0.0.1, ::
    port = Column(Integer, nullable=False, index=True)
    pid = Column(Integer, default=0)
    process_name = Column(String(100), default="")
    is_authorized = Column(Boolean, default=True)
    service_hint = Column(String(50), default="")
    risk_level = Column(String(20), default="LOW")  # LOW, MEDIUM, HIGH, CRITICAL
    last_seen_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class NetworkSecurityAlert(Base):
    """
    Security alerts emitted by network anomaly and threat analyzers.
    """
    __tablename__ = "network_security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(100), nullable=False, index=True)
    alert_type = Column(String(60), nullable=False, index=True)
    severity = Column(String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    source_ip = Column(String(50), default="")
    source_port = Column(Integer, default=0)
    destination_ip = Column(String(50), default="")
    destination_port = Column(Integer, default=0)
    protocol = Column(String(10), default="TCP")
    mitre_technique = Column(String(50), default="")  # e.g., T1043, T1071, T1046
    description = Column(String(500), nullable=False)
    recommendation = Column(String(500), default="")
    resolved = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
