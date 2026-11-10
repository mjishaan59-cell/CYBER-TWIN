"""
Database Models for Phase 27 - Multi-Server Expansion Subsystem
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
    Index
)
from backend.database import Base


class ManagedServer(Base):
    """
    Registered managed Linux host within the enterprise digital twin fleet.
    """
    __tablename__ = "managed_servers"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(100), unique=True, nullable=False, index=True)
    display_name = Column(String(120), nullable=False)
    ip_address = Column(String(50), nullable=False, index=True)
    ssh_port = Column(Integer, default=22)
    ssh_username = Column(String(50), default="root")
    auth_method = Column(String(20), default="key")  # key, password, agent
    environment = Column(String(30), default="production", index=True)  # production, staging, testing, dmz
    host_group = Column(String(50), default="general", index=True)  # web_servers, db_clusters, edge_gateways
    os_flavor = Column(String(80), default="Linux Enterprise 9")
    status = Column(String(20), default="ONLINE", index=True)  # ONLINE, OFFLINE, DEGRADED, MAINTENANCE
    latency_ms = Column(Float, default=1.5)
    cpu_usage = Column(Float, default=15.0)
    memory_usage = Column(Float, default=32.0)
    disk_usage = Column(Float, default=45.0)
    tags = Column(String(255), default="")
    notes = Column(Text, default="")
    is_active = Column(Boolean, default=True)
    last_heartbeat_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ServerHealthHeartbeat(Base):
    """
    Historical log of server connectivity heartbeats and reachability probes.
    """
    __tablename__ = "server_health_heartbeats"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(100), nullable=False, index=True)
    status = Column(String(20), default="ONLINE")
    latency_ms = Column(Float, default=0.0)
    is_reachable = Column(Boolean, default=True)
    error_message = Column(String(255), default="")
    probed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
