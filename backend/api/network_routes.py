"""
Network Security Monitoring FastAPI Router
Phase 26 - Network Security Monitoring Subsystem
"""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.auth.dependencies import get_current_user, require_roles
from backend.network_monitoring.network_service import network_service

router = APIRouter(
    prefix="/network",
    tags=["Network Security Monitoring"]
)


class TriggerNetworkScanRequest(BaseModel):
    hostname: str = Field("prac-server", max_length=100)


@router.get("/interfaces")
def get_interfaces(
    hostname: str = Query("prac-server", description="Host name"),
    current_user = Depends(get_current_user)
):
    """Retrieve network interfaces and traffic counters for host."""
    return network_service.list_interfaces(hostname=hostname)


@router.get("/connections")
def get_connections(
    hostname: str = Query("prac-server", description="Host name"),
    suspicious_only: bool = Query(False, description="Filter only suspicious socket connections"),
    limit: int = Query(50, ge=1, le=200),
    current_user = Depends(get_current_user)
):
    """Retrieve active network socket connections (TCP/UDP)."""
    return network_service.list_connections(
        hostname=hostname,
        suspicious_only=suspicious_only,
        limit=limit
    )


@router.get("/ports")
def get_listening_ports(
    hostname: str = Query("prac-server", description="Host name"),
    unauthorized_only: bool = Query(False, description="Filter only unexpected/unauthorized ports"),
    current_user = Depends(get_current_user)
):
    """Retrieve open listening sockets and bound services."""
    return network_service.list_listening_ports(
        hostname=hostname,
        unauthorized_only=unauthorized_only
    )


@router.get("/alerts")
def get_network_alerts(
    hostname: Optional[str] = Query(None, description="Host name"),
    limit: int = Query(50, ge=1, le=100),
    current_user = Depends(get_current_user)
):
    """Retrieve network security and anomaly alerts."""
    return network_service.list_alerts(hostname=hostname, limit=limit)


@router.get("/stats")
def get_network_stats(
    hostname: str = Query("prac-server", description="Host name"),
    current_user = Depends(get_current_user)
):
    """Retrieve summary network security metrics."""
    return network_service.get_stats(hostname=hostname)


@router.post("/scan")
def trigger_network_scan(
    req: TriggerNetworkScanRequest,
    current_user = Depends(require_roles({"admin", "analyst"}))
):
    """Trigger an on-demand network interface and socket inspection scan."""
    return network_service.scan_network(hostname=req.hostname)
