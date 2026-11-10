"""
Process & Service Monitoring FastAPI Router
Phase 25 - Process and Service Monitoring Subsystem
"""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.auth.dependencies import get_current_user, require_roles
from backend.process_monitoring.process_service import process_service

router = APIRouter(
    prefix="/processes",
    tags=["Process & Service Monitoring"]
)


class TriggerScanRequest(BaseModel):
    hostname: str = Field("prac-server", max_length=100)


@router.get("")
def get_processes(
    hostname: str = Query("prac-server", description="Host name"),
    sort_by: str = Query("cpu", description="Sort by 'cpu' or 'memory'"),
    suspicious_only: bool = Query(False, description="Filter only suspicious processes"),
    limit: int = Query(50, ge=1, le=200),
    current_user = Depends(get_current_user)
):
    """Retrieve running process list for monitored Linux host."""
    return process_service.list_processes(
        hostname=hostname,
        suspicious_only=suspicious_only,
        sort_by=sort_by,
        limit=limit
    )


@router.get("/suspicious")
def get_suspicious_processes(
    hostname: str = Query("prac-server", description="Host name"),
    current_user = Depends(get_current_user)
):
    """Retrieve only suspicious, anomalous, or malicious processes."""
    return process_service.list_processes(
        hostname=hostname,
        suspicious_only=True,
        limit=50
    )


@router.get("/services")
def get_systemd_services(
    hostname: str = Query("prac-server", description="Host name"),
    failed_only: bool = Query(False, description="Filter only failed systemd units"),
    current_user = Depends(get_current_user)
):
    """Retrieve systemd service unit states (running, dead, failed)."""
    return process_service.list_services(
        hostname=hostname,
        failed_only=failed_only
    )


@router.get("/alerts")
def get_process_alerts(
    hostname: Optional[str] = Query(None, description="Host name"),
    limit: int = Query(50, ge=1, le=100),
    current_user = Depends(get_current_user)
):
    """Retrieve process and service security alerts."""
    return process_service.list_alerts(hostname=hostname, limit=limit)


@router.get("/stats")
def get_process_stats(
    hostname: str = Query("prac-server", description="Host name"),
    current_user = Depends(get_current_user)
):
    """Retrieve summary metrics for processes and systemd services."""
    return process_service.get_stats(hostname=hostname)


@router.post("/scan")
def trigger_process_scan(
    req: TriggerScanRequest,
    current_user = Depends(require_roles({"admin", "analyst"}))
):
    """Trigger an immediate process discovery and systemd audit scan."""
    return process_service.scan_host(hostname=req.hostname)
