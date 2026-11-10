"""
File Integrity Monitoring FastAPI Router
Phase 24 - File Integrity Monitoring Subsystem
"""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.auth.dependencies import get_current_user, require_roles
from backend.fim.fim_service import fim_service
from backend.fim.fim_config import CRITICAL_LINUX_PATHS

router = APIRouter(
    prefix="/fim",
    tags=["File Integrity Monitoring"]
)


class BaselineEntry(BaseModel):
    file_path: str = Field(..., min_length=1, max_length=500)
    sha256_hash: str = Field(..., min_length=64, max_length=64)
    file_size_bytes: int = Field(0, ge=0)
    permissions: str = Field("0644", max_length=10)
    owner_name: str = Field("root", max_length=50)
    group_name: str = Field("root", max_length=50)


class CreateBaselineRequest(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=100)
    records: List[BaselineEntry] = Field(..., min_length=1)


class TriggerScanRequest(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=100)
    active_snapshot: Optional[List[Dict[str, Any]]] = None


@router.get("/events")
def get_fim_events(
    hostname: Optional[str] = Query(None, description="Filter by host"),
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    limit: int = Query(50, ge=1, le=500),
    current_user = Depends(get_current_user)
):
    """Retrieve recorded file integrity violation events."""
    return fim_service.list_events(hostname=hostname, severity=severity, limit=limit)


@router.get("/baseline")
def get_host_baseline(
    hostname: str = Query("prac-server", description="Host name"),
    current_user = Depends(get_current_user)
):
    """Retrieve the established integrity baseline for a monitored host."""
    return fim_service.get_baseline(hostname)


@router.post("/baseline/create", status_code=status.HTTP_201_CREATED)
def create_host_baseline(
    req: CreateBaselineRequest,
    current_user = Depends(require_roles({"admin"}))
):
    """Snapshot a new cryptographic baseline with tamper seal (Admin only)."""
    raw_records = [r.model_dump() for r in req.records]
    return fim_service.create_or_update_baseline(req.hostname, raw_records)


@router.post("/scan")
def trigger_integrity_scan(
    req: TriggerScanRequest,
    current_user = Depends(require_roles({"admin", "analyst"}))
):
    """Execute an immediate file integrity verification scan against baseline."""
    return fim_service.scan_host_integrity(req.hostname, req.active_snapshot)


@router.get("/stats")
def get_fim_stats(
    hostname: str = Query("prac-server", description="Host name"),
    current_user = Depends(get_current_user)
):
    """Retrieve File Integrity Monitoring dashboard statistics."""
    return fim_service.get_stats(hostname)


@router.get("/critical-paths")
def get_critical_paths(
    current_user = Depends(get_current_user)
):
    """Retrieve catalog of default monitored critical Linux security paths."""
    return CRITICAL_LINUX_PATHS
