"""
Multi-Server Management & Distributed Fleet API Router
Phase 27 - Multi-Server Expansion Subsystem
"""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.auth.dependencies import get_current_user, require_roles
from backend.multihost.fleet_manager import fleet_manager

router = APIRouter(
    prefix="/multihost",
    tags=["Multi-Server Expansion"]
)


class ServerRegistrationRequest(BaseModel):
    hostname: str = Field(..., min_length=2, max_length=100)
    display_name: Optional[str] = Field(None, max_length=120)
    ip_address: str = Field(..., min_length=7, max_length=50)
    ssh_port: int = Field(22, ge=1, le=65535)
    ssh_username: str = Field("root", max_length=50)
    auth_method: str = Field("key", max_length=20)
    environment: str = Field("production", max_length=30)
    host_group: str = Field("general", max_length=50)
    os_flavor: str = Field("Linux Enterprise 9", max_length=80)
    tags: Optional[str] = Field("", max_length=255)
    notes: Optional[str] = Field("", max_length=1000)


class ServerUpdateRequest(BaseModel):
    display_name: Optional[str] = None
    ip_address: Optional[str] = None
    ssh_port: Optional[int] = None
    ssh_username: Optional[str] = None
    auth_method: Optional[str] = None
    environment: Optional[str] = None
    host_group: Optional[str] = None
    os_flavor: Optional[str] = None
    status: Optional[str] = None
    tags: Optional[str] = None
    notes: Optional[str] = None


@router.get("/servers")
def list_managed_servers(
    environment: Optional[str] = Query(None, description="Filter by environment (production, staging, dmz)"),
    host_group: Optional[str] = Query(None, description="Filter by host group"),
    status: Optional[str] = Query(None, description="Filter by status (ONLINE, OFFLINE)"),
    current_user = Depends(get_current_user)
):
    """Retrieve list of managed fleet servers."""
    return fleet_manager.list_servers(
        environment=environment,
        host_group=host_group,
        status_filter=status
    )


@router.post("/servers", status_code=status.HTTP_201_CREATED)
def register_server(
    req: ServerRegistrationRequest,
    current_user = Depends(require_roles({"admin"}))
):
    """Register a new Linux server in the multi-server inventory."""
    try:
        data = req.model_dump() if hasattr(req, "model_dump") else req.dict()
        return fleet_manager.register_server(data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/servers/{identifier}")
def get_server_details(
    identifier: str,
    current_user = Depends(get_current_user)
):
    """Retrieve detailed metadata and health stats for a specific server."""
    server = fleet_manager.get_server(identifier)
    if not server:
        raise HTTPException(status_code=404, detail=f"Server '{identifier}' not found")
    return server


@router.put("/servers/{identifier}")
def update_server(
    identifier: str,
    req: ServerUpdateRequest,
    current_user = Depends(require_roles({"admin", "analyst"}))
):
    """Update managed server metadata, group, environment, or status."""
    patch = req.model_dump(exclude_unset=True) if hasattr(req, "model_dump") else req.dict(exclude_unset=True)
    updated = fleet_manager.update_server(identifier, patch)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Server '{identifier}' not found")
    return updated


@router.delete("/servers/{identifier}")
def deregister_server(
    identifier: str,
    current_user = Depends(require_roles({"admin"}))
):
    """Decommission and remove a server from the managed fleet."""
    success = fleet_manager.delete_server(identifier)
    if not success:
        raise HTTPException(status_code=404, detail=f"Server '{identifier}' not found")
    return {"message": f"Server '{identifier}' deregistered successfully"}


@router.post("/servers/{identifier}/ping")
def ping_server(
    identifier: str,
    current_user = Depends(require_roles({"admin", "analyst"}))
):
    """Dispatch a live probe to check server connectivity and latency."""
    try:
        return fleet_manager.ping_server(identifier)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/fleet/health")
def get_fleet_health(
    current_user = Depends(get_current_user)
):
    """Retrieve aggregate fleet health, status breakdown, and resource averages."""
    return fleet_manager.get_fleet_health()


@router.get("/fleet/groups")
def get_fleet_groups(
    current_user = Depends(get_current_user)
):
    """Retrieve available environments and server grouping categories."""
    return fleet_manager.get_fleet_groups()
