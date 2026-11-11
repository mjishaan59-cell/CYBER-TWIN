"""
Incident Response Playbooks & Evidence Locker API Router
Phase 29 - Advanced Incident Response & Playbooks Subsystem
"""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.auth.dependencies import get_current_user, require_roles
from backend.incident_response.incident_timeline_service import incident_timeline_service

router = APIRouter(
    prefix="/incident-response",
    tags=["Incident Response & Playbooks"]
)


class ExecutePlaybookRequest(BaseModel):
    playbook_id: str = Field(..., min_length=2, max_length=60)
    target_hostname: str = Field("localhost", max_length=100)
    incident_id: Optional[str] = Field("", max_length=64)
    mode: str = Field("DRY_RUN", description="DRY_RUN or LIVE")
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict)


class AttachEvidenceRequest(BaseModel):
    artifact_type: str = Field(..., max_length=50)  # PCAP, MEMORY_DUMP, LOG_SNIPPET, FILE_HASH, IOC
    file_name: str = Field(..., min_length=1, max_length=120)
    file_hash_sha256: Optional[str] = Field("", max_length=64)
    description: Optional[str] = Field("", max_length=255)
    metadata_json: Optional[Dict[str, Any]] = Field(default_factory=dict)


class AddTimelineEventRequest(BaseModel):
    event_type: str = Field(..., max_length=50)  # NOTE, TELEMETRY, ALERT, STATUS_CHANGE
    title: str = Field(..., min_length=2, max_length=150)
    source: Optional[str] = Field("Analyst", max_length=60)
    severity: Optional[str] = Field("INFO", max_length=20)
    details: Optional[str] = Field("", max_length=1000)


@router.get("/playbooks")
def get_playbooks(
    current_user = Depends(get_current_user)
):
    """Retrieve catalog of automated and analyst-assisted response playbooks."""
    return incident_timeline_service.list_playbooks()


@router.post("/playbooks/execute")
@router.post("/playbooks/run")
def execute_playbook(
    req: ExecutePlaybookRequest,
    current_user = Depends(require_roles({"admin", "analyst"}))
):
    """Execute a remediation playbook with safety guardrails and audit trail."""
    try:
        user_name = getattr(current_user, "username", "admin")
        return incident_timeline_service.execute_playbook(
            playbook_id=req.playbook_id,
            target_hostname=req.target_hostname,
            params=req.parameters,
            incident_id=req.incident_id or "",
            executed_by=user_name,
            mode=req.mode
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/playbooks/history")
def get_playbook_history(
    incident_id: Optional[str] = Query(None, description="Filter by incident ID"),
    target_hostname: Optional[str] = Query(None, description="Filter by target host"),
    limit: int = Query(50, ge=1, le=100),
    current_user = Depends(get_current_user)
):
    """Retrieve audit history of playbook executions."""
    return incident_timeline_service.list_playbook_history(
        incident_id=incident_id,
        target_hostname=target_hostname,
        limit=limit
    )


@router.get("/timeline/{incident_id}")
def get_incident_timeline(
    incident_id: str,
    current_user = Depends(get_current_user)
):
    """Retrieve complete chronological forensics timeline for an incident."""
    return incident_timeline_service.get_timeline(incident_id)


@router.post("/timeline/{incident_id}", status_code=status.HTTP_201_CREATED)
def add_timeline_event(
    incident_id: str,
    req: AddTimelineEventRequest,
    current_user = Depends(require_roles({"admin", "analyst"}))
):
    """Add an analyst note or observation event to an incident timeline."""
    return incident_timeline_service.add_timeline_event(
        incident_id=incident_id,
        event_type=req.event_type,
        title=req.title,
        source=req.source or "Analyst",
        severity=req.severity or "INFO",
        details=req.details or ""
    )


@router.get("/evidence/{incident_id}")
def get_incident_evidence(
    incident_id: str,
    current_user = Depends(get_current_user)
):
    """Retrieve forensic evidence artifacts attached to an incident."""
    return incident_timeline_service.list_evidence(incident_id)


@router.post("/evidence/{incident_id}", status_code=status.HTTP_201_CREATED)
def attach_incident_evidence(
    incident_id: str,
    req: AttachEvidenceRequest,
    current_user = Depends(require_roles({"admin", "analyst"}))
):
    """Attach a forensic evidence artifact (PCAP, log dump, hash) to an incident."""
    user_name = getattr(current_user, "username", "analyst")
    return incident_timeline_service.attach_evidence(
        incident_id=incident_id,
        artifact_type=req.artifact_type,
        file_name=req.file_name,
        file_hash_sha256=req.file_hash_sha256 or "",
        description=req.description or "",
        collected_by=user_name,
        metadata_json=req.metadata_json or {}
    )


@router.get("/stats")
def get_incident_response_stats(
    current_user = Depends(get_current_user)
):
    """Retrieve aggregate metrics for playbooks, safeguards, and evidence locker."""
    return incident_timeline_service.get_stats()
