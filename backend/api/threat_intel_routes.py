"""
Threat Intelligence FastAPI Router
Phase 22 - AI Threat Intelligence Subsystem
"""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.auth.dependencies import get_current_user, require_roles
from backend.threat_intel.threat_service import threat_intel_service
from backend.threat_intel.mitre_mapper import get_all_mitre_techniques
from backend.threat_intel.threat_correlator import ThreatCorrelator

router = APIRouter(
    prefix="/threat-intel",
    tags=["Threat Intelligence"]
)


class CustomIndicatorRequest(BaseModel):
    indicator_value: str = Field(..., min_length=3, max_length=255)
    indicator_type: Optional[str] = Field(None, max_length=30)
    threat_type: str = Field(..., min_length=2, max_length=50)
    severity: str = Field("MEDIUM", max_length=20)
    confidence_score: int = Field(80, ge=0, le=100)
    description: Optional[str] = Field(None, max_length=500)
    tags: Optional[str] = Field("", max_length=255)


class CorrelateRequest(BaseModel):
    indicators: List[str] = Field(..., min_length=1)
    context: Optional[Dict[str, Any]] = None


@router.get("/indicators")
def get_threat_indicators(
    indicator_type: Optional[str] = Query(None, description="Filter by type (IP, DOMAIN, SHA256, URL)"),
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user = Depends(get_current_user)
):
    """Retrieve cataloged threat indicators / IOCs."""
    return threat_intel_service.list_indicators(
        indicator_type=indicator_type,
        severity=severity,
        limit=limit,
        offset=offset
    )


@router.get("/lookup/{indicator}")
def lookup_threat_indicator(
    indicator: str,
    current_user = Depends(get_current_user)
):
    """Real-time threat intelligence lookup for an IP, domain, hash, or URL."""
    username = getattr(current_user, "username", "authenticated_user") if hasattr(current_user, "username") else (
        current_user.get("username", "user") if isinstance(current_user, dict) else "user"
    )
    result = threat_intel_service.lookup(indicator, user=username, context="api_lookup")
    return result


@router.post("/indicators", status_code=status.HTTP_201_CREATED)
def create_custom_indicator(
    req: CustomIndicatorRequest,
    current_user = Depends(require_roles({"admin", "analyst"}))
):
    """Register a custom threat intelligence indicator (Admin / Analyst)."""
    username = getattr(current_user, "username", "analyst") if hasattr(current_user, "username") else (
        current_user.get("username", "analyst") if isinstance(current_user, dict) else "analyst"
    )
    data = req.model_dump()
    data["source_feed"] = f"Analyst ({username})"
    indicator = threat_intel_service.add_custom_indicator(data)
    return {
        "status": "CREATED",
        "indicator": indicator
    }


@router.post("/correlate")
def correlate_indicators(
    req: CorrelateRequest,
    current_user = Depends(get_current_user)
):
    """Batch correlate a list of indicators (e.g. IPs) against the threat intelligence repository."""
    results = []
    for item in req.indicators:
        res = threat_intel_service.correlator.correlate_ip(item, context=req.context)
        results.append(res)
    return {
        "total_analyzed": len(results),
        "matches_found": sum(1 for r in results if r["matched"]),
        "results": results
    }


@router.post("/sync-feeds")
def sync_threat_feeds(
    current_user = Depends(require_roles({"admin"}))
):
    """Trigger threat feed collection and synchronization (Admin only)."""
    sync_result = threat_intel_service.sync_feeds()
    return {
        "status": "SUCCESS",
        "sync_details": sync_result
    }


@router.get("/stats")
def get_threat_stats(
    current_user = Depends(get_current_user)
):
    """Retrieve statistical summary for Threat Intelligence dashboard."""
    return threat_intel_service.get_stats()


@router.get("/mitre")
def get_mitre_catalog(
    current_user = Depends(get_current_user)
):
    """Get the MITRE ATT&CK techniques catalog."""
    return get_all_mitre_techniques()
