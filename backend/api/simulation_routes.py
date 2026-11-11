"""
What-If Attack Simulation API Router
Phase 28 - What-If Attack Simulation Subsystem
"""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.auth.dependencies import get_current_user, require_roles
from backend.simulation.simulation_service import simulation_service

router = APIRouter(
    prefix="/simulation",
    tags=["What-If Attack Simulation"]
)


class RunSimulationRequest(BaseModel):
    scenario_id: str = Field(..., min_length=2, max_length=60)
    target_hostname: str = Field("localhost", max_length=100)


@router.get("/scenarios")
def get_scenarios(
    current_user = Depends(get_current_user)
):
    """Retrieve catalog of available synthetic attack scenarios."""
    return simulation_service.list_scenarios()


@router.post("/run", status_code=status.HTTP_201_CREATED)
def run_simulation(
    req: RunSimulationRequest,
    current_user = Depends(require_roles({"admin", "analyst"}))
):
    """Execute a controlled What-If synthetic attack simulation."""
    try:
        user_sub = getattr(current_user, "username", "admin")
        return simulation_service.run_simulation(
            scenario_id=req.scenario_id,
            target_hostname=req.target_hostname,
            simulated_by=user_sub
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/history")
def get_simulation_history(
    target_hostname: Optional[str] = Query(None, description="Filter by target hostname"),
    limit: int = Query(50, ge=1, le=100),
    current_user = Depends(get_current_user)
):
    """Retrieve historical attack simulation exercises and outcomes."""
    return simulation_service.list_history(
        target_hostname=target_hostname,
        limit=limit
    )


@router.get("/history/{simulation_id}")
def get_simulation_details(
    simulation_id: str,
    current_user = Depends(get_current_user)
):
    """Retrieve detailed step-by-step logs and recommendations for a simulation."""
    sim = simulation_service.get_simulation(simulation_id)
    if not sim:
        raise HTTPException(status_code=404, detail=f"Simulation '{simulation_id}' not found")
    return sim


@router.get("/stats")
def get_simulation_stats(
    current_user = Depends(get_current_user)
):
    """Retrieve aggregate statistics on simulations conducted."""
    return simulation_service.get_stats()
