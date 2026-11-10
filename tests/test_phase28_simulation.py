"""
Automated Test Suite for Phase 28 - What-If Attack Simulation Subsystem
Tests:
- SimulationEngine scenario catalog and retrieval
- SimulationEngine synthetic execution and impact prediction (risk score, MTTD, MTTR, containment probability)
- SimulationService execution, persistence, step logging, and history
- Simulation REST API endpoints:
  - GET /simulation/scenarios
  - POST /simulation/run
  - GET /simulation/history
  - GET /simulation/history/{simulation_id}
  - GET /simulation/stats
"""

import pytest
from fastapi.testclient import TestClient

from backend.api.main import app
from backend.simulation.simulation_engine import SimulationEngine, SCENARIO_CATALOG
from backend.simulation.simulation_service import simulation_service
from backend.auth.jwt_handler import create_access_token


@pytest.fixture
def auth_headers():
    token = create_access_token({
        "sub": "testadmin",
        "role": "admin"
    })
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def read_only_headers():
    token = create_access_token({
        "sub": "readonly_user",
        "role": "viewer"
    })
    return {"Authorization": f"Bearer {token}"}


def test_simulation_engine_scenarios():
    """Verify catalog has all 6 synthetic adversary scenarios."""
    scenarios = SimulationEngine.list_scenarios()
    assert len(scenarios) == 6
    scenario_ids = [s["scenario_id"] for s in scenarios]
    assert "SSH_BRUTE_FORCE" in scenario_ids
    assert "REVERSE_SHELL_INJECTION" in scenario_ids
    assert "PRIVILEGE_ESCALATION_SUID" in scenario_ids
    assert "DATA_EXFILTRATION_DNS" in scenario_ids
    assert "RANSOMWARE_BURST" in scenario_ids
    assert "RESOURCE_DOS_ATTACK" in scenario_ids


def test_simulation_engine_execution():
    """Verify safe synthetic execution and impact metrics generation."""
    res = SimulationEngine.run_simulation(
        scenario_id="SSH_BRUTE_FORCE",
        target_hostname="prac-server",
        simulated_by="tester"
    )
    assert res["status"] == "COMPLETED"
    assert res["risk_score"] == 75
    assert res["impact_level"] == "HIGH"
    assert res["estimated_mttd_seconds"] > 0
    assert res["estimated_mttr_seconds"] > 0
    assert res["predicted_containment_probability"] > 50.0
    assert len(res["defensive_recommendations"]) >= 2
    assert len(res["steps"]) >= 3

    # Unknown scenario validation
    with pytest.raises(ValueError):
        SimulationEngine.run_simulation("NON_EXISTENT_ATTACK", "prac-server")


def test_simulation_service_history_and_stats():
    """Verify service tracking, history retrieval, and stats calculation."""
    run = simulation_service.run_simulation(
        scenario_id="RANSOMWARE_BURST",
        target_hostname="prod-web-01",
        simulated_by="admin"
    )
    sim_id = run["simulation_id"]
    assert sim_id.startswith("sim-")

    retrieved = simulation_service.get_simulation(sim_id)
    assert retrieved is not None
    assert retrieved["scenario_id"] == "RANSOMWARE_BURST"
    assert retrieved["target_hostname"] == "prod-web-01"

    history = simulation_service.list_history()
    assert len(history) >= 3
    assert any(h["simulation_id"] == sim_id for h in history)

    stats = simulation_service.get_stats()
    assert stats["total_simulations_conducted"] >= 3
    assert stats["available_scenarios_count"] == 6


def test_api_simulation_endpoints(auth_headers, read_only_headers):
    """Verify simulation REST API endpoints with authentication."""
    client = TestClient(app)

    # 1. Scenarios Catalog
    resp_scenarios = client.get("/simulation/scenarios", headers=auth_headers)
    assert resp_scenarios.status_code == 200
    scens = resp_scenarios.json()
    assert isinstance(scens, list)
    assert len(scens) == 6

    # 2. Stats
    resp_stats = client.get("/simulation/stats", headers=auth_headers)
    assert resp_stats.status_code == 200
    assert "total_simulations_conducted" in resp_stats.json()

    # 3. Launch Simulation (Admin)
    req_body = {
        "scenario_id": "PRIVILEGE_ESCALATION_SUID",
        "target_hostname": "db-cluster-01"
    }
    resp_run = client.post("/simulation/run", json=req_body, headers=auth_headers)
    assert resp_run.status_code == 201
    sim_data = resp_run.json()
    assert sim_data["status"] == "COMPLETED"
    assert sim_data["scenario_id"] == "PRIVILEGE_ESCALATION_SUID"
    sim_id = sim_data["simulation_id"]

    # 4. History List
    resp_hist = client.get("/simulation/history", headers=auth_headers)
    assert resp_hist.status_code == 200
    assert isinstance(resp_hist.json(), list)

    # 5. Simulation Details
    resp_detail = client.get(f"/simulation/history/{sim_id}", headers=auth_headers)
    assert resp_detail.status_code == 200
    assert resp_detail.json()["simulation_id"] == sim_id
    assert "defensive_recommendations" in resp_detail.json()
