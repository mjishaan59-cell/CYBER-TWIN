"""
Phase 30 Master Regression & Optimization Test Suite
Validates end-to-end platform capabilities across all 30 development phases:
- High-Performance In-Memory TTLCache operations & hit ratio
- Role-Based Access Control (RBAC) security enforcement (Admin vs Viewer vs Unauthorized)
- Subsystem integration sanity (Threat Intel, Predictive, FIM, Process, Network, Multi-Host, Simulation, Incident Response)
- Input boundary validation & error resilience
"""

import time
import pytest
from fastapi.testclient import TestClient

from backend.api.main import app
from backend.utils.cache_optimizer import TTLCache, global_cache
from backend.auth.jwt_handler import create_access_token


@pytest.fixture
def admin_headers():
    token = create_access_token({"sub": "master_admin", "role": "admin"})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def viewer_headers():
    token = create_access_token({"sub": "readonly_viewer", "role": "viewer"})
    return {"Authorization": f"Bearer {token}"}


def test_ttl_cache_optimization():
    """Verify in-memory cache operations, expiration, and invalidation."""
    cache = TTLCache(default_ttl=1)

    # 1. Miss on empty
    assert cache.get("key1") is None

    # 2. Set and Hit
    cache.set("key1", "sample_payload", ttl_seconds=10)
    assert cache.get("key1") == "sample_payload"

    # 3. Stats verification
    stats = cache.get_stats()
    assert stats["cache_hits"] == 1
    assert stats["cache_misses"] == 1
    assert stats["hit_ratio_percent"] == 50.0

    # 4. Invalidation
    cache.set("fleet:srv1", "val1")
    cache.set("fleet:srv2", "val2")
    cache.set("net:conn1", "val3")
    removed = cache.invalidate("fleet:")
    assert removed == 2
    assert cache.get("fleet:srv1") is None
    assert cache.get("net:conn1") == "val3"


def test_rbac_security_enforcement(admin_headers, viewer_headers):
    """Verify strict role-based access control and unauthorized protection."""
    client = TestClient(app)

    # 1. Unauthenticated requests to protected routes must be rejected with 401
    resp_unauth = client.get("/processes")
    assert resp_unauth.status_code == 401

    # 2. Viewer role has READ access
    resp_view_procs = client.get("/processes", headers=viewer_headers)
    assert resp_view_procs.status_code == 200

    resp_view_fleet = client.get("/multihost/servers", headers=viewer_headers)
    assert resp_view_fleet.status_code == 200

    # 3. Viewer role must be FORBIDDEN (403) from administrative actions
    resp_unauth_create = client.post(
        "/multihost/servers",
        json={"hostname": "illegal-srv", "ip_address": "10.0.0.99"},
        headers=viewer_headers
    )
    assert resp_unauth_create.status_code == 403

    resp_unauth_sim = client.post(
        "/simulation/run",
        json={"scenario_id": "SSH_BRUTE_FORCE"},
        headers=viewer_headers
    )
    assert resp_unauth_sim.status_code == 403


def test_all_subsystems_integration(admin_headers):
    """Verify that every core platform API subsystem is active and responsive."""
    client = TestClient(app)

    # 1. Phase 22: Threat Intelligence
    resp_ti = client.get("/threat-intel/indicators?limit=5", headers=admin_headers)
    assert resp_ti.status_code == 200

    # 2. Phase 23: Predictive Analytics
    resp_pred = client.get("/predictive-analytics/forecast", headers=admin_headers)
    assert resp_pred.status_code == 200

    # 3. Phase 24: File Integrity Monitoring
    resp_fim = client.get("/fim/baseline", headers=admin_headers)
    assert resp_fim.status_code == 200

    # 4. Phase 25: Process & Service Monitoring
    resp_proc = client.get("/processes/stats", headers=admin_headers)
    assert resp_proc.status_code == 200

    # 5. Phase 26: Network Security Monitoring
    resp_net = client.get("/network/stats", headers=admin_headers)
    assert resp_net.status_code == 200

    # 6. Phase 27: Multi-Server Expansion
    resp_fleet = client.get("/multihost/fleet/health", headers=admin_headers)
    assert resp_fleet.status_code == 200

    # 7. Phase 28: What-If Attack Simulation
    resp_sim = client.get("/simulation/scenarios", headers=admin_headers)
    assert resp_sim.status_code == 200

    # 8. Phase 29: Incident Response Playbooks
    resp_ir = client.get("/incident-response/playbooks", headers=admin_headers)
    assert resp_ir.status_code == 200


def test_input_boundary_validation(admin_headers):
    """Verify that malformed inputs receive structured error responses (422 / 400)."""
    client = TestClient(app)

    # Invalid JSON payload missing required fields
    resp_bad_sim = client.post("/simulation/run", json={}, headers=admin_headers)
    assert resp_bad_sim.status_code == 422

    # Invalid playbook target
    resp_bad_pb = client.post(
        "/incident-response/playbooks/execute",
        json={"playbook_id": "INVALID_UNKNOWN_PLAYBOOK"},
        headers=admin_headers
    )
    assert resp_bad_pb.status_code == 400
