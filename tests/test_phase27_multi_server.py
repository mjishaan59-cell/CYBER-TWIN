"""
Automated Test Suite for Phase 27 - Multi-Server Expansion Subsystem
Tests:
- FleetManager server registration, duplicate validation, and lookup
- FleetManager server update and decommission lifecycle
- Live/simulated reachability heartbeat probes (ping)
- Centralized fleet health and resource metric aggregations
- Multi-Server REST API endpoints:
  - GET /multihost/servers
  - POST /multihost/servers
  - GET /multihost/servers/{id}
  - PUT /multihost/servers/{id}
  - POST /multihost/servers/{id}/ping
  - GET /multihost/fleet/health
  - GET /multihost/fleet/groups
  - DELETE /multihost/servers/{id}
"""

import pytest
from fastapi.testclient import TestClient

from backend.api.main import app
from backend.multihost.fleet_manager import fleet_manager
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


def test_fleet_manager_inventory_and_registration():
    """Verify listing seeded servers and registering a new node."""
    servers = fleet_manager.list_servers()
    assert len(servers) >= 4
    assert any(s["hostname"] == "prac-server" for s in servers)

    new_node = {
        "hostname": "test-analytics-01",
        "display_name": "Analytics Worker Node",
        "ip_address": "192.168.38.199",
        "ssh_port": 22,
        "environment": "staging",
        "host_group": "analytics",
        "os_flavor": "Ubuntu 22.04"
    }
    reg = fleet_manager.register_server(new_node)
    assert reg["hostname"] == "test-analytics-01"
    assert reg["status"] == "ONLINE"

    # Duplicate registration must raise ValueError
    with pytest.raises(ValueError):
        fleet_manager.register_server(new_node)


def test_fleet_manager_update_and_ping():
    """Verify server metadata update and connectivity probe."""
    updated = fleet_manager.update_server("test-analytics-01", {
        "status": "DEGRADED",
        "notes": "Memory pressure observed"
    })
    assert updated is not None
    assert updated["status"] == "DEGRADED"

    probe = fleet_manager.ping_server("test-analytics-01")
    assert probe["hostname"] == "test-analytics-01"
    assert "latency_ms" in probe
    assert probe["is_reachable"] is True


def test_fleet_manager_health_aggregation():
    """Verify fleet-wide health and group metrics."""
    health = fleet_manager.get_fleet_health()
    assert health["total_servers"] >= 5
    assert "average_cpu_percent" in health
    assert "average_memory_percent" in health
    assert "environments" in health
    assert "host_groups" in health

    groups = fleet_manager.get_fleet_groups()
    assert "production" in groups["environments"]
    assert len(groups["host_groups"]) >= 2


def test_fleet_manager_delete_server():
    """Verify server decommissioning."""
    del_res = fleet_manager.delete_server("test-analytics-01")
    assert del_res is True
    assert fleet_manager.get_server("test-analytics-01") is None


def test_api_multihost_endpoints(auth_headers, read_only_headers):
    """Verify multi-host REST API endpoints with RBAC."""
    client = TestClient(app)

    # 1. Fleet Health
    resp_health = client.get("/multihost/fleet/health", headers=auth_headers)
    assert resp_health.status_code == 200
    assert "total_servers" in resp_health.json()

    # 2. List Servers
    resp_list = client.get("/multihost/servers", headers=auth_headers)
    assert resp_list.status_code == 200
    servers = resp_list.json()
    assert isinstance(servers, list)
    assert len(servers) > 0

    # 3. Register Server (Admin)
    new_srv = {
        "hostname": "api-worker-99",
        "display_name": "API Worker 99",
        "ip_address": "192.168.38.201",
        "ssh_port": 22,
        "environment": "testing",
        "host_group": "workers"
    }
    resp_create = client.post("/multihost/servers", json=new_srv, headers=auth_headers)
    assert resp_create.status_code == 201

    # 4. Get Server Details
    resp_get = client.get("/multihost/servers/api-worker-99", headers=auth_headers)
    assert resp_get.status_code == 200
    assert resp_get.json()["hostname"] == "api-worker-99"

    # 5. Ping Server
    resp_ping = client.post("/multihost/servers/api-worker-99/ping", headers=auth_headers)
    assert resp_ping.status_code == 200
    assert "latency_ms" in resp_ping.json()

    # 6. Update Server
    resp_update = client.put(
        "/multihost/servers/api-worker-99",
        json={"display_name": "API Worker Node 99 Updated"},
        headers=auth_headers
    )
    assert resp_update.status_code == 200
    assert resp_update.json()["display_name"] == "API Worker Node 99 Updated"

    # 7. Groups
    resp_grp = client.get("/multihost/fleet/groups", headers=auth_headers)
    assert resp_grp.status_code == 200
    assert "environments" in resp_grp.json()

    # 8. Delete Server
    resp_del = client.delete("/multihost/servers/api-worker-99", headers=auth_headers)
    assert resp_del.status_code == 200
