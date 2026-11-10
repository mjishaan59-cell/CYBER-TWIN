"""
Production End-to-End API Integration Verification Suite
Tests all 20 mission-critical REST API endpoints across all platform subsystems:
1. Root HTML delivery
2. OpenAPI / Swagger documentation
3. Health & Liveness probe (unauthenticated)
4. Authentication & JWT token issuing
5. Real-time hardware telemetry
6. Metrics time-series history
7. Threat intelligence indicators
8. Threat intelligence statistics
9. What-if simulation scenario catalog
10. Simulation execution
11. Simulation history
12. Incident response playbook catalog
13. Playbook execution (dry-run & live)
14. File integrity monitoring (FIM) scan by path
15. FIM scan with JSON body
16. Process monitoring inventory
17. Systemd service units
18. Network interfaces
19. Network active connections & sockets
20. Fleet server inventory & predictive ML resource forecast
"""

import pytest
from fastapi.testclient import TestClient
from backend.api.main import app

client = TestClient(app)


def get_admin_token() -> str:
    res = client.post("/auth/login", json={"username": "admin", "password": "admin123"})
    assert res.status_code == 200
    return res.json()["access_token"]


def test_e2e_01_root_html_dashboard():
    res = client.get("/", headers={"Accept": "text/html,application/xhtml+xml"})
    assert res.status_code == 200
    assert "text/html" in res.headers.get("content-type", "")
    assert "Cyber Digital Twin Dashboard" in res.text


def test_e2e_02_swagger_documentation():
    res = client.get("/docs")
    assert res.status_code == 200
    assert "swagger" in res.text.lower() or "openapi" in res.text.lower()


def test_e2e_03_health_probe_unauthenticated():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert "status" in data
    assert data["status"] in ("Healthy", "Warning", "Critical")


def test_e2e_04_auth_jwt_login():
    res = client.post("/auth/login", json={"username": "admin", "password": "admin123"})
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["role"] == "admin"


def test_e2e_05_live_hardware_metrics():
    token = get_admin_token()
    res = client.get("/metrics", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list) and len(data) >= 1
    assert "cpu_usage" in data[0]
    assert "memory_usage" in data[0]


def test_e2e_06_metrics_history():
    token = get_admin_token()
    res = client.get("/metrics/history", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_e2e_07_threat_intel_indicators():
    token = get_admin_token()
    res = client.get("/threat-intel/indicators", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_e2e_08_threat_intel_stats():
    token = get_admin_token()
    res = client.get("/threat-intel/stats", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    assert "total_active_iocs" in data or "total_indicators" in data


def test_e2e_09_simulation_scenarios_catalog():
    token = get_admin_token()
    res = client.get("/simulation/scenarios", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 5


def test_e2e_10_simulation_execution():
    token = get_admin_token()
    payload = {"scenario_id": "SSH_BRUTE_FORCE", "target_hostname": "localhost"}
    res = client.post("/simulation/run", json=payload, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 201
    data = res.json()
    assert "simulation_id" in data


def test_e2e_11_simulation_history():
    token = get_admin_token()
    res = client.get("/simulation/history", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_e2e_12_playbook_catalog():
    token = get_admin_token()
    res = client.get("/incident-response/playbooks", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert len(res.json()) >= 5


def test_e2e_13_playbook_execution_run_and_execute():
    token = get_admin_token()
    payload = {
        "playbook_id": "BLOCK_MALICIOUS_IP",
        "target_hostname": "localhost",
        "parameters": {"ip_address": "198.51.100.42"},
        "mode": "DRY_RUN"
    }
    # Test both /run and /execute aliases
    res1 = client.post("/incident-response/playbooks/run", json=payload, headers={"Authorization": f"Bearer {token}"})
    assert res1.status_code == 200
    assert res1.json()["status"] == "SUCCESS"

    res2 = client.post("/incident-response/playbooks/execute", json=payload, headers={"Authorization": f"Bearer {token}"})
    assert res2.status_code == 200
    assert res2.json()["status"] == "SUCCESS"


def test_e2e_14_fim_scan_by_path():
    token = get_admin_token()
    res = client.post("/fim/scan/localhost", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    assert "scanned_files_count" in data


def test_e2e_15_fim_scan_by_body():
    token = get_admin_token()
    res = client.post("/fim/scan", json={"hostname": "localhost"}, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.json()
    assert "scanned_files_count" in data


def test_e2e_16_process_inventory():
    token = get_admin_token()
    res = client.get("/processes", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_e2e_17_systemd_services():
    token = get_admin_token()
    res = client.get("/processes/services", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_e2e_18_network_interfaces():
    token = get_admin_token()
    res = client.get("/network/interfaces", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_e2e_19_network_connections():
    token = get_admin_token()
    res = client.get("/network/connections", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_e2e_20_multihost_servers_and_predictive_forecast():
    token = get_admin_token()
    res_servers = client.get("/multihost/servers", headers={"Authorization": f"Bearer {token}"})
    assert res_servers.status_code == 200
    assert isinstance(res_servers.json(), list)

    res_forecast = client.get("/predictive/forecast", headers={"Authorization": f"Bearer {token}"})
    assert res_forecast.status_code == 200
    data = res_forecast.json()
    assert "cpu" in data and "memory" in data
