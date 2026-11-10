"""
Automated Test Suite for Phase 26 - Network Security Monitoring Subsystem
Tests:
- NetworkSecurityAnalyzer: High-risk listening port detection (Metasploit, Elite trojans)
- NetworkSecurityAnalyzer: Authorized baseline ports (SSH, HTTP, HTTPS, PostgreSQL)
- NetworkSecurityAnalyzer: Threat intelligence IOC correlation on socket destination
- NetworkSecurityAnalyzer: Outbound port scan heuristic (SYN_SENT)
- NetworkSecurityAnalyzer: Network interface degradation / link down evaluation
- NetworkMonitoringService scan execution, port extraction, and summary statistics
- Network REST API endpoints:
  - GET /network/interfaces
  - GET /network/connections
  - GET /network/ports
  - GET /network/alerts
  - GET /network/stats
  - POST /network/scan
"""

import pytest
from fastapi.testclient import TestClient

from backend.api.main import app
from backend.network_monitoring.network_analyzer import NetworkSecurityAnalyzer
from backend.network_monitoring.network_service import network_service
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


def test_analyzer_detects_high_risk_listening_port():
    """Verify detection of dangerous listening port (Metasploit 4444)."""
    port_info = {
        "port": 4444,
        "bind_address": "0.0.0.0",
        "process_name": "meterpreter",
        "pid": 9912
    }
    result = NetworkSecurityAnalyzer.analyze_listening_port(port_info)
    assert result["is_authorized"] is False
    assert result["risk_level"] == "CRITICAL"
    assert result["risk_score"] >= 85
    assert result["alert"] is not None
    assert "METASPLOIT" in result["alert"]["alert_type"]
    assert result["alert"]["mitre_technique"] == "T1571"


def test_analyzer_allows_standard_authorized_ports():
    """Verify standard server ports (SSH, HTTPS, PostgreSQL) are flagged as authorized."""
    for standard_port in [22, 443, 5432]:
        port_info = {
            "port": standard_port,
            "bind_address": "0.0.0.0",
            "process_name": "daemon",
            "pid": 100
        }
        result = NetworkSecurityAnalyzer.analyze_listening_port(port_info)
        assert result["is_authorized"] is True
        assert result["risk_level"] == "LOW"
        assert result["alert"] is None


def test_analyzer_detects_threat_intel_ioc_connection():
    """Verify that socket connected to a known threat IOC IP triggers critical alert."""
    conn = {
        "protocol": "tcp",
        "local_address": "192.168.1.100",
        "local_port": 49210,
        "remote_address": "198.51.100.1",  # Feodo Tracker C2 IOC
        "remote_port": 443,
        "status": "ESTABLISHED",
        "process_name": "curl"
    }
    result = NetworkSecurityAnalyzer.analyze_connection(conn)
    assert result["is_suspicious"] is True
    assert result["risk_score"] >= 90
    assert any(a["alert_type"] == "C2_THREAT_INTEL_MATCH" for a in result["alerts"])
    assert any(a["mitre_technique"] == "T1071" for a in result["alerts"])


def test_analyzer_detects_syn_scan_behavior():
    """Verify SYN_SENT state to non-standard remote port is flagged as probing/scanning."""
    conn = {
        "protocol": "tcp",
        "local_address": "192.168.1.100",
        "local_port": 41234,
        "remote_address": "10.0.0.99",
        "remote_port": 2323,
        "status": "SYN_SENT",
        "process_name": "masscan"
    }
    result = NetworkSecurityAnalyzer.analyze_connection(conn)
    assert result["is_suspicious"] is True
    assert any("SYN_SCAN" in a["alert_type"] for a in result["alerts"])


def test_analyzer_evaluates_interface_health():
    """Verify link-down and excessive packet drop alerts."""
    down_iface = {
        "interface_name": "eth1",
        "is_up": False,
        "dropin": 0,
        "dropout": 0,
        "errin": 0
    }
    alert = NetworkSecurityAnalyzer.evaluate_interface_health(down_iface)
    assert alert is not None
    assert alert["alert_type"] == "INTERFACE_DOWN"
    assert alert["severity"] == "HIGH"


def test_network_service_scan_and_stats():
    """Verify NetworkMonitoringService scan execution and KPI aggregation."""
    scan_res = network_service.scan_network(hostname="prac-server")
    assert scan_res["interfaces_count"] > 0
    assert scan_res["total_connections"] > 0
    assert scan_res["listening_ports_count"] > 0

    stats = network_service.get_stats(hostname="prac-server")
    assert stats["interfaces_count"] > 0
    assert stats["active_connections_count"] > 0
    assert "listening_ports_count" in stats

    interfaces = network_service.list_interfaces(hostname="prac-server")
    assert len(interfaces) > 0

    conns = network_service.list_connections(hostname="prac-server")
    assert len(conns) > 0

    ports = network_service.list_listening_ports(hostname="prac-server")
    assert len(ports) > 0


def test_api_network_monitoring_endpoints(auth_headers, read_only_headers):
    """Verify network security REST endpoints with authentication."""
    client = TestClient(app)

    # 1. Stats
    resp_stats = client.get("/network/stats", headers=auth_headers)
    assert resp_stats.status_code == 200
    data = resp_stats.json()
    assert "active_connections_count" in data
    assert "listening_ports_count" in data

    # 2. Interfaces
    resp_ifaces = client.get("/network/interfaces", headers=auth_headers)
    assert resp_ifaces.status_code == 200
    ifaces = resp_ifaces.json()
    assert isinstance(ifaces, list)
    assert len(ifaces) > 0

    # 3. Connections
    resp_conns = client.get("/network/connections", headers=auth_headers)
    assert resp_conns.status_code == 200
    conns = resp_conns.json()
    assert isinstance(conns, list)

    # 4. Listening Ports
    resp_ports = client.get("/network/ports", headers=auth_headers)
    assert resp_ports.status_code == 200
    ports = resp_ports.json()
    assert isinstance(ports, list)
    assert len(ports) > 0

    # 5. Alerts
    resp_alerts = client.get("/network/alerts", headers=auth_headers)
    assert resp_alerts.status_code == 200
    alerts = resp_alerts.json()
    assert isinstance(alerts, list)

    # 6. On-demand Network Scan (Admin role)
    resp_scan = client.post("/network/scan", json={"hostname": "prac-server"}, headers=auth_headers)
    assert resp_scan.status_code == 200
    assert "interfaces_count" in resp_scan.json()
