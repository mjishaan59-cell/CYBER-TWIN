"""
Automated Test Suite for Phase 24 - File Integrity Monitoring (FIM) Subsystem
Tests:
- SHA-256 hash calculation
- Cryptographic baseline seal creation and tamper detection
- File creation detection
- File deletion detection
- File modification detection (content hash change)
- Permission change detection (including SUID escalation)
- Ownership change detection
- FimService baseline snapshot and verification scan
- FIM REST API Endpoints
"""

import pytest
from fastapi.testclient import TestClient

from backend.api.main import app
from backend.fim.fim_engine import (
    calculate_sha256,
    generate_baseline_seal,
    verify_baseline_seal,
    FimEngine
)
from backend.fim.fim_service import fim_service
from backend.fim.fim_config import CRITICAL_LINUX_PATHS
from backend.auth.jwt_handler import create_access_token


@pytest.fixture
def auth_headers():
    token = create_access_token({
        "sub": "testadmin",
        "role": "admin"
    })
    return {"Authorization": f"Bearer {token}"}


def test_calculate_sha256():
    """Verify SHA-256 calculation against known vector."""
    empty_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert calculate_sha256(b"") == empty_sha256
    hello_sha256 = calculate_sha256(b"hello world")
    assert len(hello_sha256) == 64


def test_tamper_seal_protection():
    """Verify cryptographic baseline seal protects against unauthorized changes."""
    records = [
        {"file_path": "/etc/passwd", "sha256_hash": "aaaa"*16, "permissions": "0644", "owner_name": "root"},
        {"file_path": "/etc/shadow", "sha256_hash": "bbbb"*16, "permissions": "0000", "owner_name": "root"}
    ]
    seal = generate_baseline_seal(records)
    assert len(seal) == 64
    assert verify_baseline_seal(records, seal) is True

    # Tamper with one record
    tampered_records = list(records)
    tampered_records[0] = dict(records[0])
    tampered_records[0]["sha256_hash"] = "cccc"*16
    assert verify_baseline_seal(tampered_records, seal) is False


def test_fim_engine_change_detections():
    """Verify detection of CREATED, MODIFIED, DELETED, PERMISSION_CHANGED, and OWNERSHIP_CHANGED."""
    baseline = [
        {"file_path": "/etc/shadow", "sha256_hash": "1111"*16, "permissions": "0000", "owner_name": "root"},
        {"file_path": "/etc/sudoers", "sha256_hash": "2222"*16, "permissions": "0440", "owner_name": "root"},
        {"file_path": "/etc/hosts", "sha256_hash": "3333"*16, "permissions": "0644", "owner_name": "root"}
    ]

    # Current state:
    # - /etc/shadow MODIFIED
    # - /etc/sudoers PERMISSION_CHANGED to 0777
    # - /etc/hosts DELETED
    # - /etc/cron.d/backdoor CREATED
    current = [
        {"file_path": "/etc/shadow", "sha256_hash": "9999"*16, "permissions": "0000", "owner_name": "root"},
        {"file_path": "/etc/sudoers", "sha256_hash": "2222"*16, "permissions": "0777", "owner_name": "nobody"},
        {"file_path": "/etc/cron.d/backdoor", "sha256_hash": "8888"*16, "permissions": "0755", "owner_name": "root"}
    ]

    events = FimEngine.compare_snapshot(baseline, current, hostname="test-server")
    event_types = [e["change_type"] for e in events]

    assert "MODIFIED" in event_types
    assert "DELETED" in event_types
    assert "CREATED" in event_types
    assert "PERMISSION_CHANGED" in event_types
    assert "OWNERSHIP_CHANGED" in event_types

    # Verify severity assignment
    shadow_mod = next(e for e in events if e["file_path"] == "/etc/shadow" and e["change_type"] == "MODIFIED")
    assert shadow_mod["severity"] == "CRITICAL"

    hosts_del = next(e for e in events if e["file_path"] == "/etc/hosts" and e["change_type"] == "DELETED")
    assert hosts_del["severity"] in ("HIGH", "CRITICAL")


def test_fim_service_operations():
    """Verify FimService baseline snapshot, scan, and statistics."""
    # 1. Get baseline (real on-disk local files)
    baseline = fim_service.get_baseline("localhost")
    assert len(baseline) > 0

    # 2. Trigger scan with identical snapshot -> 0 violations
    res = fim_service.scan_host_integrity("localhost", active_snapshot=baseline)
    assert res["violations_detected"] == 0

    # 3. Trigger scan with modified file -> 1 violation
    tampered_snapshot = [dict(r) for r in baseline]
    tampered_snapshot[0]["sha256_hash"] = "fedcba9876543210"*4
    tampered_res = fim_service.scan_host_integrity("localhost", active_snapshot=tampered_snapshot)
    assert tampered_res["violations_detected"] >= 1

    # 4. Check statistics
    stats = fim_service.get_stats("localhost")
    assert stats["monitored_files_count"] > 0


def test_fim_api_endpoints(auth_headers):
    """Test REST API endpoints for File Integrity Monitoring."""
    client = TestClient(app)

    # 1. GET /fim/baseline
    b_resp = client.get("/fim/baseline?hostname=prac-server", headers=auth_headers)
    assert b_resp.status_code == 200
    assert isinstance(b_resp.json(), list)

    # 2. GET /fim/critical-paths
    cp_resp = client.get("/fim/critical-paths", headers=auth_headers)
    assert cp_resp.status_code == 200
    assert "/etc/shadow" in cp_resp.json()

    # 3. POST /fim/baseline/create
    create_req = {
        "hostname": "prac-server",
        "records": [
            {
                "file_path": "/etc/shadow",
                "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "file_size_bytes": 1420,
                "permissions": "0000",
                "owner_name": "root",
                "group_name": "root"
            }
        ]
    }
    c_resp = client.post("/fim/baseline/create", json=create_req, headers=auth_headers)
    assert c_resp.status_code == 201
    assert "tamper_seal" in c_resp.json()

    # 4. POST /fim/scan
    scan_req = {"hostname": "prac-server"}
    s_resp = client.post("/fim/scan", json=scan_req, headers=auth_headers)
    assert s_resp.status_code == 200
    assert "scanned_files_count" in s_resp.json()

    # 5. GET /fim/events
    ev_resp = client.get("/fim/events?hostname=prac-server", headers=auth_headers)
    assert ev_resp.status_code == 200
    assert isinstance(ev_resp.json(), list)

    # 6. GET /fim/stats
    st_resp = client.get("/fim/stats?hostname=prac-server", headers=auth_headers)
    assert st_resp.status_code == 200
    assert "monitored_files_count" in st_resp.json()
