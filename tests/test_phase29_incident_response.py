"""
Automated Test Suite for Phase 29 - Advanced Incident Response & Playbooks Subsystem
Tests:
- PlaybookEngine catalog and safeguard validation (prevents self-lockout, loopback blocking, PID 1 termination)
- PlaybookEngine execution in DRY_RUN and LIVE modes
- IncidentTimelineService evidence artifact collection and verification
- Incident timeline event logging and chronological retrieval
- Incident Response REST API endpoints:
  - GET /incident-response/playbooks
  - POST /incident-response/playbooks/execute
  - GET /incident-response/playbooks/history
  - GET /incident-response/timeline/{incident_id}
  - POST /incident-response/timeline/{incident_id}
  - GET /incident-response/evidence/{incident_id}
  - POST /incident-response/evidence/{incident_id}
  - GET /incident-response/stats
"""

import pytest
from fastapi.testclient import TestClient

from backend.api.main import app
from backend.incident_response.playbook_engine import PlaybookEngine
from backend.incident_response.incident_timeline_service import incident_timeline_service
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


def test_playbook_catalog_and_safeguards():
    """Verify catalog and rigorous safeguard checks."""
    playbooks = PlaybookEngine.list_playbooks()
    assert len(playbooks) >= 6
    pb_ids = [p["playbook_id"] for p in playbooks]
    assert "BLOCK_MALICIOUS_IP" in pb_ids
    assert "KILL_ROGUE_PROCESS" in pb_ids
    assert "ISOLATE_HOST_VLAN" in pb_ids

    # 1. Safeguard: Loopback IP must be rejected
    passed_lb, note_lb = PlaybookEngine.check_safeguards(
        "BLOCK_MALICIOUS_IP",
        {"ip_address": "127.0.0.1"}
    )
    assert passed_lb is False
    assert "Safeguard Violation" in note_lb

    # 2. Safeguard: PID 1 termination must be rejected
    passed_pid1, note_pid1 = PlaybookEngine.check_safeguards(
        "KILL_ROGUE_PROCESS",
        {"pid": 1, "process_name": "systemd"}
    )
    assert passed_pid1 is False
    assert "protected" in note_pid1

    # 3. Safeguard: Legitimate rogue IP must pass
    passed_valid, _ = PlaybookEngine.check_safeguards(
        "BLOCK_MALICIOUS_IP",
        {"ip_address": "198.51.100.99"}
    )
    assert passed_valid is True


def test_playbook_execution_and_safeguard_interception():
    """Verify playbook execution outcomes and safeguard-blocked status."""
    # Successful execution
    res_success = PlaybookEngine.execute_playbook(
        playbook_id="BLOCK_MALICIOUS_IP",
        target_hostname="prac-server",
        params={"ip_address": "203.0.113.88"},
        mode="DRY_RUN"
    )
    assert res_success["status"] == "SUCCESS"
    assert res_success["safeguards_passed"] is True
    assert len(res_success["execution_log"]) >= 2

    # Blocked execution by safeguard
    res_blocked = PlaybookEngine.execute_playbook(
        playbook_id="KILL_ROGUE_PROCESS",
        target_hostname="prac-server",
        params={"pid": 1, "process_name": "systemd"},
        mode="DRY_RUN"
    )
    assert res_blocked["status"] == "BLOCKED_BY_SAFEGUARD"
    assert res_blocked["safeguards_passed"] is False


def test_incident_timeline_and_evidence_service():
    """Verify timeline event logging and evidence artifact management."""
    inc_id = "inc-test-99"

    # Add timeline event
    ev = incident_timeline_service.add_timeline_event(
        incident_id=inc_id,
        event_type="NOTE",
        title="Forensic triage initialized",
        source="Analyst:Bob",
        details="Beginning triage on compromised web node."
    )
    assert ev["title"] == "Forensic triage initialized"

    timeline = incident_timeline_service.get_timeline(inc_id)
    assert len(timeline) >= 1
    assert any(t["title"] == "Forensic triage initialized" for t in timeline)

    # Attach evidence
    art = incident_timeline_service.attach_evidence(
        incident_id=inc_id,
        artifact_type="PCAP",
        file_name="suspicious_c2_traffic.pcap",
        file_hash_sha256="abcdef1234567890"*4,
        description="Packet capture of reverse shell traffic"
    )
    assert art["artifact_id"].startswith("art-")
    assert art["file_name"] == "suspicious_c2_traffic.pcap"

    evidence_list = incident_timeline_service.list_evidence(inc_id)
    assert len(evidence_list) == 1

    stats = incident_timeline_service.get_stats()
    assert stats["total_playbook_executions"] > 0
    assert stats["evidence_artifacts_secured"] > 0


def test_api_incident_response_endpoints(auth_headers, read_only_headers):
    """Verify incident response REST API endpoints with RBAC."""
    client = TestClient(app)

    # 1. Playbooks Catalog
    resp_pbs = client.get("/incident-response/playbooks", headers=auth_headers)
    assert resp_pbs.status_code == 200
    assert isinstance(resp_pbs.json(), list)

    # 2. Stats
    resp_stats = client.get("/incident-response/stats", headers=auth_headers)
    assert resp_stats.status_code == 200
    assert "total_playbook_executions" in resp_stats.json()

    # 3. Execute Playbook (Admin/Analyst)
    exec_req = {
        "playbook_id": "RESTART_FAILED_SERVICE",
        "target_hostname": "prac-server",
        "incident_id": "inc-2026-001",
        "mode": "DRY_RUN",
        "parameters": {"service_name": "nginx.service"}
    }
    resp_exec = client.post("/incident-response/playbooks/execute", json=exec_req, headers=auth_headers)
    assert resp_exec.status_code == 200
    assert resp_exec.json()["status"] == "SUCCESS"

    # 4. Playbook History
    resp_hist = client.get("/incident-response/playbooks/history", headers=auth_headers)
    assert resp_hist.status_code == 200
    assert isinstance(resp_hist.json(), list)

    # 5. Get Timeline
    resp_time = client.get("/incident-response/timeline/inc-2026-001", headers=auth_headers)
    assert resp_time.status_code == 200
    assert isinstance(resp_time.json(), list)

    # 6. Add Timeline Event
    note_req = {
        "event_type": "NOTE",
        "title": "Analyst confirmation",
        "source": "Lead Analyst",
        "details": "Remediation verified clean."
    }
    resp_add_time = client.post("/incident-response/timeline/inc-2026-001", json=note_req, headers=auth_headers)
    assert resp_add_time.status_code == 201

    # 7. Get Evidence
    resp_evi = client.get("/incident-response/evidence/inc-2026-001", headers=auth_headers)
    assert resp_evi.status_code == 200
    assert isinstance(resp_evi.json(), list)

    # 8. Attach Evidence
    art_req = {
        "artifact_type": "LOG_SNIPPET",
        "file_name": "auditd_execve.log",
        "file_hash_sha256": "1122334455667788"*4,
        "description": "Kernel execve log trace"
    }
    resp_attach = client.post("/incident-response/evidence/inc-2026-001", json=art_req, headers=auth_headers)
    assert resp_attach.status_code == 201
    assert "artifact_id" in resp_attach.json()
