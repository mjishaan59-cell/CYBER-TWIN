"""
Automated Test Suite for Phase 22 - AI Threat Intelligence Subsystem
Tests:
- Indicator Format Validation and Type Detection
- MITRE ATT&CK Mapping
- Dynamic Threat Classification and Severity Scoring
- Feed Collector and Parsing
- Threat Event Correlation
- Threat Intelligence Service (CRUD, Lookup, Stats)
- Threat Intelligence REST API Endpoints
"""

import pytest
from fastapi.testclient import TestClient

from backend.api.main import app
from backend.threat_intel.mitre_mapper import (
    map_threat_to_mitre,
    get_all_mitre_techniques,
    MITRE_ATTACK_DB
)
from backend.threat_intel.feed_collector import (
    detect_indicator_type,
    is_valid_ipv4,
    is_valid_domain,
    is_valid_sha256,
    ThreatFeedCollector
)
from backend.threat_intel.threat_classifier import (
    ThreatClassifier,
    score_to_severity
)
from backend.threat_intel.threat_correlator import ThreatCorrelator
from backend.threat_intel.threat_service import (
    ThreatIntelligenceService,
    threat_intel_service
)
from backend.auth.jwt_handler import create_access_token


@pytest.fixture
def auth_headers():
    token = create_access_token({
        "sub": "testadmin",
        "role": "admin"
    })
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def analyst_headers():
    token = create_access_token({
        "sub": "testanalyst",
        "role": "analyst"
    })
    return {"Authorization": f"Bearer {token}"}


def test_indicator_validation():
    """Verify IP, domain, and SHA256 validation logic."""
    assert is_valid_ipv4("192.168.1.1") is True
    assert is_valid_ipv4("999.999.999.999") is False
    assert is_valid_ipv4("invalid-ip") is False

    assert is_valid_domain("malicious-c2.example.com") is True
    assert is_valid_domain("c2.org") is True
    assert is_valid_domain("not a domain") is False

    valid_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    assert is_valid_sha256(valid_hash) is True
    assert is_valid_sha256("short-hash") is False


def test_detect_indicator_type():
    """Verify automatic type deduction for indicators."""
    assert detect_indicator_type("194.26.29.118") == "IP"
    assert detect_indicator_type("c2.malicious-domain.com") == "DOMAIN"
    assert detect_indicator_type("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f") == "SHA256"
    assert detect_indicator_type("https://malware-drop.com/payload.elf") == "URL"


def test_mitre_mapping():
    """Verify mapping of threats to MITRE ATT&CK techniques."""
    mitre_ssh = map_threat_to_mitre("SSH_BRUTE_FORCE")
    assert mitre_ssh["attack_id"] == "T1110.001"
    assert mitre_ssh["tactic"] == "Credential Access"

    mitre_c2 = map_threat_to_mitre("MALWARE_C2")
    assert mitre_c2["attack_id"] == "T1071.001"
    assert mitre_c2["tactic"] == "Command and Control"

    mitre_tor = map_threat_to_mitre("TOR_EXIT_NODE")
    assert mitre_tor["attack_id"] == "T1090.003"

    techniques = get_all_mitre_techniques()
    assert len(techniques) >= 8


def test_threat_classifier_scoring():
    """Verify dynamic threat scoring and severity assignment."""
    res_critical = ThreatClassifier.calculate_threat_score(
        threat_type="MALWARE_C2",
        feed_confidence=95,
        observed_attempts=25,
        root_targeted=True
    )
    assert res_critical["threat_score"] >= 90
    assert res_critical["severity"] == "CRITICAL"
    assert "root" in res_critical["explanation"]

    res_medium = ThreatClassifier.calculate_threat_score(
        threat_type="TOR_EXIT_NODE",
        feed_confidence=70
    )
    assert res_medium["severity"] in ("MEDIUM", "LOW")

    assert score_to_severity(95) == "CRITICAL"
    assert score_to_severity(75) == "HIGH"
    assert score_to_severity(50) == "MEDIUM"
    assert score_to_severity(20) == "LOW"


def test_feed_collector_seed():
    """Verify feed collector loads high-confidence seed baseline."""
    collector = ThreatFeedCollector()
    seeds = collector.get_fallback_seed_iocs()
    assert len(seeds) >= 5
    assert any(s["indicator_type"] == "IP" for s in seeds)
    assert any(s["indicator_type"] == "DOMAIN" for s in seeds)
    assert any(s["indicator_type"] == "SHA256" for s in seeds)


def test_threat_correlator():
    """Verify correlation of IP events with threat intelligence."""
    mock_db = {
        "194.26.29.118": {
            "indicator_value": "194.26.29.118",
            "indicator_type": "IP",
            "threat_type": "MALWARE_C2",
            "confidence_score": 95,
            "source_feed": "Abuse.ch Feodo",
            "description": "Known Cobalt Strike Team Server"
        }
    }
    correlator = ThreatCorrelator(lambda ip: mock_db.get(ip))

    # Test matched IOC
    match = correlator.correlate_ip("194.26.29.118", context={"attempts": 10, "username": "root"})
    assert match["matched"] is True
    assert match["threat_score"] >= 85
    assert match["severity"] == "CRITICAL"
    assert match["recommended_action"] == "BLOCK_SOURCE_IP"
    assert match["mitre_attack"]["attack_id"] == "T1071.001"

    # Test clean IP
    clean = correlator.correlate_ip("10.0.0.99", context={"attempts": 1, "username": "operator"})
    assert clean["matched"] is False
    assert clean["severity"] in ("LOW", "MEDIUM")


def test_threat_service_lookup_and_stats():
    """Verify ThreatIntelligenceService lookup and statistics."""
    # Known seed IP lookup
    res = threat_intel_service.lookup("194.26.29.118")
    assert res["matched"] is True
    assert res["severity"] in ("HIGH", "CRITICAL")
    assert res["mitre_attack"] is not None

    # Clean IP lookup
    clean_res = threat_intel_service.lookup("8.8.8.8")
    assert clean_res["matched"] is False
    assert clean_res["severity"] == "CLEAN"

    # Stats
    stats = threat_intel_service.get_stats()
    assert stats["total_active_iocs"] >= 5
    assert stats["mitre_techniques_cataloged"] >= 5


def test_api_threat_intel_endpoints(auth_headers):
    """Test REST API endpoints for Threat Intelligence."""
    client = TestClient(app)

    # 1. GET /threat-intel/indicators
    resp = client.get("/threat-intel/indicators?limit=10", headers=auth_headers)
    assert resp.status_code == 200
    indicators = resp.json()
    assert isinstance(indicators, list)
    assert len(indicators) > 0

    # 2. GET /threat-intel/lookup/{indicator}
    lookup_resp = client.get("/threat-intel/lookup/194.26.29.118", headers=auth_headers)
    assert lookup_resp.status_code == 200
    data = lookup_resp.json()
    assert data["matched"] is True
    assert data["indicator_value"] == "194.26.29.118"

    # 3. POST /threat-intel/indicators (Add Custom IOC)
    custom_ioc = {
        "indicator_value": "103.203.57.18",
        "indicator_type": "IP",
        "threat_type": "SSH_BRUTE_FORCE",
        "severity": "HIGH",
        "confidence_score": 85,
        "description": "Suspected scanning bot targeting port 22",
        "tags": "test,bot"
    }
    create_resp = client.post("/threat-intel/indicators", json=custom_ioc, headers=auth_headers)
    assert create_resp.status_code == 201

    # 4. POST /threat-intel/correlate
    correlate_req = {
        "indicators": ["194.26.29.118", "103.203.57.18", "127.0.0.1"],
        "context": {"attempts": 5, "username": "root"}
    }
    corr_resp = client.post("/threat-intel/correlate", json=correlate_req, headers=auth_headers)
    assert corr_resp.status_code == 200
    corr_data = corr_resp.json()
    assert corr_data["total_analyzed"] == 3
    assert corr_data["matches_found"] >= 2

    # 5. GET /threat-intel/stats
    stats_resp = client.get("/threat-intel/stats", headers=auth_headers)
    assert stats_resp.status_code == 200
    stats_data = stats_resp.json()
    assert "total_active_iocs" in stats_data
    assert "mitre_techniques_cataloged" in stats_data

    # 6. GET /threat-intel/mitre
    mitre_resp = client.get("/threat-intel/mitre", headers=auth_headers)
    assert mitre_resp.status_code == 200
    techniques = mitre_resp.json()
    assert isinstance(techniques, list)
    assert len(techniques) >= 8
