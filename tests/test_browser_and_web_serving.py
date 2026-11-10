"""
Test Suite for Browser Delivery, Web Dashboard Serving, Static Assets, and API Routing.
Verifies that:
1. Web browser accessing root '/' directly receives the HTML dashboard.
2. Static assets (style.css, app.js, favicon.ico) resolve properly with correct MIME types.
3. Transparent /api/ routing works natively without requiring external reverse proxy.
4. Demo credentials (admin / admin123) authenticate successfully and grant valid JWT tokens.
5. All major subsystems are accessible through the web gateway.
"""

import pytest
from fastapi.testclient import TestClient
from backend.api.main import app

client = TestClient(app)


def test_root_serves_html_dashboard():
    """Verify that visiting '/' in a web browser renders the HTML Dashboard."""
    response = client.get("/", headers={"Accept": "text/html,application/xhtml+xml"})
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "<title>Cyber Digital Twin Dashboard</title>" in response.text
    assert "loginScreen" in response.text


def test_root_json_api_negotiation():
    """Verify that API clients requesting application/json receive API status JSON."""
    response = client.get("/", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert "application/json" in response.headers.get("content-type", "")
    data = response.json()
    assert "message" in data


def test_static_assets_delivery():
    """Verify CSS, JavaScript, and Index files are accessible with correct MIME types."""
    # Index HTML
    res_index = client.get("/index.html")
    assert res_index.status_code == 200
    assert "text/html" in res_index.headers.get("content-type", "")

    # Style CSS
    res_css = client.get("/style.css")
    assert res_css.status_code == 200
    assert "text/css" in res_css.headers.get("content-type", "")

    # Application JS
    res_js = client.get("/app.js")
    assert res_js.status_code == 200
    assert "javascript" in res_js.headers.get("content-type", "")


def test_demo_authentication_and_jwt_grant():
    """Verify default demo credentials allow instant dashboard login."""
    # Test with /auth/login directly
    res_direct = client.post("/auth/login", json={"username": "admin", "password": "admin123"})
    assert res_direct.status_code == 200
    token_data = res_direct.json()
    assert "access_token" in token_data
    assert token_data["role"] == "admin"

    # Test with /api/auth/login prefix (used by frontend app.js)
    res_api = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert res_api.status_code == 200
    assert "access_token" in res_api.json()


def test_prefixed_api_routing_across_subsystems():
    """Verify frontend /api/ calls transparently map to backend subsystems."""
    # Login to obtain token
    login_res = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Threat Intel via /api/
    ti_res = client.get("/api/threat-intel/indicators", headers=headers)
    assert ti_res.status_code == 200

    # Predictive Analytics via /api/
    pred_res = client.get("/api/predictive-analytics/forecast", headers=headers)
    assert pred_res.status_code == 200

    # Attack Simulation via /api/
    sim_res = client.post(
        "/api/simulation/run",
        json={"scenario_id": "SSH_BRUTE_FORCE", "target_hostname": "prac-server"},
        headers=headers
    )
    assert sim_res.status_code == 201
    assert sim_res.json()["status"] == "COMPLETED"

    # Incident Response Playbooks via /api/
    pb_res = client.get("/api/incident-response/playbooks", headers=headers)
    assert pb_res.status_code == 200
