"""
Test Suite for Phase 31 & 32: Docker Containerization and Enterprise Cloud Deployment.
Validates structural integrity, security configurations, Docker specs, and deployment scripts.
"""

from pathlib import Path
import pytest


WORKSPACE_ROOT = Path(__file__).resolve().parent.parent


def test_dockerfile_backend_configuration():
    """Verify backend Dockerfile exists and enforces security best practices."""
    dockerfile = WORKSPACE_ROOT / "Dockerfile.backend"
    assert dockerfile.exists(), "Dockerfile.backend must exist"

    content = dockerfile.read_text(encoding="utf-8")
    assert "python:3.12-slim" in content, "Must use python 3.12 slim image"
    assert "appuser" in content, "Must configure non-root user"
    assert "HEALTHCHECK" in content, "Must define container healthcheck"
    assert "EXPOSE 8000" in content, "Must expose backend API port 8000"


def test_dockerfile_frontend_and_nginx_configuration():
    """Verify frontend Dockerfile and Nginx configuration files."""
    frontend_dockerfile = WORKSPACE_ROOT / "Dockerfile.frontend"
    assert frontend_dockerfile.exists(), "Dockerfile.frontend must exist"

    content = frontend_dockerfile.read_text(encoding="utf-8")
    assert "nginx" in content and "alpine" in content, "Must use lightweight nginx alpine base"
    assert "EXPOSE 80" in content, "Must expose web port 80"

    nginx_conf = WORKSPACE_ROOT / "deployment" / "nginx" / "nginx.conf"
    assert nginx_conf.exists(), "Main nginx.conf must exist"

    site_conf = WORKSPACE_ROOT / "deployment" / "nginx" / "cyber-twin.conf"
    assert site_conf.exists(), "Site nginx configuration must exist"
    site_content = site_conf.read_text(encoding="utf-8")
    assert "proxy_pass http://backend_api" in site_content or "backend:8000" in site_content, "Must proxy API requests to backend"
    assert "X-Frame-Options" in site_content, "Must configure security headers"


def test_docker_compose_and_dockerignore():
    """Verify docker-compose.yml and .dockerignore are properly formed."""
    compose_file = WORKSPACE_ROOT / "docker-compose.yml"
    assert compose_file.exists(), "docker-compose.yml must exist"

    compose_content = compose_file.read_text(encoding="utf-8")
    assert "postgres:" in compose_content, "docker-compose must declare postgres service"
    assert "backend:" in compose_content, "docker-compose must declare backend service"
    assert "frontend:" in compose_content, "docker-compose must declare frontend service"
    assert "postgres_data:" in compose_content, "docker-compose must define persistent volume"

    dockerignore = WORKSPACE_ROOT / ".dockerignore"
    assert dockerignore.exists(), ".dockerignore must exist"
    dockerignore_content = dockerignore.read_text(encoding="utf-8")
    assert "__pycache__" in dockerignore_content
    assert ".git" in dockerignore_content


def test_systemd_and_deployment_scripts():
    """Verify Linux systemd service unit and operations bash scripts exist."""
    systemd_file = WORKSPACE_ROOT / "deployment" / "systemd" / "cyber-twin-backend.service"
    assert systemd_file.exists(), "systemd service unit must exist"
    systemd_content = systemd_file.read_text(encoding="utf-8")
    assert "ExecStart=" in systemd_content
    assert "Restart=always" in systemd_content
    assert "NoNewPrivileges=true" in systemd_content

    scripts = [
        WORKSPACE_ROOT / "deployment" / "scripts" / "backup_database.sh",
        WORKSPACE_ROOT / "deployment" / "scripts" / "restore_database.sh",
        WORKSPACE_ROOT / "deployment" / "scripts" / "deploy_cloud.sh",
    ]
    for script in scripts:
        assert script.exists(), f"Deployment script {script.name} must exist"
        script_content = script.read_text(encoding="utf-8")
        assert "#!/usr/bin/env bash" in script_content, f"{script.name} must have bash shebang"


def test_cloud_deployment_documentation():
    """Verify cloud deployment documentation is comprehensive and complete."""
    doc_file = WORKSPACE_ROOT / "docs" / "cloud-deployment.md"
    assert doc_file.exists(), "docs/cloud-deployment.md must exist"

    doc_content = doc_file.read_text(encoding="utf-8")
    assert "Docker Compose Deployment" in doc_content
    assert "Native Linux Deployment via Systemd" in doc_content
    assert "Cloud Provider Deployment Playbooks" in doc_content
    assert "Backup and Disaster Recovery" in doc_content
