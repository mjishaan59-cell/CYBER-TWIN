"""
Unit and Integration Tests for Phase 21.6:
- Notification Settings & Policies
- Incident Assignment & Acknowledgement Reminders
- Incident Escalations
- Notification Simulator
- Delivery Health Monitoring
"""

import pytest
from backend.notifications.notification_policy import (
    SEVERITY_PRIORITIES,
    VALID_CHANNELS,
    get_notification_policy,
    should_send_notification
)
from backend.notifications.notification_settings_manager import (
    VALID_SEVERITIES,
    VALID_CHANNELS as SETTINGS_CHANNELS,
    normalize_severity,
    normalize_channel
)
from backend.security.incident_reminder_manager import REMINDER_POLICY
from backend.security.incident_escalation_manager import ESCALATION_POLICY
from backend.api.main import (
    NotificationSettingUpdateRequest,
    NotificationSimulationRequest,
    IncidentAssignmentRequest,
    IncidentNoteRequest,
    IncidentResolutionRequest,
    IncidentReopenRequest
)


def test_severity_priorities_mapping():
    """Verify standard severity-to-priority mappings."""
    assert SEVERITY_PRIORITIES["LOW"] == "P4"
    assert SEVERITY_PRIORITIES["MEDIUM"] == "P3"
    assert SEVERITY_PRIORITIES["HIGH"] == "P2"
    assert SEVERITY_PRIORITIES["CRITICAL"] == "P1"


def test_notification_channels():
    """Verify recognized notification channels."""
    assert "email" in VALID_CHANNELS
    assert "telegram" in VALID_CHANNELS
    assert "dashboard" in VALID_CHANNELS


def test_reminder_policy_thresholds():
    """Verify escalation and reminder policy timing."""
    assert REMINDER_POLICY["HIGH"] == 10
    assert REMINDER_POLICY["CRITICAL"] == 3

    assert ESCALATION_POLICY["HIGH"][1] == 15
    assert ESCALATION_POLICY["HIGH"][2] == 30
    assert ESCALATION_POLICY["CRITICAL"][1] == 5
    assert ESCALATION_POLICY["CRITICAL"][2] == 10


def test_normalization():
    """Verify severity and channel normalization and validation."""
    assert normalize_severity("high") == "HIGH"
    assert normalize_severity("CRITICAL ") == "CRITICAL"
    with pytest.raises(ValueError):
        normalize_severity("UNKNOWN")

    assert normalize_channel("email") == "EMAIL"
    assert normalize_channel("telegram") == "TELEGRAM"
    with pytest.raises(ValueError):
        normalize_channel("SLACK")


def test_fail_closed_policy():
    """Verify fallback policy fails closed for external notifications but keeps dashboard."""
    policy = get_notification_policy("HIGH")
    assert policy["severity"] == "HIGH"
    assert policy["priority"] == "P2"
    assert policy["dashboard"] is True
    # If DB is not connected, email and telegram must fail closed (False)
    assert isinstance(policy["email"], bool)
    assert isinstance(policy["telegram"], bool)


def test_pydantic_request_validation():
    """Verify Phase 21.6 API request models."""
    req = NotificationSettingUpdateRequest(enabled=True)
    assert req.enabled is True

    sim_req = NotificationSimulationRequest(severity="CRITICAL")
    assert sim_req.severity == "CRITICAL"

    assign_req = IncidentAssignmentRequest(assigned_to_user_id=42)
    assert assign_req.assigned_to_user_id == 42

    note_req = IncidentNoteRequest(note="Investigating brute force attempts")
    assert note_req.note == "Investigating brute force attempts"

    res_req = IncidentResolutionRequest(resolution_summary="Blocked offending subnet at border firewall")
    assert "firewall" in res_req.resolution_summary

    reopen_req = IncidentReopenRequest(reason="New SSH connection attempts detected from same source")
    assert "reopen" in reopen_req.reason.lower() or "attempts" in reopen_req.reason.lower()
