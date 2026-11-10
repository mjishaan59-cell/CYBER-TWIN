# Phase 29 — Advanced Incident Response & Playbooks Subsystem

## Overview
The **Advanced Incident Response & Playbooks Subsystem** provides automated containment, analyst-driven remediation, forensics evidence handling, and chronological incident timelines for enterprise Linux environments.

It bridges reactive alerting and automated active defense, enabling operators to execute surgical containment playbooks (firewall rules, process termination, VLAN quarantine, FIM file restoration, account invalidation) backed by **strict safety guardrails** to prevent accidental self-lockout or production degradation.

---

## Architecture & Containment Workflow

```
                        +---------------------------------------+
                        |  High-Severity Incident or Simulation |
                        +-------------------+-------------------+
                                            |
                                            v
                        +---------------------------------------+
                        |        Playbook Safety Guardrails     |
                        | - Whitelist Protection (Gateway, Local)|
                        | - Core Daemon Safeguards (PID 1, SSH) |
                        | - Explicit Operator Confirmation Gate |
                        +-------------------+-------------------+
                                            |
                         +------------------+------------------+
                         |                                     |
              [Passed Safeguards]                     [Safeguard Violation]
                         |                                     |
                         v                                     v
        +---------------------------------+   +---------------------------------+
        |      PlaybookEngine Execution   |   |     BLOCKED_BY_SAFEGUARD        |
        | - Mode: DRY_RUN vs LIVE         |   | - Logged to Audit Trail         |
        | - Step-by-Step Command Compile  |   | - Halts Execution Safely        |
        +----------------+----------------+   +---------------------------------+
                         |
                         v
        +---------------------------------+
        |   IncidentTimelineService       |
        | - Chronological Forensic Events |
        | - Evidence Locker (PCAP / Hash) |
        | - PostgreSQL Execution Audit    |
        +----------------+----------------+
                         |
           +-------------+-------------+
           |                           |
           v                           v
+---------------------+     +---------------------+
| Playbook REST APIs  |     |  Dashboard Live UI  |
+---------------------+     +---------------------+
```

---

## Playbook Catalog & Safeguards

The subsystem features six production-ready playbooks:

1. **Block Malicious IP (`BLOCK_MALICIOUS_IP`)**:
   - **Remediation**: Injects `iptables -I INPUT -s <IP> -j DROP` or nftables rule.
   - **Safeguard**: Validates IP is not a loopback address (`127.0.0.1`), default gateway, or immutable management IP.

2. **Network Quarantine & VLAN Isolation (`ISOLATE_HOST_VLAN`)**:
   - **Remediation**: Shifts host interface to an isolated quarantine VLAN (VLAN 999) while preserving jumpbox access.
   - **Safeguard**: Requires explicit `confirm_isolation=True` parameter in LIVE mode.

3. **Kill Rogue Process (`KILL_ROGUE_PROCESS`)**:
   - **Remediation**: Dispatches `kill -15` (SIGTERM) followed by `kill -9` (SIGKILL) on rogue process tree.
   - **Safeguard**: Refuses to terminate protected system processes (`PID 1`, `systemd`, `systemd-journald`, `auditd`, `sshd`).

4. **Restore Tampered FIM File (`RESTORE_FIM_FILE`)**:
   - **Remediation**: Replaces tampered system file from cryptographically verified HMAC-SHA256 baseline backup and re-applies strict permissions (`0640`).
   - **Safeguard**: Validates path is an absolute Linux path and in the monitored FIM path registry.

5. **Expire Compromised User Credentials (`RESET_COMPROMISED_CREDENTIALS`)**:
   - **Remediation**: Executes `chage -d 0 <user>` to force password reset and wipes compromised `~/.ssh/authorized_keys`.
   - **Safeguard**: Prevents complete lockout of root without backup SSH access.

6. **Restart Failed Critical Systemd Service (`RESTART_FAILED_SERVICE`)**:
   - **Remediation**: Clears failed state via `systemctl reset-failed` and issues clean restart.
   - **Safeguard**: Confirms target unit name is a recognized systemd unit.

---

## Forensics Evidence Locker & Timeline

1. **Evidence Locker**:
   - Stores forensic artifacts (PCAP packet dumps, process memory snapshots, auditd log snippets, IOC hashes).
   - Records cryptographic SHA-256 fingerprint, collector identity, and JSON metadata.

2. **Consolidated Chronological Timeline**:
   - Merges alerts, telemetry correlations, playbook remediation actions, and analyst investigation notes into an ordered event sequence.

---

## Database Models & Schema

- **`playbook_execution_audits`**: `execution_id`, `playbook_id`, `playbook_name`, `incident_id`, `target_hostname`, `executed_by`, `mode` (`DRY_RUN`/`LIVE`), `safeguards_passed`, `safeguard_notes`, `status` (`SUCCESS`/`BLOCKED_BY_SAFEGUARD`), `parameters` (JSON), `execution_log` (JSON), `result_summary`, `executed_at`.
- **`incident_evidence_artifacts`**: `artifact_id`, `incident_id`, `artifact_type`, `file_name`, `file_hash_sha256`, `description`, `collected_by`, `metadata_json`, `collected_at`.
- **`incident_timeline_events`**: `incident_id`, `event_type`, `title`, `source`, `severity`, `details`, `event_timestamp`.

---

## API Endpoints Reference

All endpoints are mounted under `/incident-response` with JWT RBAC:

| Method | Endpoint | Description | Role Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/incident-response/playbooks` | Retrieve catalog of remediation playbooks | `admin`, `analyst`, `viewer` |
| `POST` | `/incident-response/playbooks/execute` | Execute or dry-run a playbook with guardrails | `admin`, `analyst` |
| `GET` | `/incident-response/playbooks/history` | Audit log of playbook execution runs | `admin`, `analyst`, `viewer` |
| `GET` | `/incident-response/timeline/{id}` | Complete chronological incident timeline | `admin`, `analyst`, `viewer` |
| `POST` | `/incident-response/timeline/{id}` | Add analyst observation note to timeline | `admin`, `analyst` |
| `GET` | `/incident-response/evidence/{id}` | Retrieve secured forensic evidence artifacts | `admin`, `analyst`, `viewer` |
| `POST` | `/incident-response/evidence/{id}` | Attach forensic artifact with SHA-256 hash | `admin`, `analyst` |
| `GET` | `/incident-response/stats` | Aggregated response and safeguard metrics | `admin`, `analyst`, `viewer` |

---

## Dashboard Integration

- **Playbook Execution Bar**: Dropdown selector for playbooks, mode toggle (`DRY_RUN` vs `LIVE`), target parameter input, and "Execute" action button.
- **KPI Summary Cards**: Total Playbook Executions, Successful Remediations, Safeguard Interceptions, Secured Evidence Artifacts.
- **Audit Table**: Real-time log of playbook runs, mode badges, safeguard indicators, and summary messages.
- **Split Timeline & Evidence View**: Side-by-side view of incident timeline events and secured evidence artifacts with cryptographic hashes.
