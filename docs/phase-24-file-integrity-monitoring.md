# Phase 24: File Integrity Monitoring (FIM) Subsystem

## Overview
Phase 24 establishes a complete, real-time File Integrity Monitoring (FIM) Subsystem for the AI Cyber Digital Twin platform. It continuously validates critical Linux system configuration files, authentication databases, credential stores, scheduled cron jobs, and privileged system binaries against tamper-sealed cryptographic baselines.

---

## Key Capabilities

1. **Cryptographic Integrity & Tamper-Sealed Baselines**:
   - Computes SHA-256 content hashes for all monitored filesystem objects.
   - Calculates a cryptographic HMAC-SHA256 seal across the baseline catalog to detect unauthorized backend database tampering or modifications to the integrity baselines themselves.

2. **Monitored Critical Linux Targets**:
   - `/etc/shadow`, `/etc/gshadow`: Encrypted password stores (`CRITICAL`).
   - `/etc/sudoers`, `/etc/sudoers.d/`: Sudo access rules & privilege escalation pathways (`CRITICAL`).
   - `/bin/sudo`, `/bin/su`, `/bin/login`: SUID root binaries (`CRITICAL`).
   - `/etc/passwd`, `/etc/group`: System user and group databases (`HIGH`).
   - `/etc/ssh/sshd_config`: SSH daemon security options (`HIGH`).
   - `/etc/hosts`, `/etc/resolv.conf`: Hostname resolution & DNS configurations (`HIGH`/`MEDIUM`).
   - `/etc/crontab`, `/etc/cron.*`: System persistence & automated scheduled tasks (`HIGH`).

3. **Multi-Dimensional Violation Detection**:
   - **`FILE_MODIFIED`**: Mismatch in content SHA-256 digest indicating tampering or unauthorized edits.
   - **`FILE_CREATED`**: Unapproved files introduced into monitored critical directories (e.g., unauthorized cron jobs or web shells).
   - **`FILE_DELETED`**: Monitored files removed from the filesystem.
   - **`PERMISSION_CHANGED`**: File permission modifications (e.g., `0440` -> `0777` or introduction of SUID bit `4755`).
   - **`OWNERSHIP_CHANGED`**: UID/GID transfer (e.g., `root:root` modified to unprivileged users).

4. **Web Dashboard Integration**:
   - Live KPI cards: Baselined Files, Violations Count, Critical Alerts, Baseline Seal Status.
   - Real-time Integrity Violation Events table with timestamp, host, path, change type badges, severity badges, and diff summaries.
   - "Scan Integrity Now" on-demand verification button.

---

## API Reference

### 1. Retrieve Current Baseline
```bash
curl -H "Authorization: Bearer <TOKEN>" \
  "http://localhost:8000/fim/baseline?hostname=prac-server"
```

### 2. Trigger Integrity Verification Scan
```bash
curl -X POST -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"hostname": "prac-server"}' \
  "http://localhost:8000/fim/scan"
```
**Example Response:**
```json
{
  "hostname": "prac-server",
  "scanned_files_count": 6,
  "violations_detected": 1,
  "events": [
    {
      "hostname": "prac-server",
      "file_path": "/etc/shadow",
      "change_type": "MODIFIED",
      "severity": "CRITICAL",
      "old_sha256": "e3b0c44298fc...",
      "new_sha256": "9f86d081884c...",
      "details": "SHA-256 integrity violation: Content of '/etc/shadow' was modified."
    }
  ],
  "scanned_at": "2026-11-10T10:45:00Z"
}
```

### 3. Retrieve Violation Events
```bash
curl -H "Authorization: Bearer <TOKEN>" \
  "http://localhost:8000/fim/events?hostname=prac-server&severity=CRITICAL"
```

### 4. Create / Snapshot New Baseline (Admin)
```bash
curl -X POST -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
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
  }' \
  "http://localhost:8000/fim/baseline/create"
```

---

## Verification & Testing
Covered by automated test suite in `tests/test_phase24_fim.py`:
- Cryptographic SHA-256 calculation.
- HMAC-SHA256 baseline tamper sealing and invalidation on record change.
- Detection of all 5 change categories (`CREATED`, `MODIFIED`, `DELETED`, `PERMISSION_CHANGED`, `OWNERSHIP_CHANGED`).
- High-risk severity mapping for sensitive Linux security assets.
- REST endpoints and RBAC protection.
