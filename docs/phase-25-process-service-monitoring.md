# Phase 25 — Process and Service Monitoring Subsystem

## Overview
The **Process and Service Monitoring Subsystem** provides real-time visibility, behavioral security heuristics, and systemd service state tracking for Linux enterprise workloads within the AI-Powered Cyber Digital Twin platform.

This subsystem monitors active system processes, detects malicious behavioral signatures (such as unauthorized cryptominers, interactive reverse shells, hidden executables, and binaries running from volatile directories like `/tmp` and `/dev/shm`), and tracks systemd service unit health with instant anomaly alerting.

---

## Architecture & Components

```
                +---------------------------------------+
                |     Target Linux Host Telemetry       |
                |  (psutil + /proc + systemctl / dbus)  |
                +-------------------+-------------------+
                                    |
                                    v
                +---------------------------------------+
                |    ProcessSecurityAnalyzer (Rules)    |
                | - Cryptominer Signature Detection     |
                | - Reverse Shell Argument Heuristics   |
                | - Volatile Executable Directory Flag  |
                | - Hidden Binary / Process Evasion     |
                | - Resource Saturation (CPU / RAM)     |
                | - Systemd Critical Unit Failure       |
                +-------------------+-------------------+
                                    |
                                    v
                +---------------------------------------+
                |       ProcessMonitoringService        |
                |  - PostgreSQL State Sync / In-Memory  |
                |  - Aggregated Metrics & Auditing      |
                |  - Incident & Security Alert Engine   |
                +-------------------+-------------------+
                                    |
           +------------------------+------------------------+
           |                                                 |
           v                                                 v
+-----------------------+                         +-----------------------+
|  Process REST API     |                         |  Live Dashboard UI    |
|  /process-monitoring/ |                         |  KPI Cards & Tables   |
+-----------------------+                         +-----------------------+
```

---

## Key Features

1. **Malicious Signature & Behavioral Detection**:
   - **Cryptominers**: Identifies known mining tools (`xmrig`, `minerd`, `cgminer`, `cpuminer`) and mining protocol arguments (`stratum+tcp`, `stratum+ssl`).
   - **Interactive Reverse Shells**: Detects network redirection patterns (`/dev/tcp/`, `/dev/udp/`, `nc -e`, `ncat -e`, `bash -i`).
   - **Volatile Execution Paths**: Detects execution out of write-heavy ephemeral locations (`/tmp`, `/var/tmp`, `/dev/shm`).
   - **Hidden Execution**: Flags binaries whose basenames start with a period (e.g. `/.crypto`, `/.hidden_agent`).
   - **Resource Saturation**: Triggers alerts when processes cross high CPU (>85%) or memory (>80%) thresholds.

2. **Systemd Service Unit Health**:
   - Continuously supervises critical units (`sshd.service`, `nginx.service`, `docker.service`, `firewalld.service`, `auditd.service`, `cron.service`).
   - Generates high/critical severity security alerts immediately when critical daemons enter a `failed` or unexpected state.

3. **Multi-Host Resilience & Fallback**:
   - Fully decoupled from local database dependencies. Under test environments or network partitioning, the service provides structured baseline seed processes and service telemetry seamlessly.

---

## Database Models & Schema

- **`monitored_processes`**: Hostname, PID, PPID, process name, command line, executable path, user, CPU %, memory %, status, risk score, is_suspicious flag, recorded timestamp.
- **`systemd_service_units`**: Hostname, unit name, load state, active state, sub state, is_critical flag, status description, last checked timestamp.
- **`process_security_alerts`**: Hostname, alert type, severity, PID, process name, MITRE technique (`T1059`, `T1496`, `T1053`, `T1071`), description, resolution status.

---

## API Endpoints Reference

All endpoints are mounted under `/process-monitoring` and secured via JWT authentication:

| Method | Endpoint | Description | Required Role |
| :--- | :--- | :--- | :--- |
| `GET` | `/process-monitoring/processes` | Retrieve active monitored processes (filterable by host and suspicious flag) | `admin`, `analyst`, `viewer` |
| `GET` | `/process-monitoring/services` | Retrieve monitored systemd service units | `admin`, `analyst`, `viewer` |
| `GET` | `/process-monitoring/alerts` | Retrieve process and service security alerts | `admin`, `analyst`, `viewer` |
| `GET` | `/process-monitoring/stats` | Aggregated process and service metrics | `admin`, `analyst`, `viewer` |
| `POST` | `/process-monitoring/scan` | Trigger immediate process tree inspection | `admin`, `analyst` |
| `POST` | `/process-monitoring/systemd/scan` | Trigger immediate systemd unit health evaluation | `admin`, `analyst` |

---

## Dashboard Integration

The dashboard (`frontend/index.html` & `frontend/app.js`) features:
- **Summary KPI Counters**: Total Processes, Resource Hogs, Suspicious Processes, Failed Services.
- **Interactive Action Buttons**: "Scan Processes", "Scan Systemd", and "Refresh".
- **Real-Time Tables**:
  - Process Security Alerts & Anomalies table with severity badges and MITRE tags.
  - Active Processes table ranked by resource consumption with risk scoring.
  - Critical Systemd Services status table.
