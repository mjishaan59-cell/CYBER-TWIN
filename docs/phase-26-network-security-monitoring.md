# Phase 26 — Network Security Monitoring Subsystem

## Overview
The **Network Security Monitoring Subsystem** provides real-time socket connection tracking, listening port profiling, network interface telemetry, and automated threat detection for enterprise Linux cloud environments.

It bridges low-level kernel networking with high-level cybersecurity analytics, correlating active connections against Phase 22 Threat Intelligence IOCs, profiling open ports against an authorized server baseline, detecting reconnaissance/scanning behavior, and mapping all anomalies to MITRE ATT&CK techniques.

---

## Architecture & Data Flow

```
                     +---------------------------------------+
                     |    Target Linux Host Sockets & NICs   |
                     |  (psutil + /proc/net/tcp + netstat)   |
                     +-------------------+-------------------+
                                         |
                                         v
                     +---------------------------------------+
                     |        NetworkSecurityAnalyzer        |
                     | - Listening Port Profiling (Allowed)  |
                     | - High-Risk Trojan/Backdoor Port Flag |
                     | - Threat Intel IOC IP Match (T1071)   |
                     | - SYN_SENT Scan Detection (T1046)     |
                     | - Non-Standard Port Anomaly (T1043)   |
                     | - NIC Down / Drop Error Health        |
                     +-------------------+-------------------+
                                         |
                                         v
                     +---------------------------------------+
                     |       NetworkMonitoringService        |
                     | - Periodic & On-Demand Host Audits    |
                     | - In-Memory Cache & PostgreSQL Store  |
                     | - Real-time Network Security Alerts   |
                     +-------------------+-------------------+
                                         |
              +--------------------------+--------------------------+
              |                                                     |
              v                                                     v
+---------------------------+                         +---------------------------+
|    Network REST APIs      |                         |   Live Dashboard UI       |
|    /network/interfaces    |                         |   - Summary KPI Counters  |
|    /network/connections   |                         |   - Active Sockets Table  |
|    /network/ports         |                         |   - Listening Ports Table |
|    /network/alerts        |                         |   - Network Alerts Table  |
|    /network/stats         |                         |   - Interface NIC Table   |
+---------------------------+                         +---------------------------+
```

---

## Key Capabilities

1. **Listening Port Profiling & Unauthorized Service Detection**:
   - **Baseline Ports**: Automatically recognizes authorized enterprise services (`22/SSH`, `80/HTTP`, `443/HTTPS`, `53/DNS`, `5432/PostgreSQL`, `123/NTP`).
   - **High-Risk Ports**: Immediately flags dangerous listener ports including Metasploit handler (`4444`), Elite backdoors (`1337`, `31337`), IRC botnet C2 (`6667`), and Tor onion proxies (`9001`, `9050`).
   - **MITRE ATT&CK Mapping**: Labels events with `T1571` (Non-Standard Port) and `T1059` (Command and Scripting Interpreter).

2. **Connection Threat Correlation**:
   - Compares remote destination IPs with Threat Intelligence feeds (Abuse.ch Feodo Tracker, URLhaus, Tor exit nodes).
   - Identifies active Command & Control (C2) communication channels in real-time.
   - Detects outbound network reconnaissance (repeated `SYN_SENT` sockets to non-standard remote ports).

3. **Interface Health & Traffic Analytics**:
   - Monitors physical and virtual NICs (`eth0`, `lo`, `ens33`).
   - Tracks transmitted/received byte volumes, packet rates, framing errors, and drops.
   - Triggers `INTERFACE_DOWN` and `EXCESSIVE_PACKET_DROPS` degradation alerts.

---

## Database Models & Schema

- **`network_interface_snapshots`**: Interface name, bytes sent/recv, packets sent/recv, error counters, drop counters, operational status (`is_up`), link speed.
- **`network_connection_records`**: Protocol (`tcp`/`udp`), local socket, remote socket, state (`LISTEN`, `ESTABLISHED`, `SYN_SENT`), PID, process name, suspicious flag, risk score, threat description.
- **`listening_port_records`**: Bind address, port number, PID, process name, authorized flag, service hint, risk level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **`network_security_alerts`**: Alert type, severity, source IP/port, destination IP/port, protocol, MITRE technique, description, remediation recommendation.

---

## API Endpoints Reference

All endpoints are mounted under `/network` with JWT role-based access control:

| Method | Endpoint | Description | Role Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/network/interfaces` | Query network interface health and traffic statistics | `admin`, `analyst`, `viewer` |
| `GET` | `/network/connections` | Retrieve active socket connections (with suspicious filter) | `admin`, `analyst`, `viewer` |
| `GET` | `/network/ports` | Query open listening ports and binding services | `admin`, `analyst`, `viewer` |
| `GET` | `/network/alerts` | Retrieve network security and anomaly alerts | `admin`, `analyst`, `viewer` |
| `GET` | `/network/stats` | Aggregated network summary metrics and throughput | `admin`, `analyst`, `viewer` |
| `POST` | `/network/scan` | Trigger on-demand socket and interface audit | `admin`, `analyst` |

---

## Dashboard Integration

The Cyber Digital Twin user interface includes:
- **KPI Summary Cards**: Active Sockets, Open Listening Ports, Suspicious Sockets, Unexpected Ports, Egress Throughput, Ingress Throughput.
- **On-Demand Action Button**: "Scan Network Now" for instantaneous host audit.
- **Interactive Tables**:
  - Open Listening Ports & Bound Services.
  - Active Sockets with process ownership and risk scoring.
  - Network Security Alerts with MITRE technique codes and severity badges.
  - Network Interfaces table with drop and error rate status.
