# Phase 27 — Multi-Server Expansion Subsystem

## Overview
The **Multi-Server Expansion Subsystem** elevates the AI-Powered Cyber Digital Twin from a single-machine monitor into an enterprise-scale, distributed Linux fleet management and cybersecurity orchestrator.

It provides centralized host inventory, automated reachability probing, environment and tier grouping, fleet-wide resource and health aggregation, and a live dashboard host switcher enabling operators to pivot monitoring focus across dozens or hundreds of distributed Linux nodes.

---

## Fleet Architecture & Topology

```
                          +------------------------------------------+
                          |   Central Cyber Digital Twin Platform    |
                          |      (API, AI Models, Threat Intel)      |
                          +--------------------+---------------------+
                                               |
                     +-------------------------+-------------------------+
                     |                         |                         |
                     v                         v                         v
          +---------------------+   +---------------------+   +---------------------+
          |  Primary Workload   |   |   Edge Web Ingress  |   | PostgreSQL Cluster  |
          |     prac-server     |   |     prod-web-01     |   |    db-cluster-01    |
          |  192.168.38.145:22  |   |  192.168.38.150:22  |   |  192.168.38.160:22  |
          |   Group: General    |   | Group: Web Servers  |   | Group: DB Clusters  |
          |   Env: Production   |   |   Env: Production   |   |   Env: Production   |
          +---------------------+   +---------------------+   +---------------------+
                     |                         |                         |
                     +-------------------------+-------------------------+
                                               |
                     +-------------------------+-------------------------+
                     |                                                   |
                     v                                                   v
          +---------------------+                             +---------------------+
          |   DMZ Border Node   |                             |   Staging Canary    |
          |   edge-gateway-01   |                             |   staging-app-01    |
          | 192.168.38.170:2222 |                             |  192.168.38.180:22  |
          | Group: Edge Gateway |                             | Group: Web Servers  |
          |      Env: DMZ       |                             |    Env: Staging     |
          +---------------------+                             +---------------------+
```

---

## Core Capabilities

1. **Centralized Dynamic Host Inventory**:
   - Register new managed hosts on-the-fly with host metadata (hostname, display name, IP, SSH port, user, auth method, OS flavor, environment, tags).
   - Update server properties, decommission/deregister retired hosts.
   - Categorize by environments (`production`, `staging`, `testing`, `dmz`) and architectural tiers (`web_servers`, `db_clusters`, `edge_gateways`, `general`).

2. **Remote Heartbeat & Reachability Prober**:
   - Dispatches socket connectivity checks to measure link latency (in milliseconds) and verify host status (`ONLINE`, `OFFLINE`, `DEGRADED`, `MAINTENANCE`).
   - Maintains an audit history of ping probes in `server_health_heartbeats`.

3. **Fleet-Wide Health Aggregation**:
   - Computes real-time fleet totals (total managed servers, online/offline breakdown, average CPU, RAM, disk utilization, and network round-trip latency).
   - Generates breakdown counts by operational environment and host group.

4. **Host Switcher**:
   - Seamlessly switches the dashboard UI focus across any managed server in the fleet, instantaneously loading its respective processes, network sockets, FIM baseline, and security alerts.

---

## Database Models & Schema

- **`managed_servers`**: Hostname, display name, IP address, SSH port, username, authentication method, environment, host group, OS flavor, status, latency ms, CPU/RAM/Disk metrics, tags, notes, active flag.
- **`server_health_heartbeats`**: Hostname, reachability status, round-trip latency, error message, timestamp.

---

## API Endpoints Reference

All endpoints are mounted under `/multihost` and protected with JWT RBAC:

| Method | Endpoint | Description | Role Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/multihost/servers` | List managed fleet servers with optional filters | `admin`, `analyst`, `viewer` |
| `POST` | `/multihost/servers` | Register a new server in the fleet | `admin` |
| `GET` | `/multihost/servers/{id}` | Retrieve specific server metadata and health | `admin`, `analyst`, `viewer` |
| `PUT` | `/multihost/servers/{id}` | Update server metadata, status, or group | `admin`, `analyst` |
| `DELETE` | `/multihost/servers/{id}` | Decommission and remove server from fleet | `admin` |
| `POST` | `/multihost/servers/{id}/ping` | Dispatch live connectivity probe (latency ms) | `admin`, `analyst` |
| `GET` | `/multihost/fleet/health` | Fleet aggregate metrics and health status | `admin`, `analyst`, `viewer` |
| `GET` | `/multihost/fleet/groups` | Available environments and server groups | `admin`, `analyst`, `viewer` |

---

## Dashboard Integration

- **Host Switcher Dropdown**: Allows instant one-click switching of active target server across all dashboards.
- **Fleet Summary KPI Cards**: Total Managed Servers, Online Nodes, Degraded/Offline, Fleet Avg CPU %, Fleet Avg RAM %, Fleet Avg Latency ms.
- **Distributed Server Inventory Table**: Displays host IP, environment badge, group, OS, status, current compute load, ping latency, and quick "Focus" / "Ping" action buttons.
