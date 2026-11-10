# Phase 28 — What-If Attack Simulation Subsystem

## Overview
The **What-If Attack Simulation Subsystem** empowers security engineers, DevSecOps practitioners, and administrators to evaluate the defensive posture of Linux systems against real-world adversary tradecraft in a **safe, strictly controlled, and non-destructive virtual manner**.

Rather than running destructive payloads on live production filesystems, this subsystem simulates cyber attacks against the **Cyber Digital Twin representation** of target nodes. It computes expected Mean Time to Detect (MTTD), Mean Time to Respond (MTTR), predicted business impact scores, and prescribes immediate defensive hardening actions.

---

## Architecture & Simulation Lifecycle

```
                       +---------------------------------------+
                       |       Security Operator / CI-CD       |
                       |       Selects Scenario & Host         |
                       +-------------------+-------------------+
                                           |
                                           v
                       +---------------------------------------+
                       |          SimulationEngine             |
                       | - Non-destructive Synthetic Injection |
                       | - MITRE ATT&CK Tactic Mapping         |
                       | - Step-by-Step Simulated Timeline     |
                       | - Impact Predictor (MTTD / MTTR)      |
                       +-------------------+-------------------+
                                           |
                                           v
                       +---------------------------------------+
                       |          SimulationService            |
                       | - Audit Trail & Step Log Archiving    |
                       | - PostgreSQL Store + In-Memory Fallback|
                       | - Containment Probability Scoring     |
                       +-------------------+-------------------+
                                           |
                +--------------------------+--------------------------+
                |                                                     |
                v                                                     v
+-------------------------------+                         +-------------------------------+
|     Simulation REST APIs      |                         |      Live Dashboard UI        |
|     /simulation/scenarios     |                         |  - Scenario Launcher Dropdown |
|     /simulation/run           |                         |  - Real-time Impact Result    |
|     /simulation/history       |                         |  - Prescriptive Action List   |
|     /simulation/stats         |                         |  - Historical Audit Table     |
+-------------------------------+                         +-------------------------------+
```

---

## Scenario Catalog & MITRE ATT&CK Mapping

The subsystem comes pre-loaded with six standard enterprise adversary scenarios:

1. **Distributed SSH Brute Force (`SSH_BRUTE_FORCE`)**:
   - **MITRE**: `T1110.001` (Brute Force: Password Guessing)
   - **Tactics**: Credential Access
   - **Behavior**: Simulates multi-source rapid failed authentication bursts. Tests SSHGuard/Fail2ban triggers and account lockout policies.

2. **Command Injection & Reverse Shell (`REVERSE_SHELL_INJECTION`)**:
   - **MITRE**: `T1059.004` (Command and Scripting Interpreter: Unix Shell) / `T1071` (C2)
   - **Tactics**: Execution & Command and Control
   - **Behavior**: Simulates web input exploitation spawning interactive bash sockets redirected to external listener port 4444.

3. **SUID Privilege Escalation (`PRIVILEGE_ESCALATION_SUID`)**:
   - **MITRE**: `T1548.001` (Abuse Elevation Control Mechanism: SUID)
   - **Tactics**: Privilege Escalation
   - **Behavior**: Simulates unprivileged local user finding SUID helpers and modifying `/etc/sudoers` to acquire persistent root privileges.

4. **Covert DNS Data Exfiltration (`DATA_EXFILTRATION_DNS`)**:
   - **MITRE**: `T1048.003` (Exfiltration Over Alternative Protocol: DNS)
   - **Tactics**: Exfiltration
   - **Behavior**: Simulates chunking sensitive credential dumps into high-frequency subdomain queries to evade edge packet filters.

5. **Ransomware Burst Encryption (`RANSOMWARE_BURST`)**:
   - **MITRE**: `T1486` (Data Encrypted for Impact)
   - **Tactics**: Impact
   - **Behavior**: Simulates high-speed batch file extension modifications and encryption bursts across non-production test folders to measure File Integrity Monitoring (FIM) detection velocity.

6. **Resource Exhaustion DoS (`RESOURCE_DOS_ATTACK`)**:
   - **MITRE**: `T1499.001` (Endpoint Denial of Service: OS Exhaustion Flood)
   - **Tactics**: Impact
   - **Behavior**: Simulates runaway CPU thread explosion and memory leak spikes to validate the AI Predictive Saturation engine.

---

## Impact Prediction & Defensive Hardening

For every simulation run, the engine computes:
- **Predicted Risk Score (0–100)**: Quantitative risk exposure for the target workload.
- **Estimated MTTD & MTTR**: Projected duration to detection and remediation.
- **Containment Probability (%)**: Likelihood that host defenses (FIM, analyzers, rate-limiters) isolate the attack prior to catastrophic breach.
- **Prescriptive Hardening Recommendations**: Concrete, copy-pasteable configuration changes (e.g. `chmod -s`, immutable `chattr +i`, Fail2ban jails, systemd cgroup slices).

---

## Database Models & Schema

- **`attack_simulation_runs`**: `simulation_id`, `scenario_id`, `scenario_name`, `target_hostname`, `mitre_technique`, `tactics`, `simulated_by`, `status`, `risk_score`, `impact_level`, `predicted_containment_probability`, `estimated_mttd_seconds`, `estimated_mttr_seconds`, `defensive_recommendations` (JSON), `impact_summary`.
- **`simulation_step_logs`**: `simulation_id`, `step_number`, `step_name`, `mitre_subtechnique`, `action_type`, `observed_telemetry`, `detection_status` (`DETECTED`, `EVADED`, `BLOCKED`), `details`.

---

## API Endpoints Reference

All endpoints are mounted under `/simulation` with JWT authentication:

| Method | Endpoint | Description | Role Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/simulation/scenarios` | Catalog of available synthetic scenarios | `admin`, `analyst`, `viewer` |
| `POST` | `/simulation/run` | Execute controlled simulation on target host | `admin`, `analyst` |
| `GET` | `/simulation/history` | Query past simulation runs and outcomes | `admin`, `analyst`, `viewer` |
| `GET` | `/simulation/history/{id}` | Granular step-by-step trace & recommendations | `admin`, `analyst`, `viewer` |
| `GET` | `/simulation/stats` | Aggregated simulation metrics & containment rates | `admin`, `analyst`, `viewer` |

---

## Dashboard Integration

The dashboard includes:
- **Interactive Scenario Launcher**: Dropdown selector with 6 adversary scenarios, target server targeting, and instant "Launch Simulation" trigger.
- **Live Impact Result Box**: Real-time display of predicted risk score badge, MTTD/MTTR metrics, containment probability gauge, and prescriptive hardening checklist.
- **Historical Audit Table**: Displays all previous simulation runs with MITRE technique codes, tactics, simulation owners, and execution status.
