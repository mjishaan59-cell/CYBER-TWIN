"""
What-If Attack Simulation Engine
Phase 28 - What-If Attack Simulation Subsystem
Safe, controlled synthetic adversary simulation, impact prediction,
and defensive recommendation generation.
"""

import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

# Synthetic Attack Scenario Definitions
SCENARIO_CATALOG = {
    "SSH_BRUTE_FORCE": {
        "scenario_id": "SSH_BRUTE_FORCE",
        "name": "Distributed SSH Credential Stuffing & Brute Force",
        "description": "Simulates high-frequency dictionary attack against OpenSSH daemon from multiple distributed IP addresses.",
        "mitre_technique": "T1110.001",
        "tactics": "Credential Access",
        "severity": "HIGH",
        "base_risk": 75,
        "default_steps": [
            ("Port Discovery & Banner Grabbing", "T1046", "SYN scan to port 22; OpenSSH 9.2 banner retrieved", "DETECTED"),
            ("Credential Spraying Burst", "T1110.001", "25 failed authentication attempts for root/admin/ubuntu in 3s", "DETECTED"),
            ("Distributed Password Guessing", "T1110.003", "Rotation across 5 external IPs to evade simple per-IP thresholds", "DETECTED"),
            ("Account Lockout / Rate-Limit Trigger", "T1110", "Fail2ban or rate-limiter jail engaged; connection dropped", "BLOCKED")
        ],
        "recommendations": [
            "Disable SSH password authentication and enforce Ed25519 public key auth (PermitRootLogin no, PasswordAuthentication no)",
            "Deploy Fail2ban or SSHGuard with maxretry = 3 and bantime = 86400",
            "Move SSH listening port to a non-standard port and restrict ingress via security group / firewall rules"
        ]
    },
    "REVERSE_SHELL_INJECTION": {
        "scenario_id": "REVERSE_SHELL_INJECTION",
        "name": "Remote Command Injection & Reverse Shell",
        "description": "Simulates web application command injection spawning an interactive bash shell redirected to an external listener.",
        "mitre_technique": "T1059.004",
        "tactics": "Execution / C2",
        "severity": "CRITICAL",
        "base_risk": 95,
        "default_steps": [
            ("Web Input Vulnerability Probe", "T1190", "HTTP POST payload containing shell metacharacters (; /bin/bash)", "DETECTED"),
            ("Interactive Process Spawn", "T1059.004", "Parent: nginx/gunicorn, Child: /bin/bash -i >& /dev/tcp/...", "DETECTED"),
            ("Outbound C2 Sockets", "T1071", "SYN socket established to high-risk external port 4444", "DETECTED"),
            ("Host Perimeter Defense", "T1059", "Process analyzer flags reverse shell command line; socket terminated", "BLOCKED")
        ],
        "recommendations": [
            "Enforce strict input validation and parameterization on all user-supplied input strings",
            "Apply AppArmor or SELinux profiles confining web processes from invoking bash/sh binaries",
            "Configure outbound egress firewall filtering allowing only authorized web/DNS ports"
        ]
    },
    "PRIVILEGE_ESCALATION_SUID": {
        "scenario_id": "PRIVILEGE_ESCALATION_SUID",
        "name": "SUID Binary Abuse & Sudoers Tampering",
        "description": "Simulates local unprivileged user discovering SUID binaries and modifying /etc/sudoers for persistent root access.",
        "mitre_technique": "T1548.001",
        "tactics": "Privilege Escalation",
        "severity": "CRITICAL",
        "base_risk": 90,
        "default_steps": [
            ("SUID Enumeration Probe", "T1083", "find / -perm -4000 -type f 2>/dev/null", "DETECTED"),
            ("Vulnerable Binary Execution", "T1548.001", "Execution of misconfigured root-owned SUID helper", "DETECTED"),
            ("Sudoers Modification Attempt", "T1548.003", "Write attempt to /etc/sudoers (NOPASSWD: ALL)", "DETECTED"),
            ("FIM Violation Interception", "T1548", "FIM baseline engine detects hash/content tampering; security alert raised", "BLOCKED")
        ],
        "recommendations": [
            "Audit all SUID/SGID binaries using 'chmod -s' on unneeded utilities",
            "Lock /etc/sudoers with immutable bit (chattr +i /etc/sudoers)",
            "Enable File Integrity Monitoring (FIM) continuous auditing on /etc/sudoers and /etc/shadow"
        ]
    },
    "DATA_EXFILTRATION_DNS": {
        "scenario_id": "DATA_EXFILTRATION_DNS",
        "name": "Covert Data Exfiltration via DNS Tunneling",
        "description": "Simulates encoding sensitive enterprise telemetry into chunked subdomains to bypass perimeter inspection.",
        "mitre_technique": "T1048.003",
        "tactics": "Exfiltration",
        "severity": "HIGH",
        "base_risk": 80,
        "default_steps": [
            ("Sensitive File Discovery", "T1083", "Accessing /etc/passwd and /var/log/secure", "DETECTED"),
            ("Payload Base64 Encoding", "T1027", "Encoding credentials into DNS-compatible alphanumeric chunks", "DETECTED"),
            ("High-Frequency Subdomain Queries", "T1048.003", "120 rapid TXT/A queries to *.tunnel.attacker-domain.com", "DETECTED"),
            ("DNS Inspection Containment", "T1071.004", "DNS anomaly heuristic flags DGA high entropy; queries sinkholed", "BLOCKED")
        ],
        "recommendations": [
            "Deploy DNS response policy zones (RPZ) and restrict DNS resolution to authenticated internal resolvers",
            "Monitor outbound DNS query length and query frequency for entropy anomalies",
            "Restrict egress UDP/TCP port 53 exclusively to designated corporate DNS servers"
        ]
    },
    "RANSOMWARE_BURST": {
        "scenario_id": "RANSOMWARE_BURST",
        "name": "Rapid Multi-File Encryption Wave (Ransomware Burst)",
        "description": "Simulates rapid file modification and encryption across non-production test folders to measure FIM detection velocity.",
        "mitre_technique": "T1486",
        "tactics": "Impact",
        "severity": "CRITICAL",
        "base_risk": 98,
        "default_steps": [
            ("Shadow Directory Traversal", "T1083", "Scanning target test folder tree for writeable documents", "DETECTED"),
            ("Batch File Extension Renaming", "T1486", "Renaming *.log and *.conf to *.encrypted_test", "DETECTED"),
            ("High-Entropy File Content Writes", "T1486", "AES-256 simulated payload overwrite bursts", "DETECTED"),
            ("Automated Containment Action", "T1486", "FIM rapid-burst alert triggers process freeze and snapshot isolation", "BLOCKED")
        ],
        "recommendations": [
            "Maintain immutable, offsite backups with automated point-in-time recovery testing",
            "Configure volume-level snapshot policies with write-once-read-many (WORM) storage",
            "Implement automated process kill triggers upon detecting multiple FIM modifications per second"
        ]
    },
    "RESOURCE_DOS_ATTACK": {
        "scenario_id": "RESOURCE_DOS_ATTACK",
        "name": "Resource Exhaustion & Denial of Service",
        "description": "Simulates runaway memory allocation and CPU thread saturation to test predictive saturation forecasting.",
        "mitre_technique": "T1499.001",
        "tactics": "Impact",
        "severity": "MEDIUM",
        "base_risk": 65,
        "default_steps": [
            ("Thread Fork Explosion", "T1499.001", "Spawning 20 worker threads executing intensive math loops", "DETECTED"),
            ("Memory Buffer Leak Simulation", "T1499.001", "Heap allocation growth at 50 MB/s towards 90% capacity", "DETECTED"),
            ("Predictive Engine Early Alert", "T1499", "Predictive forecaster flags PROJECTED_MEMORY_EXHAUSTION (3 min window)", "DETECTED"),
            ("Cgroup OOM Prevention Limit", "T1499", "Systemd Slice memory limit enforces throttle before host crash", "BLOCKED")
        ],
        "recommendations": [
            "Define systemd Slice memory and CPU quotas (MemoryMax, CPUQuota) for all system services",
            "Enable early OOM daemon (systemd-oomd) to protect critical kernel daemons",
            "Set proactive predictive threshold alerting at 80% capacity"
        ]
    }
}


class SimulationEngine:
    """
    Executes controlled synthetic adversary scenarios, predicts impact,
    and returns tactical defense recommendations.
    """

    @classmethod
    def list_scenarios(cls) -> List[Dict[str, Any]]:
        """Return all available synthetic scenarios."""
        return list(SCENARIO_CATALOG.values())

    @classmethod
    def get_scenario(cls, scenario_id: str) -> Optional[Dict[str, Any]]:
        """Find scenario by scenario_id."""
        return SCENARIO_CATALOG.get(scenario_id)

    @classmethod
    def run_simulation(
        cls,
        scenario_id: str,
        target_hostname: str = "prac-server",
        simulated_by: str = "admin"
    ) -> Dict[str, Any]:
        """
        Execute a safe, non-destructive synthetic attack simulation.
        """
        scenario = cls.get_scenario(scenario_id)
        if not scenario:
            raise ValueError(f"Unknown attack simulation scenario '{scenario_id}'")

        sim_id = f"sim-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()

        # Step-by-step synthetic simulation trace
        steps_log = []
        for idx, (name, subtech, obs, det_status) in enumerate(scenario["default_steps"], start=1):
            steps_log.append({
                "simulation_id": sim_id,
                "step_number": idx,
                "step_name": name,
                "mitre_subtechnique": subtech,
                "action_type": "SYNTHETIC_PROBE",
                "observed_telemetry": obs,
                "detection_status": det_status,
                "details": f"Simulated adversary technique {subtech} targeted against {target_hostname}.",
                "logged_at": now
            })

        # Calculate Impact Metrics based on scenario
        base_risk = scenario["base_risk"]
        severity = scenario["severity"]

        mttd = 8 if severity == "CRITICAL" else 15 if severity == "HIGH" else 30
        mttr = 60 if severity == "CRITICAL" else 120 if severity == "HIGH" else 180
        containment_prob = 92.0 if severity == "CRITICAL" else 88.0

        impact_summary = (
            f"Synthetic simulation of {scenario['name']} on host '{target_hostname}' completed successfully. "
            f"Adversary tactic '{scenario['tactics']}' ({scenario['mitre_technique']}) was fully simulated across "
            f"{len(steps_log)} controlled phases. All telemetry was captured by the digital twin sensor array with "
            f"predicted containment probability of {containment_prob}%."
        )

        return {
            "simulation_id": sim_id,
            "scenario_id": scenario_id,
            "scenario_name": scenario["name"],
            "target_hostname": target_hostname,
            "mitre_technique": scenario["mitre_technique"],
            "tactics": scenario["tactics"],
            "simulated_by": simulated_by,
            "status": "COMPLETED",
            "risk_score": base_risk,
            "impact_level": severity,
            "predicted_containment_probability": containment_prob,
            "estimated_mttd_seconds": mttd,
            "estimated_mttr_seconds": mttr,
            "defensive_recommendations": scenario["recommendations"],
            "impact_summary": impact_summary,
            "steps": steps_log,
            "started_at": now,
            "completed_at": now
        }
