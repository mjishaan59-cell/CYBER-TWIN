"""
Process & Systemd Service Security Analyzer
Phase 25 - Process and Service Monitoring Subsystem
Rules, heuristics, and behavioral signatures for detecting cryptominers,
reverse shells, volatile execution, and failed security services.
"""

import re
from typing import Dict, Any, List, Optional

# Known malicious binaries and keywords
SUSPICIOUS_CMD_PATTERNS = [
    (r"(?:xmrig|minerd|cpuminer|stratum\+tcp|kworkerds|kinsing)", "CRYPTOMINER", "CRITICAL"),
    (r"(?:nc\s+-[el]|nc\s+.*-e\s+/bin/(?:ba)?sh|bash\s+-i\s+>&|/dev/tcp/)", "REVERSE_SHELL", "CRITICAL"),
    (r"(?:python(?:3)?\s+-c\s+.*pty\.spawn|perl\s+-e\s+.*exec.*sh)", "INTERACTIVE_PAYLOAD", "HIGH"),
    (r"(?:/tmp/|/dev/shm/|/var/tmp/)\S+", "VOLATILE_EXECUTION", "HIGH"),
    (r"(?:masscan|zmap|hydra|medusa|nmap\s+-sS)", "NETWORK_SCANNER", "HIGH"),
    (r"(?:mimikatz|lazagne|linpeas|linenum)", "CREDENTIAL_DUMPING", "CRITICAL")
]

# Essential Linux security services that must remain running
CRITICAL_SERVICES = {
    "sshd.service": "SSH Remote Access Daemon",
    "auditd.service": "Linux Audit Framework",
    "firewalld.service": "Host Firewall Daemon",
    "nftables.service": "Packet Filtering Engine",
    "systemd-journald.service": "System Logging Service",
    "fail2ban.service": "Intrusion Prevention Ban Service"
}


class ProcessAnalyzer:
    """
    Analyzes running processes and systemd service states for security risks.
    """

    @staticmethod
    def inspect_process(proc: Dict[str, Any]) -> Dict[str, Any]:
        """
        Inspect a single process dict for malicious signatures and resource anomalies.
        """
        cmdline = str(proc.get("cmdline", "")).lower()
        proc_name = str(proc.get("process_name", "")).lower()
        cpu = float(proc.get("cpu_percent", 0.0))
        mem = float(proc.get("memory_percent", 0.0))
        user = str(proc.get("username", "")).lower()

        # 1. Signature-based Pattern Matching
        for pattern, cat, sev in SUSPICIOUS_CMD_PATTERNS:
            if re.search(pattern, cmdline) or re.search(pattern, proc_name):
                return {
                    "is_suspicious": True,
                    "threat_category": cat,
                    "severity": sev,
                    "alert_type": f"SUSPICIOUS_{cat}_PROCESS",
                    "details": f"Process '{proc.get('process_name')}' matches known malicious signature [{cat}]. Cmd: {proc.get('cmdline')[:80]}",
                    "recommendation": f"Inspect process tree for PID {proc.get('pid')}. Terminate process if unauthorized."
                }

        # 2. Resource Abuse Anomaly
        if cpu >= 85.0:
            return {
                "is_suspicious": True,
                "threat_category": "CPU_EXHAUSTION",
                "severity": "HIGH",
                "alert_type": "EXCESSIVE_CPU_CONSUMPTION",
                "details": f"Process '{proc.get('process_name')}' consuming {cpu}% CPU (PID {proc.get('pid')}).",
                "recommendation": "Check if runaway compute process or hidden unauthorized miner."
            }

        if mem >= 75.0:
            return {
                "is_suspicious": True,
                "threat_category": "MEMORY_EXHAUSTION",
                "severity": "HIGH",
                "alert_type": "EXCESSIVE_MEMORY_CONSUMPTION",
                "details": f"Process '{proc.get('process_name')}' consuming {mem}% Memory (PID {proc.get('pid')}).",
                "recommendation": "Inspect memory leak or resource starvation risk."
            }

        return {
            "is_suspicious": False,
            "threat_category": "BENIGN",
            "severity": "LOW",
            "alert_type": "NONE",
            "details": "Process appears normal.",
            "recommendation": "No action required."
        }

    @staticmethod
    def inspect_service(service: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Inspect a systemd service for failures or degraded critical security services.
        """
        name = service.get("service_name", "").lower()
        active = service.get("active_state", "").lower()
        sub = service.get("sub_state", "").lower()

        if active == "failed" or sub == "failed":
            is_critical = name in CRITICAL_SERVICES
            return {
                "service_name": service.get("service_name"),
                "alert_type": "CRITICAL_SECURITY_SERVICE_FAILED" if is_critical else "SYSTEMD_SERVICE_FAILED",
                "severity": "CRITICAL" if is_critical else "HIGH",
                "details": f"Systemd service '{service.get('service_name')}' entered FAILED state ({sub}). Description: {service.get('description')}",
                "recommendation": f"Investigate with 'systemctl status {service.get('service_name')}' and restart service."
            }

        # Check if a critical security service is inactive/dead
        if name in CRITICAL_SERVICES and active != "active":
            return {
                "service_name": service.get("service_name"),
                "alert_type": "CRITICAL_SERVICE_INACTIVE",
                "severity": "HIGH",
                "details": f"Core defense service '{service.get('service_name')}' is NOT ACTIVE (status: {active}/{sub}).",
                "recommendation": f"Ensure {service.get('service_name')} is enabled and running for host protection."
            }

        return None
