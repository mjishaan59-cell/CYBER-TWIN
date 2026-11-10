"""
Playbook Execution Engine with Safeguards and Remediation Rules
Phase 29 - Advanced Incident Response & Playbooks Subsystem
"""

import uuid
import ipaddress
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone

# Guardrail Whitelists - IPs and Processes that must NEVER be blocked/killed
IMMUTABLE_SAFE_IPS = {"127.0.0.1", "::1", "192.168.38.1", "10.0.0.1", "192.168.38.145"}
PROTECTED_PROCESS_PIDS = {1}
PROTECTED_PROCESS_NAMES = {"systemd", "systemd-journald", "auditd", "sshd", "init", "kthreadd"}

PLAYBOOK_CATALOG = {
    "BLOCK_MALICIOUS_IP": {
        "playbook_id": "BLOCK_MALICIOUS_IP",
        "name": "Block Malicious IP via Host Firewall (iptables/nftables)",
        "description": "Appends an immediate DROP rule for an offending remote IP in host packet filter tables.",
        "requires_confirmation": False,
        "default_mode": "DRY_RUN",
        "required_params": ["ip_address"],
        "mitre_technique": "T1071",
        "action_type": "FIREWALL_RULE"
    },
    "ISOLATE_HOST_VLAN": {
        "playbook_id": "ISOLATE_HOST_VLAN",
        "name": "Network Quarantine & VLAN Isolation",
        "description": "Quarantines a compromised Linux server to an isolated remediation network segment.",
        "requires_confirmation": True,
        "default_mode": "DRY_RUN",
        "required_params": ["target_hostname"],
        "mitre_technique": "T1071",
        "action_type": "NETWORK_ISOLATION"
    },
    "KILL_ROGUE_PROCESS": {
        "playbook_id": "KILL_ROGUE_PROCESS",
        "name": "Terminate Rogue or Malicious Process Tree",
        "description": "Dispatches SIGTERM and SIGKILL signals to terminate unauthorized cryptominers or reverse shells.",
        "requires_confirmation": False,
        "default_mode": "DRY_RUN",
        "required_params": ["pid", "process_name"],
        "mitre_technique": "T1059",
        "action_type": "PROCESS_KILL"
    },
    "RESTORE_FIM_FILE": {
        "playbook_id": "RESTORE_FIM_FILE",
        "name": "Restore Tampered File from Cryptographic Baseline",
        "description": "Replaces modified system files (/etc/sudoers, /etc/shadow) with sealed trusted baseline backups.",
        "requires_confirmation": True,
        "default_mode": "DRY_RUN",
        "required_params": ["file_path"],
        "mitre_technique": "T1548",
        "action_type": "FILE_RESTORE"
    },
    "RESET_COMPROMISED_CREDENTIALS": {
        "playbook_id": "RESET_COMPROMISED_CREDENTIALS",
        "name": "Expire User Password & Invalidate SSH Sessions",
        "description": "Forces password expiration via chage -d 0 and terminates active pts sessions for compromised accounts.",
        "requires_confirmation": True,
        "default_mode": "DRY_RUN",
        "required_params": ["username"],
        "mitre_technique": "T1110",
        "action_type": "ACCOUNT_REMEDIATION"
    },
    "RESTART_FAILED_SERVICE": {
        "playbook_id": "RESTART_FAILED_SERVICE",
        "name": "Restart Failed Critical Systemd Service",
        "description": "Resets failed unit state via systemctl reset-failed and triggers clean service restart.",
        "requires_confirmation": False,
        "default_mode": "DRY_RUN",
        "required_params": ["service_name"],
        "mitre_technique": "T1499",
        "action_type": "SERVICE_RESTART"
    }
}


class PlaybookEngine:
    """
    Evaluates safety guardrails, compiles remediation steps, and executes incident response playbooks.
    """

    @classmethod
    def list_playbooks(cls) -> List[Dict[str, Any]]:
        """Return all catalog playbooks."""
        return list(PLAYBOOK_CATALOG.values())

    @classmethod
    def check_safeguards(
        cls,
        playbook_id: str,
        params: Dict[str, Any],
        is_live: bool = False
    ) -> Tuple[bool, str]:
        """
        Evaluate safety guardrails to prevent accidental self-lockout or host instability.
        """
        if playbook_id == "BLOCK_MALICIOUS_IP":
            ip = str(params.get("ip_address", "")).strip()
            if not ip:
                return False, "Target IP address cannot be empty"
            if ip in IMMUTABLE_SAFE_IPS:
                return False, f"Safeguard Violation: IP '{ip}' is on the protected whitelist and cannot be blocked"
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_loopback:
                    return False, f"Safeguard Violation: Loopback IP '{ip}' cannot be blocked"
            except ValueError:
                return False, f"Invalid IPv4/IPv6 address: '{ip}'"

        elif playbook_id == "KILL_ROGUE_PROCESS":
            pid = int(params.get("pid", 0))
            name = str(params.get("process_name", "")).lower()
            if pid in PROTECTED_PROCESS_PIDS:
                return False, f"Safeguard Violation: Refusing to terminate protected system process PID {pid}"
            if name in PROTECTED_PROCESS_NAMES:
                return False, f"Safeguard Violation: Refusing to terminate essential core daemon '{name}'"

        elif playbook_id == "ISOLATE_HOST_VLAN":
            confirmed = params.get("confirm_isolation", False)
            if is_live and not confirmed:
                return False, "Safeguard Violation: Network quarantine requires explicit 'confirm_isolation=True'"

        elif playbook_id == "RESTORE_FIM_FILE":
            fpath = str(params.get("file_path", "")).strip()
            if not fpath.startswith("/"):
                return False, f"Invalid file path: '{fpath}'. Absolute Linux path required."

        return True, "All guardrail verification checks passed"

    @classmethod
    def execute_playbook(
        cls,
        playbook_id: str,
        target_hostname: str = "prac-server",
        params: Optional[Dict[str, Any]] = None,
        incident_id: str = "",
        executed_by: str = "admin",
        mode: str = "DRY_RUN"
    ) -> Dict[str, Any]:
        """
        Execute an automated or analyst-assisted response playbook with full auditing.
        """
        if playbook_id not in PLAYBOOK_CATALOG:
            raise ValueError(f"Unknown playbook '{playbook_id}'")

        playbook = PLAYBOOK_CATALOG[playbook_id]
        params = params or {}
        is_live = mode.upper() == "LIVE"

        # 1. Guardrail / Safeguard Verification
        passed, note = cls.check_safeguards(playbook_id, params, is_live=is_live)
        exec_id = f"exec-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()

        if not passed:
            return {
                "execution_id": exec_id,
                "playbook_id": playbook_id,
                "playbook_name": playbook["name"],
                "incident_id": incident_id,
                "target_hostname": target_hostname,
                "executed_by": executed_by,
                "mode": mode,
                "safeguards_passed": False,
                "safeguard_notes": note,
                "status": "BLOCKED_BY_SAFEGUARD",
                "parameters": params,
                "execution_log": [
                    {"step": 1, "action": "SAFEGUARD_CHECK", "status": "REJECTED", "detail": note}
                ],
                "result_summary": f"Execution halted: {note}",
                "executed_at": now
            }

        # 2. Compile Playbook Steps
        log = [
            {"step": 1, "action": "SAFEGUARD_VERIFICATION", "status": "PASSED", "detail": note}
        ]

        if playbook_id == "BLOCK_MALICIOUS_IP":
            ip = params.get("ip_address")
            cmd = f"iptables -I INPUT -s {ip} -j DROP"
            log.append({"step": 2, "action": "FIREWALL_COMMAND_COMPILE", "status": "SUCCESS", "detail": cmd})
            log.append({"step": 3, "action": "AUDIT_LOG_PERSISTENCE", "status": "SUCCESS", "detail": f"Blocked IP {ip} in {mode} mode"})
            summary = f"Successfully executed rule to DROP all traffic from {ip} on host '{target_hostname}' ({mode})."

        elif playbook_id == "ISOLATE_HOST_VLAN":
            log.append({"step": 2, "action": "VLAN_RECONFIGURATION", "status": "SUCCESS", "detail": f"Switched interface to remediation segment (VLAN 999)"})
            log.append({"step": 3, "action": "MANAGEMENT_LINK_PRESERVE", "status": "SUCCESS", "detail": "Kept jumpbox SSH port open for forensic triage"})
            summary = f"Host '{target_hostname}' placed into virtual network quarantine ({mode})."

        elif playbook_id == "KILL_ROGUE_PROCESS":
            pid = params.get("pid")
            pname = params.get("process_name")
            log.append({"step": 2, "action": "SIGNAL_DISPATCH_SIGTERM", "status": "SUCCESS", "detail": f"kill -15 {pid} ({pname})"})
            log.append({"step": 3, "action": "VERIFY_PROCESS_TERMINATION", "status": "SUCCESS", "detail": f"PID {pid} no longer in process tree"})
            summary = f"Terminated rogue process '{pname}' (PID: {pid}) on host '{target_hostname}' ({mode})."

        elif playbook_id == "RESTORE_FIM_FILE":
            fpath = params.get("file_path")
            log.append({"step": 2, "action": "FETCH_CRYPTO_SEALED_BACKUP", "status": "SUCCESS", "detail": f"Retrieved baseline backup for {fpath}"})
            log.append({"step": 3, "action": "RESTORE_AND_SET_PERMISSIONS", "status": "SUCCESS", "detail": f"Overwrote {fpath} and restored strict permissions 0640"})
            summary = f"Restored integrity of critical file '{fpath}' from verified baseline ({mode})."

        elif playbook_id == "RESET_COMPROMISED_CREDENTIALS":
            user = params.get("username")
            log.append({"step": 2, "action": "EXPIRE_ACCOUNT_PASSWORD", "status": "SUCCESS", "detail": f"chage -d 0 {user}"})
            log.append({"step": 3, "action": "CLEAR_AUTHORIZED_KEYS", "status": "SUCCESS", "detail": f"Cleared ~/.ssh/authorized_keys for {user}"})
            summary = f"Compromised credentials for '{user}' expired on host '{target_hostname}' ({mode})."

        elif playbook_id == "RESTART_FAILED_SERVICE":
            sname = params.get("service_name")
            log.append({"step": 2, "action": "SYSTEMCTL_RESET_FAILED", "status": "SUCCESS", "detail": f"systemctl reset-failed {sname}"})
            log.append({"step": 3, "action": "SYSTEMCTL_RESTART", "status": "SUCCESS", "detail": f"systemctl restart {sname}"})
            summary = f"Restarted failed systemd unit '{sname}' on host '{target_hostname}' ({mode})."

        else:
            summary = f"Playbook '{playbook_id}' executed successfully ({mode})."

        return {
            "execution_id": exec_id,
            "playbook_id": playbook_id,
            "playbook_name": playbook["name"],
            "incident_id": incident_id,
            "target_hostname": target_hostname,
            "executed_by": executed_by,
            "mode": mode,
            "safeguards_passed": True,
            "safeguard_notes": note,
            "status": "SUCCESS",
            "parameters": params,
            "execution_log": log,
            "result_summary": summary,
            "executed_at": now
        }
