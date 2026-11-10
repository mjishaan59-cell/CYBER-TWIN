"""
FIM Configuration & Critical Monitored Files
Phase 24 - File Integrity Monitoring Subsystem
"""

from typing import Dict, Any, List

# Core Linux security files categorized by impact
CRITICAL_LINUX_PATHS: Dict[str, Dict[str, Any]] = {
    "/etc/shadow": {
        "severity": "CRITICAL",
        "category": "AUTHENTICATION",
        "description": "Encrypted user passwords and aging policies",
        "expected_permissions": "0000"
    },
    "/etc/sudoers": {
        "severity": "CRITICAL",
        "category": "PRIVILEGE_ESCALATION",
        "description": "Sudo privileges and administrative authorization",
        "expected_permissions": "0440"
    },
    "/etc/passwd": {
        "severity": "HIGH",
        "category": "AUTHENTICATION",
        "description": "User account configurations and shells",
        "expected_permissions": "0644"
    },
    "/etc/group": {
        "severity": "HIGH",
        "category": "AUTHENTICATION",
        "description": "Group definitions and memberships",
        "expected_permissions": "0644"
    },
    "/etc/ssh/sshd_config": {
        "severity": "HIGH",
        "category": "REMOTE_ACCESS",
        "description": "SSH daemon configuration and security options",
        "expected_permissions": "0600"
    },
    "/etc/crontab": {
        "severity": "HIGH",
        "category": "PERSISTENCE",
        "description": "System scheduled job definitions",
        "expected_permissions": "0644"
    },
    "/etc/hosts": {
        "severity": "HIGH",
        "category": "NETWORKING",
        "description": "Static IP-to-hostname mappings",
        "expected_permissions": "0644"
    },
    "/etc/resolv.conf": {
        "severity": "MEDIUM",
        "category": "NETWORKING",
        "description": "DNS name resolver configuration",
        "expected_permissions": "0644"
    },
    "/bin/sudo": {
        "severity": "CRITICAL",
        "category": "SUID_BINARY",
        "description": "Privileged elevation binary",
        "expected_permissions": "4755"
    },
    "/bin/su": {
        "severity": "CRITICAL",
        "category": "SUID_BINARY",
        "description": "Switch user identity binary",
        "expected_permissions": "4755"
    }
}


def get_default_monitored_paths() -> List[str]:
    """Return list of default critical monitored file paths."""
    return list(CRITICAL_LINUX_PATHS.keys())
