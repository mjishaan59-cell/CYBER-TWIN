"""
MITRE ATT&CK Mapping Subsystem
Phase 22 - AI Threat Intelligence Subsystem
"""

from typing import Dict, Any, Optional, List

# Authoritative MITRE ATT&CK Techniques relevant to Linux cyber defense and server operations
MITRE_ATTACK_DB: Dict[str, Dict[str, Any]] = {
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown or when password hashes are unavailable.",
        "subtechniques": ["T1110.001 (Password Guessing)", "T1110.003 (Password Spraying)"],
        "mitigation": "Account lockout policies, multi-factor authentication, SSH key-only auth, fail2ban rate limiting.",
        "url": "https://attack.mitre.org/techniques/T1110/"
    },
    "T1110.001": {
        "id": "T1110.001",
        "name": "Password Guessing",
        "tactic": "Credential Access",
        "description": "Adversaries with no prior knowledge of passwords may systematically attempt passwords on SSH or web services.",
        "subtechniques": [],
        "mitigation": "Disable password authentication, enforce rate limiting, use SSH keys.",
        "url": "https://attack.mitre.org/techniques/T1110/001/"
    },
    "T1110.003": {
        "id": "T1110.003",
        "name": "Password Spraying",
        "tactic": "Credential Access",
        "description": "Adversaries may use a single or small list of commonly used passwords against many accounts to avoid lockout thresholds.",
        "subtechniques": [],
        "mitigation": "Enforce strong password policy, monitor failed login distributions across accounts.",
        "url": "https://attack.mitre.org/techniques/T1110/003/"
    },
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic.",
        "subtechniques": ["T1071.001 (Web Protocols)", "T1071.004 (DNS)"],
        "mitigation": "Network intrusion detection, protocol anomaly detection, outbound egress filtering.",
        "url": "https://attack.mitre.org/techniques/T1071/"
    },
    "T1071.001": {
        "id": "T1071.001",
        "name": "Web Protocols (HTTP/HTTPS C2)",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using HTTP/HTTPS to blend in with normal web surfing.",
        "subtechniques": [],
        "mitigation": "SSL inspection, threat intel domain blocklists, egress proxy filtering.",
        "url": "https://attack.mitre.org/techniques/T1071/001/"
    },
    "T1071.004": {
        "id": "T1071.004",
        "name": "DNS C2 Communication",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection.",
        "subtechniques": [],
        "mitigation": "DNS sinkholing, monitoring suspicious DNS request volume and entropy.",
        "url": "https://attack.mitre.org/techniques/T1071/004/"
    },
    "T1021.004": {
        "id": "T1021.004",
        "name": "Remote Services: SSH",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use Valid Accounts to log into remote machines using Secure Shell (SSH) for lateral movement.",
        "subtechniques": [],
        "mitigation": "Strict firewall segmentation, bastion hosts, multi-factor authentication on SSH.",
        "url": "https://attack.mitre.org/techniques/T1021/004/"
    },
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit vulnerabilities in Internet-facing software (e.g. web servers, databases).",
        "subtechniques": [],
        "mitigation": "Regular patch management, Web Application Firewalls (WAF), vulnerability scanning.",
        "url": "https://attack.mitre.org/techniques/T1190/"
    },
    "T1059.004": {
        "id": "T1059.004",
        "name": "Command and Scripting Interpreter: Unix Shell",
        "tactic": "Execution",
        "description": "Adversaries may abuse Unix shell commands and scripts (bash, sh, zsh) to execute malicious code.",
        "subtechniques": [],
        "mitigation": "Auditd logging, restricting shell access, principle of least privilege.",
        "url": "https://attack.mitre.org/techniques/T1059/004/"
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts (port scanning).",
        "subtechniques": [],
        "mitigation": "Disable unused listening services, use host-based firewalls (iptables/nftables).",
        "url": "https://attack.mitre.org/techniques/T1046/"
    },
    "T1499": {
        "id": "T1499",
        "name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services.",
        "subtechniques": [],
        "mitigation": "Rate limiting, resource quotas (cgroups/systemd), anomaly detection.",
        "url": "https://attack.mitre.org/techniques/T1499/"
    },
    "T1090.003": {
        "id": "T1090.003",
        "name": "Multi-hop Proxy: Tor",
        "tactic": "Command and Control",
        "description": "Adversaries may route traffic through the Tor network to conceal command and control server origins.",
        "subtechniques": [],
        "mitigation": "Block known Tor exit nodes at border firewalls, flag Tor exit IPs in SIEM/twin.",
        "url": "https://attack.mitre.org/techniques/T1090/003/"
    }
}

# Mapping keywords / threat types to MITRE technique IDs
THREAT_TYPE_MITRE_MAP: Dict[str, str] = {
    "SSH_BRUTE_FORCE": "T1110.001",
    "PASSWORD_SPRAYING": "T1110.003",
    "BRUTE_FORCE": "T1110",
    "MALWARE_C2": "T1071.001",
    "BOTNET_C2": "T1071",
    "DNS_TUNNEL": "T1071.004",
    "TOR_EXIT_NODE": "T1090.003",
    "PORT_SCANNER": "T1046",
    "SCANNER": "T1046",
    "EXPLOIT_PROBE": "T1190",
    "SHELL_INJECTION": "T1059.004",
    "LATERAL_MOVEMENT": "T1021.004",
    "DENIAL_OF_SERVICE": "T1499"
}


def map_threat_to_mitre(threat_type: str, context: Optional[str] = None) -> Dict[str, Any]:
    """
    Map a given threat type or behavioral pattern to the corresponding MITRE ATT&CK technique.
    """
    normalized = threat_type.strip().upper()
    tech_id = THREAT_TYPE_MITRE_MAP.get(normalized, "T1110")
    
    # Check context keywords if not directly matched
    if tech_id == "T1110" and context:
        ctx_lower = context.lower()
        if "tor" in ctx_lower:
            tech_id = "T1090.003"
        elif "scan" in ctx_lower or "probe" in ctx_lower:
            tech_id = "T1046"
        elif "c2" in ctx_lower or "command" in ctx_lower:
            tech_id = "T1071.001"
        elif "spray" in ctx_lower:
            tech_id = "T1110.003"
        elif "exploit" in ctx_lower:
            tech_id = "T1190"

    technique = MITRE_ATTACK_DB.get(tech_id, MITRE_ATTACK_DB["T1110"])
    return {
        "attack_id": technique["id"],
        "technique_name": technique["name"],
        "tactic": technique["tactic"],
        "description": technique["description"],
        "mitigation": technique["mitigation"],
        "url": technique["url"]
    }


def get_all_mitre_techniques() -> List[Dict[str, Any]]:
    """Return all cataloged MITRE ATT&CK techniques."""
    return list(MITRE_ATTACK_DB.values())
