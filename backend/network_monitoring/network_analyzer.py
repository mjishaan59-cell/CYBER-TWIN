"""
Network Security Analyzer
Phase 26 - Network Security Monitoring Subsystem
Heuristics, signature matching, MITRE ATT&CK mapping, and anomaly detection
for network sockets, listening ports, and interface traffic.
"""

import ipaddress
import re
from typing import Dict, Any, List, Optional, Tuple

# Authorized / Standard Baseline Ports for Enterprise Linux Servers
STANDARD_AUTHORIZED_PORTS = {
    22: ("SSH", "OpenSSH Secure Shell"),
    80: ("HTTP", "Web Server"),
    443: ("HTTPS", "Secure Web Server"),
    53: ("DNS", "Domain Name System"),
    5432: ("PostgreSQL", "Enterprise Relational Database"),
    123: ("NTP", "Network Time Protocol"),
    25: ("SMTP", "Mail Transfer Agent"),
    9100: ("Prometheus", "Node Exporter Telemetry"),
    8000: ("FastAPI", "Cyber Digital Twin API")
}

# High-Risk / Known Trojan / Malicious Ports
HIGH_RISK_PORTS = {
    4444: ("METASPLOIT_C2", "Metasploit default listener or reverse meterpreter payload", "CRITICAL", "T1571"),
    1337: ("ELITE_BACKDOOR", "Classic elite hacker backdoor / rootkit shell", "CRITICAL", "T1059"),
    31337: ("BACK_ORIFICE", "Back Orifice remote administration trojan", "CRITICAL", "T1059"),
    6667: ("IRC_BOTNET_C2", "IRC botnet command & control channel", "HIGH", "T1071"),
    9001: ("TOR_OR_PORT", "Tor network relay or onion routing proxy", "HIGH", "T1090"),
    9050: ("TOR_SOCKS", "Tor SOCKS proxy tunnel", "HIGH", "T1090"),
    8888: ("ALT_HTTP_PROXY", "Unauthenticated alt-HTTP proxy or debug server", "MEDIUM", "T1071"),
    5555: ("ADB_OR_TROJAN", "Android debug bridge or reverse shell backdoor", "HIGH", "T1059"),
    1080: ("SOCKS_PROXY", "Generic unencrypted SOCKS proxy service", "MEDIUM", "T1090")
}

# Suspicious remote IP patterns (e.g. Tor exit nodes, known test malicious IPs)
KNOWN_MALICIOUS_IPS = {
    "198.51.100.1": "Feodo Tracker C2 Node",
    "185.220.101.5": "Known Tor Exit Relay",
    "203.0.113.50": "URLhaus CobaltStrike Stager",
    "45.33.32.156": "Active Internet Scanner C2"
}


class NetworkSecurityAnalyzer:
    """
    Evaluates listening ports, connection records, and interface metrics for anomalies.
    """

    @classmethod
    def analyze_listening_port(cls, port_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate an open listening socket against authorized and high-risk profiles.
        """
        port = int(port_info.get("port", 0))
        bind_addr = str(port_info.get("bind_address", "0.0.0.0"))
        proc_name = str(port_info.get("process_name", "unknown")).lower()

        # Check high-risk ports
        if port in HIGH_RISK_PORTS:
            tag, desc, severity, mitre = HIGH_RISK_PORTS[port]
            return {
                "is_authorized": False,
                "risk_level": severity,
                "risk_score": 90 if severity == "CRITICAL" else 75,
                "service_hint": tag,
                "alert": {
                    "alert_type": f"HIGH_RISK_PORT_LISTENING_{tag}",
                    "severity": severity,
                    "mitre_technique": mitre,
                    "destination_port": port,
                    "description": f"Dangerous listening port {port} ({desc}) detected on bind address {bind_addr} by '{proc_name}'.",
                    "recommendation": f"Identify process PID {port_info.get('pid')}, terminate unauthorized listeners and investigate host compromise."
                }
            }

        # Check standard authorized ports
        if port in STANDARD_AUTHORIZED_PORTS:
            tag, desc = STANDARD_AUTHORIZED_PORTS[port]
            return {
                "is_authorized": True,
                "risk_level": "LOW",
                "risk_score": 10,
                "service_hint": tag,
                "alert": None
            }

        # Non-standard listening port above 1024 or unexpected low port
        is_priv = port < 1024
        risk_score = 45 if is_priv else 30
        return {
            "is_authorized": False,
            "risk_level": "MEDIUM" if is_priv else "LOW",
            "risk_score": risk_score,
            "service_hint": f"CustomPort_{port}",
            "alert": {
                "alert_type": "UNEXPECTED_OPEN_PORT",
                "severity": "MEDIUM" if is_priv else "LOW",
                "mitre_technique": "T1043",
                "destination_port": port,
                "description": f"Unexpected open listening port {port} ({bind_addr}) bound to process '{proc_name}'.",
                "recommendation": "Confirm whether this port is required by business applications or block in firewall."
            } if is_priv else None
        }

    @classmethod
    def analyze_connection(cls, conn: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate an active network connection record for C2, exfiltration, or scanner behavior.
        """
        remote_ip = str(conn.get("remote_address", "")).strip()
        remote_port = int(conn.get("remote_port", 0))
        status = str(conn.get("status", "")).upper()
        proc_name = str(conn.get("process_name", "")).lower()

        alerts = []
        risk_score = 10
        is_suspicious = False
        threat_desc = "Normal Connection"

        # 1. Threat Intel IP Correlation
        if remote_ip in KNOWN_MALICIOUS_IPS:
            is_suspicious = True
            risk_score = max(risk_score, 95)
            intel_info = KNOWN_MALICIOUS_IPS[remote_ip]
            threat_desc = f"Connected to Threat IOC ({intel_info})"
            alerts.append({
                "alert_type": "C2_THREAT_INTEL_MATCH",
                "severity": "CRITICAL",
                "mitre_technique": "T1071",
                "destination_ip": remote_ip,
                "destination_port": remote_port,
                "description": f"Host established connection to verified threat IOC IP {remote_ip}:{remote_port} ({intel_info}).",
                "recommendation": f"Isolate host immediately and block {remote_ip} at edge perimeter."
            })

        # 2. High-Risk Remote Destination Port (e.g. 4444, 1337)
        if remote_port in HIGH_RISK_PORTS:
            is_suspicious = True
            tag, desc, severity, mitre = HIGH_RISK_PORTS[remote_port]
            risk_score = max(risk_score, 85)
            threat_desc = f"High Risk Destination Port ({tag})"
            alerts.append({
                "alert_type": f"SUSPICIOUS_DESTINATION_PORT_{tag}",
                "severity": severity,
                "mitre_technique": mitre,
                "destination_ip": remote_ip,
                "destination_port": remote_port,
                "description": f"Outbound traffic to high-risk destination port {remote_port} ({desc}) by '{proc_name}'.",
                "recommendation": "Inspect binary initiating connection. Verify if unauthorized reverse shell or beaconing."
            })

        # 3. Connection State Heuristics (e.g. SYN_SENT to non-standard remote ports indicates scan)
        if status == "SYN_SENT" and remote_port not in STANDARD_AUTHORIZED_PORTS and remote_port != 0:
            is_suspicious = True
            risk_score = max(risk_score, 60)
            threat_desc = "SYN_SENT Outbound Probing"
            alerts.append({
                "alert_type": "SYN_SCAN_ACTIVITY_OUTBOUND",
                "severity": "MEDIUM",
                "mitre_technique": "T1046",
                "destination_ip": remote_ip,
                "destination_port": remote_port,
                "description": f"Repeated SYN_SENT socket to {remote_ip}:{remote_port} suggests port scanning or unreachable C2.",
                "recommendation": "Review process network activity and monitor firewall egress logs."
            })

        return {
            "is_suspicious": is_suspicious,
            "risk_score": risk_score,
            "threat_description": threat_desc,
            "alerts": alerts
        }

    @classmethod
    def evaluate_interface_health(cls, iface: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Check for severe packet loss, frame errors, or interface down alerts.
        """
        name = iface.get("interface_name", "eth0")
        is_up = iface.get("is_up", True)
        dropin = iface.get("dropin", 0)
        dropout = iface.get("dropout", 0)
        errin = iface.get("errin", 0)

        if not is_up and name != "lo":
            return {
                "alert_type": "INTERFACE_DOWN",
                "severity": "HIGH",
                "mitre_technique": "T1499",
                "description": f"Network interface '{name}' is in DOWN state.",
                "recommendation": f"Check physical/virtual cable link and run 'ip link set {name} up'."
            }

        if (dropin > 1000 or dropout > 1000 or errin > 500) and name != "lo":
            return {
                "alert_type": "EXCESSIVE_PACKET_DROPS",
                "severity": "MEDIUM",
                "mitre_technique": "T1499",
                "description": f"Interface '{name}' experiencing high error/drop rates (dropin={dropin}, errin={errin}).",
                "recommendation": "Check MTU settings, duplex mismatch, or network link congestion."
            }

        return None
