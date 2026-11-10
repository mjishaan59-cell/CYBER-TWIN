"""
Threat Correlation Engine
Phase 22 - AI Threat Intelligence Subsystem
Correlates incoming Linux telemetry, SSH authentication attempts, and network events
with the active Threat Intelligence repository and MITRE ATT&CK techniques.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from backend.threat_intel.threat_classifier import ThreatClassifier
from backend.threat_intel.mitre_mapper import map_threat_to_mitre


class ThreatCorrelator:
    """
    Correlates runtime Linux security events with Threat Intelligence Indicators.
    """

    def __init__(self, ioc_lookup_fn):
        self.ioc_lookup_fn = ioc_lookup_fn

    def correlate_ip(self, ip_address: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Check if an IP address matches known threat intelligence and return correlated risk data.
        """
        clean_ip = ip_address.strip()
        ioc_match = self.ioc_lookup_fn(clean_ip)
        ctx = context or {}

        attempts = ctx.get("attempts", 1)
        root_targeted = ctx.get("username") == "root"
        invalid_user = ctx.get("invalid_user", False)

        if ioc_match:
            threat_type = ioc_match.get("threat_type", "SSH_BRUTE_FORCE")
            feed_conf = ioc_match.get("confidence_score", 75)
            score_data = ThreatClassifier.calculate_threat_score(
                threat_type=threat_type,
                feed_confidence=feed_conf,
                observed_attempts=attempts,
                invalid_user_targeted=invalid_user,
                root_targeted=root_targeted,
                recent_hours=1.0
            )

            mitre_data = map_threat_to_mitre(threat_type, ioc_match.get("description"))

            return {
                "matched": True,
                "indicator_value": clean_ip,
                "indicator_type": "IP",
                "source_feed": ioc_match.get("source_feed", "Threat Intelligence"),
                "threat_type": threat_type,
                "threat_score": score_data["threat_score"],
                "severity": score_data["severity"],
                "confidence_score": score_data["confidence_score"],
                "mitre_attack": mitre_data,
                "description": ioc_match.get("description", "Known malicious indicator"),
                "correlation_summary": (
                    f"CRITICAL MATCH: IP {clean_ip} matches active threat feed '{ioc_match.get('source_feed')}'. "
                    f"Classified as {threat_type} with threat score {score_data['threat_score']}/100 ({score_data['severity']}). "
                    f"MITRE Technique: {mitre_data['attack_id']} ({mitre_data['technique_name']})."
                ),
                "recommended_action": (
                    "BLOCK_SOURCE_IP" if score_data["threat_score"] >= 75 else "ENHANCED_MONITORING"
                )
            }

        # No direct IOC match -> evaluate purely on behavioral telemetry
        base_threat = "SSH_BRUTE_FORCE" if attempts >= 3 else "UNKNOWN"
        score_data = ThreatClassifier.calculate_threat_score(
            threat_type=base_threat,
            feed_confidence=50,
            observed_attempts=attempts,
            invalid_user_targeted=invalid_user,
            root_targeted=root_targeted
        )
        mitre_data = map_threat_to_mitre(base_threat)

        return {
            "matched": False,
            "indicator_value": clean_ip,
            "indicator_type": "IP",
            "source_feed": "Local Behavioral Analysis",
            "threat_type": base_threat,
            "threat_score": score_data["threat_score"],
            "severity": score_data["severity"],
            "confidence_score": 45,
            "mitre_attack": mitre_data,
            "description": f"No external IOC record found for {clean_ip}; behavioral score calculated.",
            "correlation_summary": (
                f"Standard behavioral telemetry for {clean_ip}: {attempts} attempts, score {score_data['threat_score']}."
            ),
            "recommended_action": "ALLOW_WITH_MONITORING" if score_data["threat_score"] < 70 else "RATE_LIMIT"
        }

    def correlate_ssh_events(self, ssh_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Batch correlate a list of SSH events from Linux logs.
        """
        correlated = []
        for event in ssh_events:
            ip = event.get("source_ip")
            if not ip:
                continue
            res = self.correlate_ip(
                ip,
                context={
                    "attempts": event.get("attempt_count", 1),
                    "username": event.get("username"),
                    "invalid_user": "invalid" in str(event.get("event_type", "")).lower()
                }
            )
            correlated.append({
                "event_id": event.get("id"),
                "event_time": event.get("event_time"),
                "username": event.get("username"),
                "source_ip": ip,
                "correlation": res
            })
        return correlated
