"""
Threat Classifier & Dynamic Severity Scoring Engine
Phase 22 - AI Threat Intelligence Subsystem
"""

from typing import Dict, Any, Optional

BASE_THREAT_WEIGHTS = {
    "RANSOMWARE": 95,
    "MALWARE_C2": 85,
    "EXPLOIT_PROBE": 80,
    "SSH_BRUTE_FORCE": 75,
    "SHELL_INJECTION": 85,
    "PHISHING": 70,
    "SUSPICIOUS_DOMAIN": 65,
    "TOR_EXIT_NODE": 50,
    "PORT_SCANNER": 45,
    "SCANNER": 40,
    "UNKNOWN": 30
}


def score_to_severity(score: int) -> str:
    """Map numeric 0-100 score to standardized severity band."""
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


class ThreatClassifier:
    """
    Evaluates indicators and context to compute classification, confidence, and severity.
    """

    @staticmethod
    def calculate_threat_score(
        threat_type: str,
        feed_confidence: int = 70,
        observed_attempts: int = 0,
        invalid_user_targeted: bool = False,
        root_targeted: bool = False,
        recent_hours: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Dynamically calculate a 0-100 threat score and explain contributing factors.
        """
        threat_type_norm = threat_type.strip().upper()
        base_score = BASE_THREAT_WEIGHTS.get(threat_type_norm, BASE_THREAT_WEIGHTS["UNKNOWN"])
        factors = [f"Base score for {threat_type_norm} ({base_score} pts)"]

        current_score = float(base_score)

        # Feed confidence adjustment (weights higher-confidence feeds)
        if feed_confidence >= 90:
            current_score += 8
            factors.append("High-confidence intelligence feed (+8 pts)")
        elif feed_confidence < 50:
            current_score -= 10
            factors.append("Low-confidence feed penalty (-10 pts)")

        # Behavioral indicators
        if observed_attempts > 20:
            current_score += 15
            factors.append(f"Very high attack intensity ({observed_attempts} attempts, +15 pts)")
        elif observed_attempts > 5:
            current_score += 8
            factors.append(f"Repeated attack attempts ({observed_attempts} attempts, +8 pts)")

        if root_targeted:
            current_score += 12
            factors.append("Privileged account 'root' targeted (+12 pts)")

        if invalid_user_targeted:
            current_score += 8
            factors.append("Invalid/non-existent user enumeration (+8 pts)")

        if recent_hours is not None and recent_hours <= 24:
            current_score += 7
            factors.append(f"Active within last {recent_hours:.1f} hours (+7 pts)")

        # Clamp between 0 and 100
        final_score = int(max(5, min(100, round(current_score))))
        severity = score_to_severity(final_score)

        return {
            "threat_score": final_score,
            "severity": severity,
            "threat_type": threat_type_norm,
            "confidence_score": feed_confidence,
            "factors": factors,
            "explanation": " | ".join(factors)
        }
