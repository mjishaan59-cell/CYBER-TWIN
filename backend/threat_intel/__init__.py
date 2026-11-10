"""
Threat Intelligence Subsystem Package
Phase 22 - AI Threat Intelligence Subsystem
"""

from backend.threat_intel.mitre_mapper import map_threat_to_mitre, get_all_mitre_techniques
from backend.threat_intel.feed_collector import ThreatFeedCollector, detect_indicator_type
from backend.threat_intel.threat_classifier import ThreatClassifier
from backend.threat_intel.threat_correlator import ThreatCorrelator
from backend.threat_intel.threat_service import ThreatIntelligenceService, threat_intel_service

__all__ = [
    "map_threat_to_mitre",
    "get_all_mitre_techniques",
    "ThreatFeedCollector",
    "detect_indicator_type",
    "ThreatClassifier",
    "ThreatCorrelator",
    "ThreatIntelligenceService",
    "threat_intel_service"
]
