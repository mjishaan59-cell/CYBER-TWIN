# Phase 22: AI-Powered Threat Intelligence Subsystem

## Overview
Phase 22 implements a production-grade, AI-powered Threat Intelligence Subsystem for the AI Cyber Digital Twin platform. It continuously ingests, scores, classifies, and correlates Indicators of Compromise (IOCs)—including malicious IP addresses, suspicious domain names, and malicious file hashes—with real-time Linux telemetry and MITRE ATT&CK tactics.

---

## Key Capabilities

1. **Reputable Public Feeds & Integration**:
   - **Abuse.ch Feodo Tracker**: Ingests active botnet and Command & Control (C2) IP addresses.
   - **Abuse.ch URLhaus / ThreatFox**: Tracks malware distribution domains and payload hashes.
   - **Tor Project Exit Directory**: Identifies traffic originating through Tor anonymization exit nodes.
   - **AlienVault OTX & AbuseIPDB**: Optional external API key support via environment variables (`ALIENVAULT_OTX_API_KEY`, `ABUSEIPDB_API_KEY`).
   - **Offline Seed Corpus**: High-fidelity verified IOC baseline ensuring operational readiness in isolated and air-gapped environments.

2. **Automated Indicator Validation & Type Detection**:
   - Strict regex and IPv4/IPv6 address parsing.
   - Standard domain name syntax checking.
   - SHA-256 cryptographic hash format validation (64-character hexadecimal).

3. **Dynamic Threat Classification & Severity Scoring**:
   - Base weights calculated per threat category (`MALWARE_C2`: 85, `SSH_BRUTE_FORCE`: 75, `EXPLOIT_PROBE`: 80, `TOR_EXIT_NODE`: 50, `SCANNER`: 40).
   - Contextual modifiers:
     - Privileged target bonus (`root` account targeted: +12 pts)
     - High attack intensity (>20 attempts: +15 pts)
     - User enumeration (+8 pts)
     - Recency boost (<24h active: +7 pts)
   - Severity Bands: `LOW` (0-39), `MEDIUM` (40-69), `HIGH` (70-89), `CRITICAL` (90-100).

4. **MITRE ATT&CK Matrix Mapping**:
   - Automated mapping to ATT&CK tactics and techniques:
     - **T1110 / T1110.001 / T1110.003**: Brute Force / Password Guessing / Password Spraying
     - **T1071 / T1071.001 / T1071.004**: C2 Communication / Web Protocols / DNS Tunneling
     - **T1090.003**: Multi-hop Proxy (Tor)
     - **T1046**: Network Service Discovery
     - **T1190**: Exploit Public-Facing Application
     - **T1059.004**: Unix Shell Command & Scripting Interpreter

5. **Threat Event Correlation**:
   - Correlates incoming Linux authentication logs (`ssh_events`) and network connection telemetry against the active threat database.
   - Dispatches actionable recommendations (`BLOCK_SOURCE_IP`, `RATE_LIMIT`, `ENHANCED_LOGGING`).

6. **Web Dashboard Integration**:
   - Live KPI cards (Active IOCs, Critical Threats, Total Lookups, MITRE Coverage).
   - Real-time interactive Indicator Lookup Sandbox.
   - Dynamic IOC indicators table with severity tags and mitigation actions.
   - Visual MITRE ATT&CK coverage matrix.

---

## API Reference

### 1. List Indicators
```bash
curl -H "Authorization: Bearer <TOKEN>" \
  "http://localhost:8000/threat-intel/indicators?limit=50&severity=HIGH"
```

### 2. Lookup Indicator
```bash
curl -H "Authorization: Bearer <TOKEN>" \
  "http://localhost:8000/threat-intel/lookup/194.26.29.118"
```
**Example Response:**
```json
{
  "indicator_value": "194.26.29.118",
  "indicator_type": "IP",
  "matched": true,
  "threat_score": 93,
  "severity": "CRITICAL",
  "confidence_score": 95,
  "threat_type": "MALWARE_C2",
  "source_feed": "Abuse.ch Feodo Tracker",
  "mitre_attack": {
    "attack_id": "T1071.001",
    "technique_name": "Web Protocols (HTTP/HTTPS C2)",
    "tactic": "Command and Control",
    "mitigation": "SSL inspection, threat intel domain blocklists, egress proxy filtering."
  },
  "recommendation": "BLOCK_INDICATOR"
}
```

### 3. Add Custom Indicator (Admin / Analyst)
```bash
curl -X POST -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "indicator_value": "45.154.255.89",
    "indicator_type": "IP",
    "threat_type": "SSH_BRUTE_FORCE",
    "severity": "HIGH",
    "confidence_score": 90,
    "description": "Automated scanner targeting SSH daemon"
  }' \
  "http://localhost:8000/threat-intel/indicators"
```

### 4. Correlation
```bash
curl -X POST -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "indicators": ["194.26.29.118", "127.0.0.1"],
    "context": {"attempts": 10, "username": "root"}
  }' \
  "http://localhost:8000/threat-intel/correlate"
```

### 5. Summary Statistics
```bash
curl -H "Authorization: Bearer <TOKEN>" \
  "http://localhost:8000/threat-intel/stats"
```

---

## Verification & Testing
The subsystem is covered by automated pytest tests in `tests/test_phase22_threat_intel.py`.
- **Validation**: IP, domain, hash format deduction.
- **MITRE Mapping**: ATT&CK technique IDs and tactic mappings.
- **Severity Classifier**: Scoring formulas, weights, and confidence adjustments.
- **Correlation Engine**: Correlating threat feeds with attack behavior.
- **REST Endpoints**: HTTP status codes, schemas, and RBAC enforcement.
