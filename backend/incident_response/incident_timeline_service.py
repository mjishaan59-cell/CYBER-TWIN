"""
Incident Timeline & Evidence Locker Service
Phase 29 - Advanced Incident Response & Playbooks Subsystem
"""

import uuid
import json
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy import text
from backend.database import engine
from backend.incident_response.playbook_engine import PlaybookEngine, PLAYBOOK_CATALOG


class IncidentTimelineService:
    """
    Manages playbook execution audits, incident evidence artifacts, and chronological timelines.
    """

    def __init__(self):
        self._playbook_history: Dict[str, Dict[str, Any]] = {}
        self._evidence_artifacts: List[Dict[str, Any]] = []
        self._timeline_events: List[Dict[str, Any]] = []
        self._ensure_tables()
        self._seed_data()

    def _ensure_tables(self):
        sql = """
        CREATE TABLE IF NOT EXISTS playbook_execution_audits (
            id SERIAL PRIMARY KEY,
            execution_id VARCHAR(64) UNIQUE NOT NULL,
            playbook_id VARCHAR(60) NOT NULL,
            playbook_name VARCHAR(120) NOT NULL,
            incident_id VARCHAR(64) DEFAULT '',
            target_hostname VARCHAR(100) NOT NULL,
            executed_by VARCHAR(50) DEFAULT 'admin',
            mode VARCHAR(20) DEFAULT 'DRY_RUN',
            safeguards_passed BOOLEAN DEFAULT TRUE,
            safeguard_notes VARCHAR(255) DEFAULT 'All safeguard checks passed',
            status VARCHAR(30) DEFAULT 'SUCCESS',
            parameters JSON DEFAULT '{}'::json,
            execution_log JSON DEFAULT '[]'::json,
            result_summary TEXT DEFAULT '',
            executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS incident_evidence_artifacts (
            id SERIAL PRIMARY KEY,
            artifact_id VARCHAR(64) UNIQUE NOT NULL,
            incident_id VARCHAR(64) NOT NULL,
            artifact_type VARCHAR(50) NOT NULL,
            file_name VARCHAR(120) NOT NULL,
            file_hash_sha256 VARCHAR(64) DEFAULT '',
            description VARCHAR(255) DEFAULT '',
            collected_by VARCHAR(50) DEFAULT 'analyst',
            metadata_json JSON DEFAULT '{}'::json,
            collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS incident_timeline_events (
            id SERIAL PRIMARY KEY,
            incident_id VARCHAR(64) NOT NULL,
            event_type VARCHAR(50) NOT NULL,
            title VARCHAR(150) NOT NULL,
            source VARCHAR(60) DEFAULT 'SYSTEM',
            severity VARCHAR(20) DEFAULT 'INFO',
            details TEXT DEFAULT '',
            event_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        if str(engine.url).startswith("sqlite"):
            sql = sql.replace("SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT").replace("::json", "")
        try:
            with engine.begin() as conn:
                for stmt in sql.split(";"):
                    if stmt.strip():
                        conn.execute(text(stmt.strip()))
        except Exception:
            pass

    def _seed_data(self):
        inc_id = "inc-2026-001"

        # Seed timeline events
        now = datetime.now(timezone.utc).isoformat()
        self._timeline_events.extend([
            {
                "incident_id": inc_id,
                "event_type": "ALERT",
                "title": "SSH Brute Force Burst Detected",
                "source": "RiskEngine",
                "severity": "HIGH",
                "details": "25 failed login attempts observed from 198.51.100.1 targeting root.",
                "event_timestamp": now
            },
            {
                "incident_id": inc_id,
                "event_type": "TELEMETRY",
                "title": "Threat Feed Correlation Match",
                "source": "ThreatIntelService",
                "severity": "CRITICAL",
                "details": "Source IP 198.51.100.1 is indexed in Abuse.ch Feodo Tracker C2 corpus.",
                "event_timestamp": now
            }
        ])

        # Seed evidence
        self._evidence_artifacts.append({
            "artifact_id": "art-001",
            "incident_id": inc_id,
            "artifact_type": "LOG_SNIPPET",
            "file_name": "secure_ssh_auth_fail.log",
            "file_hash_sha256": "4a7d1ed414474e4033ac29ccb8653d9b110a123a105f23d42b7814b99ccb5c6e",
            "description": "Auth log snapshot containing brute-force attack attempts",
            "collected_by": "secops-bot",
            "metadata_json": {"source_ip": "198.51.100.1", "attempts": 25},
            "collected_at": now
        })

        # Seed playbook run
        run = PlaybookEngine.execute_playbook(
            playbook_id="BLOCK_MALICIOUS_IP",
            target_hostname="prac-server",
            params={"ip_address": "198.51.100.1"},
            incident_id=inc_id,
            executed_by="admin",
            mode="DRY_RUN"
        )
        self._playbook_history[run["execution_id"]] = run

    def list_playbooks(self) -> List[Dict[str, Any]]:
        """List all available playbooks."""
        return PlaybookEngine.list_playbooks()

    def execute_playbook(
        self,
        playbook_id: str,
        target_hostname: str = "prac-server",
        params: Optional[Dict[str, Any]] = None,
        incident_id: str = "",
        executed_by: str = "admin",
        mode: str = "DRY_RUN"
    ) -> Dict[str, Any]:
        """Execute a playbook with auditing and timeline recording."""
        result = PlaybookEngine.execute_playbook(
            playbook_id=playbook_id,
            target_hostname=target_hostname,
            params=params,
            incident_id=incident_id,
            executed_by=executed_by,
            mode=mode
        )
        self._playbook_history[result["execution_id"]] = result

        # Record timeline event if incident_id provided
        if incident_id:
            self.add_timeline_event(
                incident_id=incident_id,
                event_type="PLAYBOOK",
                title=f"Playbook Executed: {result['playbook_name']}",
                source=f"User:{executed_by}",
                severity="HIGH" if result["status"] == "SUCCESS" else "WARNING",
                details=result["result_summary"]
            )

        # Non-blocking DB write
        try:
            with engine.begin() as conn:
                conn.execute(text("""
                    INSERT INTO playbook_execution_audits
                    (execution_id, playbook_id, playbook_name, incident_id, target_hostname, executed_by, mode, safeguards_passed, safeguard_notes, status, parameters, execution_log, result_summary)
                    VALUES (:eid, :pid, :pname, :inc, :host, :by, :mode, :safe, :notes, :status, :params, :log, :sum)
                """), {
                    "eid": result["execution_id"],
                    "pid": result["playbook_id"],
                    "pname": result["playbook_name"],
                    "inc": result["incident_id"],
                    "host": result["target_hostname"],
                    "by": result["executed_by"],
                    "mode": result["mode"],
                    "safe": result["safeguards_passed"],
                    "notes": result["safeguard_notes"],
                    "status": result["status"],
                    "params": json.dumps(result["parameters"]),
                    "log": json.dumps(result["execution_log"]),
                    "sum": result["result_summary"]
                })
        except Exception:
            pass

        return result

    def list_playbook_history(
        self,
        incident_id: Optional[str] = None,
        target_hostname: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """List past playbook execution audits."""
        runs = list(self._playbook_history.values())
        if incident_id:
            runs = [r for r in runs if r.get("incident_id") == incident_id]
        if target_hostname:
            runs = [r for r in runs if r.get("target_hostname") == target_hostname]
        runs = sorted(runs, key=lambda x: str(x.get("executed_at")), reverse=True)
        return runs[:limit]

    def add_timeline_event(
        self,
        incident_id: str,
        event_type: str,
        title: str,
        source: str = "SYSTEM",
        severity: str = "INFO",
        details: str = ""
    ) -> Dict[str, Any]:
        """Record an entry on the incident forensics timeline."""
        event = {
            "incident_id": incident_id,
            "event_type": event_type,
            "title": title,
            "source": source,
            "severity": severity,
            "details": details,
            "event_timestamp": datetime.now(timezone.utc).isoformat()
        }
        self._timeline_events.append(event)

        try:
            with engine.begin() as conn:
                conn.execute(text("""
                    INSERT INTO incident_timeline_events
                    (incident_id, event_type, title, source, severity, details)
                    VALUES (:inc, :type, :title, :src, :sev, :det)
                """), {
                    "inc": incident_id,
                    "type": event_type,
                    "title": title,
                    "src": source,
                    "sev": severity,
                    "det": details
                })
        except Exception:
            pass

        return event

    def get_timeline(self, incident_id: str) -> List[Dict[str, Any]]:
        """Retrieve full chronological timeline for an incident."""
        events = [e for e in self._timeline_events if e.get("incident_id") == incident_id]
        return sorted(events, key=lambda x: str(x.get("event_timestamp")))

    def attach_evidence(
        self,
        incident_id: str,
        artifact_type: str,
        file_name: str,
        file_hash_sha256: str = "",
        description: str = "",
        collected_by: str = "analyst",
        metadata_json: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Attach a forensic evidence artifact to an incident investigation."""
        art_id = f"art-{uuid.uuid4().hex[:10]}"
        evidence = {
            "artifact_id": art_id,
            "incident_id": incident_id,
            "artifact_type": artifact_type,
            "file_name": file_name,
            "file_hash_sha256": file_hash_sha256,
            "description": description,
            "collected_by": collected_by,
            "metadata_json": metadata_json or {},
            "collected_at": datetime.now(timezone.utc).isoformat()
        }
        self._evidence_artifacts.append(evidence)

        # Add timeline entry
        self.add_timeline_event(
            incident_id=incident_id,
            event_type="EVIDENCE",
            title=f"Forensic Artifact Attached: {file_name}",
            source=f"Analyst:{collected_by}",
            severity="INFO",
            details=f"Type: {artifact_type}, SHA-256: {file_hash_sha256[:16]}..." if file_hash_sha256 else f"Type: {artifact_type}"
        )

        try:
            with engine.begin() as conn:
                conn.execute(text("""
                    INSERT INTO incident_evidence_artifacts
                    (artifact_id, incident_id, artifact_type, file_name, file_hash_sha256, description, collected_by, metadata_json)
                    VALUES (:aid, :inc, :type, :name, :hash, :desc, :by, :meta)
                """), {
                    "aid": art_id,
                    "inc": incident_id,
                    "type": artifact_type,
                    "name": file_name,
                    "hash": file_hash_sha256,
                    "desc": description,
                    "by": collected_by,
                    "meta": json.dumps(metadata_json or {})
                })
        except Exception:
            pass

        return evidence

    def list_evidence(self, incident_id: str) -> List[Dict[str, Any]]:
        """Retrieve forensic evidence artifacts for an incident."""
        return [e for e in self._evidence_artifacts if e.get("incident_id") == incident_id]

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate stats for incident response playbooks and evidence."""
        runs = list(self._playbook_history.values())
        return {
            "total_playbook_executions": len(runs),
            "successful_executions": sum(1 for r in runs if r.get("status") == "SUCCESS"),
            "blocked_by_safeguards": sum(1 for r in runs if r.get("status") == "BLOCKED_BY_SAFEGUARD"),
            "evidence_artifacts_secured": len(self._evidence_artifacts),
            "timeline_events_recorded": len(self._timeline_events),
            "available_playbooks_count": len(PLAYBOOK_CATALOG)
        }


# Singleton service
incident_timeline_service = IncidentTimelineService()
