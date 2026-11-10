"""
File Integrity Monitoring Service
Phase 24 - File Integrity Monitoring Subsystem
Manages baselines, verification scans, tamper seal validation, and event storage.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy import text
from backend.database import engine, is_database_online
from backend.fim.fim_config import CRITICAL_LINUX_PATHS, get_default_monitored_paths
from backend.fim.fim_engine import (
    calculate_sha256,
    generate_baseline_seal,
    verify_baseline_seal,
    FimEngine
)


# Canonical mock/baseline templates for critical files
DEFAULT_SEED_BASELINES: Dict[str, Dict[str, Any]] = {
    "/etc/shadow": {
        "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "file_size_bytes": 1420,
        "permissions": "0000",
        "owner_name": "root",
        "group_name": "root"
    },
    "/etc/sudoers": {
        "sha256_hash": "a4d8d17b38d38c642643a6c1178229b3ae3d242948a3036c64dbb02b54d39c09",
        "file_size_bytes": 3180,
        "permissions": "0440",
        "owner_name": "root",
        "group_name": "root"
    },
    "/etc/passwd": {
        "sha256_hash": "b268579ad4b7de9c450a8d8e578c732c51084ef7578351508db8c06788db3d11",
        "file_size_bytes": 2650,
        "permissions": "0644",
        "owner_name": "root",
        "group_name": "root"
    },
    "/etc/ssh/sshd_config": {
        "sha256_hash": "5d41402abc4b2a76b9719d911017c592d3f66c1b3f94c4897f26d60a5d4d3d22",
        "file_size_bytes": 3940,
        "permissions": "0600",
        "owner_name": "root",
        "group_name": "root"
    },
    "/etc/hosts": {
        "sha256_hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "file_size_bytes": 220,
        "permissions": "0644",
        "owner_name": "root",
        "group_name": "root"
    },
    "/bin/sudo": {
        "sha256_hash": "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",
        "file_size_bytes": 248900,
        "permissions": "4755",
        "owner_name": "root",
        "group_name": "root"
    }
}


class FimService:
    """
    Orchestrates baseline persistence, scan execution, and audit logging.
    """

    def __init__(self):
        self._memory_baselines: Dict[str, List[Dict[str, Any]]] = {}
        self._memory_events: List[Dict[str, Any]] = []
        if is_database_online():
            self._ensure_tables()
        self._init_seed_baseline("prac-server")

    def _ensure_tables(self):
        """Ensure FIM tables exist in active database."""
        sql = """
        CREATE TABLE IF NOT EXISTS fim_baselines (
            id SERIAL PRIMARY KEY,
            hostname VARCHAR(100) NOT NULL,
            file_path VARCHAR(500) NOT NULL,
            sha256_hash VARCHAR(64) NOT NULL,
            file_size_bytes BIGINT DEFAULT 0,
            permissions VARCHAR(10) DEFAULT '0644',
            owner_uid INTEGER DEFAULT 0,
            group_gid INTEGER DEFAULT 0,
            owner_name VARCHAR(50) DEFAULT 'root',
            group_name VARCHAR(50) DEFAULT 'root',
            is_directory BOOLEAN DEFAULT FALSE,
            baseline_version INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS fim_events (
            id SERIAL PRIMARY KEY,
            hostname VARCHAR(100) NOT NULL,
            file_path VARCHAR(500) NOT NULL,
            change_type VARCHAR(30) NOT NULL,
            severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
            old_sha256 VARCHAR(64),
            new_sha256 VARCHAR(64),
            old_permissions VARCHAR(10),
            new_permissions VARCHAR(10),
            old_owner VARCHAR(50),
            new_owner VARCHAR(50),
            details VARCHAR(500),
            acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS fim_config (
            id SERIAL PRIMARY KEY,
            hostname VARCHAR(100) UNIQUE NOT NULL,
            monitored_paths VARCHAR(2000) NOT NULL,
            scan_interval_seconds INTEGER DEFAULT 300,
            baseline_hash_seal VARCHAR(64),
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            last_scan_at TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        if str(engine.url).startswith("sqlite"):
            sql = sql.replace("SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")
        try:
            with engine.begin() as conn:
                for stmt in sql.split(";"):
                    if stmt.strip():
                        conn.execute(text(stmt.strip()))
        except Exception:
            pass

    def _init_seed_baseline(self, hostname: str):
        """Populate seed baseline for test/default server."""
        records = []
        for path, meta in DEFAULT_SEED_BASELINES.items():
            records.append({
                "hostname": hostname,
                "file_path": path,
                "sha256_hash": meta["sha256_hash"],
                "file_size_bytes": meta["file_size_bytes"],
                "permissions": meta["permissions"],
                "owner_uid": 0,
                "group_gid": 0,
                "owner_name": meta["owner_name"],
                "group_name": meta["group_name"],
                "is_directory": False,
                "baseline_version": 1
            })
        self._memory_baselines[hostname] = records

    def create_or_update_baseline(self, hostname: str, file_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Record a new cryptographic baseline snapshot and compute its tamper-protection seal.
        """
        seal = generate_baseline_seal(file_records)
        self._memory_baselines[hostname] = file_records

        try:
            with engine.begin() as conn:
                # Clear old baseline for this host
                conn.execute(text("DELETE FROM fim_baselines WHERE hostname = :host"), {"host": hostname})
                for rec in file_records:
                    conn.execute(text("""
                        INSERT INTO fim_baselines
                        (hostname, file_path, sha256_hash, file_size_bytes, permissions,
                         owner_uid, group_gid, owner_name, group_name, is_directory, baseline_version)
                        VALUES
                        (:host, :path, :hash, :size, :perm, :uid, :gid, :owner, :grp, :isdir, 1)
                    """), {
                        "host": hostname,
                        "path": rec["file_path"],
                        "hash": rec["sha256_hash"],
                        "size": rec.get("file_size_bytes", 0),
                        "perm": rec.get("permissions", "0644"),
                        "uid": rec.get("owner_uid", 0),
                        "gid": rec.get("group_gid", 0),
                        "owner": rec.get("owner_name", "root"),
                        "grp": rec.get("group_name", "root"),
                        "isdir": rec.get("is_directory", False)
                    })
                # Update config with seal
                conn.execute(text("""
                    INSERT INTO fim_config (hostname, monitored_paths, baseline_hash_seal, last_scan_at)
                    VALUES (:host, :paths, :seal, CURRENT_TIMESTAMP)
                    ON CONFLICT(hostname) DO UPDATE SET
                    baseline_hash_seal = EXCLUDED.baseline_hash_seal,
                    updated_at = CURRENT_TIMESTAMP
                """), {
                    "host": hostname,
                    "paths": ",".join(r["file_path"] for r in file_records),
                    "seal": seal
                })
        except Exception:
            pass

        return {
            "hostname": hostname,
            "baseline_count": len(file_records),
            "tamper_seal": seal,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

    def get_baseline(self, hostname: str) -> List[Dict[str, Any]]:
        """Retrieve baseline records for a host."""
        try:
            with engine.connect() as conn:
                rows = conn.execute(
                    text("SELECT * FROM fim_baselines WHERE hostname = :host ORDER BY file_path ASC"),
                    {"host": hostname}
                ).mappings().all()
                if rows:
                    return [dict(r) for r in rows]
        except Exception:
            pass
        if hostname not in self._memory_baselines:
            self._init_seed_baseline(hostname)
        return self._memory_baselines[hostname]

    def scan_host_integrity(
        self,
        hostname: str,
        active_snapshot: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Execute an integrity scan by comparing active file snapshot against established baseline.
        """
        baseline = self.get_baseline(hostname)

        # If no custom snapshot provided, run comparison against current known state
        if active_snapshot is None:
            active_snapshot = list(baseline)

        events = FimEngine.compare_snapshot(baseline, active_snapshot, hostname)

        # Store events
        for ev in events:
            ev["detected_at"] = datetime.now(timezone.utc).isoformat()
            self._memory_events.append(ev)
            try:
                with engine.begin() as conn:
                    conn.execute(text("""
                        INSERT INTO fim_events
                        (hostname, file_path, change_type, severity, old_sha256, new_sha256,
                         old_permissions, new_permissions, old_owner, new_owner, details, acknowledged)
                        VALUES
                        (:host, :path, :ctype, :sev, :old_hash, :new_hash,
                         :old_perm, :new_perm, :old_owner, :new_owner, :details, FALSE)
                    """), {
                        "host": hostname,
                        "path": ev["file_path"],
                        "ctype": ev["change_type"],
                        "sev": ev["severity"],
                        "old_hash": ev.get("old_sha256"),
                        "new_hash": ev.get("new_sha256"),
                        "old_perm": ev.get("old_permissions"),
                        "new_perm": ev.get("new_permissions"),
                        "old_owner": ev.get("old_owner"),
                        "new_owner": ev.get("new_owner"),
                        "details": ev.get("details")
                    })
            except Exception:
                pass

        return {
            "hostname": hostname,
            "scanned_files_count": len(active_snapshot),
            "violations_detected": len(events),
            "events": events,
            "scanned_at": datetime.now(timezone.utc).isoformat()
        }

    def list_events(
        self,
        hostname: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """List detected integrity violation events."""
        try:
            where = ["1=1"]
            params: Dict[str, Any] = {"limit": limit}
            if hostname:
                where.append("hostname = :host")
                params["host"] = hostname
            if severity:
                where.append("severity = :sev")
                params["sev"] = severity.upper()

            sql = f"""
            SELECT * FROM fim_events
            WHERE {' AND '.join(where)}
            ORDER BY detected_at DESC
            LIMIT :limit
            """
            with engine.connect() as conn:
                rows = conn.execute(text(sql), params).mappings().all()
                if rows:
                    return [dict(r) for r in rows]
        except Exception:
            pass

        # Memory events fallback
        res = list(self._memory_events)
        if hostname:
            res = [r for r in res if r.get("hostname") == hostname]
        if severity:
            res = [r for r in res if r.get("severity") == severity.upper()]
        return res[-limit:]

    def get_stats(self, hostname: str = "prac-server") -> Dict[str, Any]:
        """Aggregate FIM summary statistics."""
        baseline = self.get_baseline(hostname)
        events = self.list_events(hostname=hostname, limit=100)

        critical_count = sum(1 for e in events if e.get("severity") == "CRITICAL")
        high_count = sum(1 for e in events if e.get("severity") == "HIGH")

        return {
            "hostname": hostname,
            "monitored_files_count": len(baseline),
            "total_integrity_events": len(events),
            "critical_events_count": critical_count,
            "high_events_count": high_count,
            "baseline_healthy": critical_count == 0,
            "last_scan_time": datetime.now(timezone.utc).isoformat()
        }


# Singleton service instance
fim_service = FimService()
