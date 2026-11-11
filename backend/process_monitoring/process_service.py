"""
Process & Systemd Service Monitoring Service
Phase 25 - Process and Service Monitoring Subsystem
"""

import psutil
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy import text
from backend.database import engine, is_database_online
from backend.process_monitoring.process_analyzer import ProcessAnalyzer

DEFAULT_SYSTEMD_SERVICES = [
    {"service_name": "sshd.service", "load_state": "loaded", "active_state": "active", "sub_state": "running", "description": "OpenSSH server daemon", "is_failed": False},
    {"service_name": "systemd-journald.service", "load_state": "loaded", "active_state": "active", "sub_state": "running", "description": "Journal Service", "is_failed": False},
    {"service_name": "crond.service", "load_state": "loaded", "active_state": "active", "sub_state": "running", "description": "Command Scheduler", "is_failed": False},
    {"service_name": "auditd.service", "load_state": "loaded", "active_state": "active", "sub_state": "running", "description": "Security Auditing Service", "is_failed": False},
    {"service_name": "firewalld.service", "load_state": "loaded", "active_state": "active", "sub_state": "running", "description": "FirewallD Daemon", "is_failed": False},
    {"service_name": "dbus.service", "load_state": "loaded", "active_state": "active", "sub_state": "running", "description": "D-Bus System Message Bus", "is_failed": False},
    {"service_name": "network.service", "load_state": "loaded", "active_state": "active", "sub_state": "running", "description": "Network Management", "is_failed": False}
]

DEFAULT_LINUX_PROCS = [
    {"pid": 1, "ppid": 0, "username": "root", "process_name": "systemd", "cmdline": "/usr/lib/systemd/systemd --switched-root --system --deserialize 31", "cpu_percent": 0.1, "memory_percent": 0.4, "status": "S"},
    {"pid": 340, "ppid": 1, "username": "root", "process_name": "systemd-journald", "cmdline": "/usr/lib/systemd/systemd-journald", "cpu_percent": 0.3, "memory_percent": 1.2, "status": "S"},
    {"pid": 845, "ppid": 1, "username": "root", "process_name": "sshd", "cmdline": "/usr/sbin/sshd -D", "cpu_percent": 0.0, "memory_percent": 0.6, "status": "S"},
    {"pid": 920, "ppid": 1, "username": "root", "process_name": "auditd", "cmdline": "/sbin/auditd", "cpu_percent": 0.2, "memory_percent": 0.5, "status": "S"},
    {"pid": 1050, "ppid": 1, "username": "root", "process_name": "firewalld", "cmdline": "/usr/bin/python3 -Es /usr/sbin/firewalld --nofork --nopid", "cpu_percent": 0.1, "memory_percent": 1.8, "status": "S"},
    {"pid": 1410, "ppid": 1, "username": "postgres", "process_name": "postgres", "cmdline": "/usr/pgsql-16/bin/postgres -D /var/lib/pgsql/16/data", "cpu_percent": 1.2, "memory_percent": 4.5, "status": "S"},
    {"pid": 2045, "ppid": 845, "username": "root", "process_name": "sshd", "cmdline": "sshd: root@pts/0", "cpu_percent": 0.4, "memory_percent": 0.8, "status": "S"},
    {"pid": 2046, "ppid": 2045, "username": "root", "process_name": "bash", "cmdline": "-bash", "cpu_percent": 0.0, "memory_percent": 0.3, "status": "S"}
]


class ProcessMonitoringService:
    """
    Manages host process telemetry, systemd units, anomaly detection, and persistence.
    """

    def __init__(self):
        self._memory_processes: Dict[str, List[Dict[str, Any]]] = {}
        self._memory_services: Dict[str, List[Dict[str, Any]]] = {}
        self._memory_alerts: List[Dict[str, Any]] = []
        if is_database_online():
            self._ensure_tables()
        self._init_defaults("localhost")

    def _ensure_tables(self):
        sql = """
        CREATE TABLE IF NOT EXISTS monitored_processes (
            id SERIAL PRIMARY KEY,
            hostname VARCHAR(100) NOT NULL,
            pid INTEGER NOT NULL,
            ppid INTEGER DEFAULT 0,
            username VARCHAR(50) NOT NULL,
            process_name VARCHAR(100) NOT NULL,
            cmdline VARCHAR(1000) DEFAULT '',
            cpu_percent DOUBLE PRECISION DEFAULT 0.0,
            memory_percent DOUBLE PRECISION DEFAULT 0.0,
            status VARCHAR(20) DEFAULT 'R',
            is_suspicious BOOLEAN DEFAULT FALSE,
            threat_category VARCHAR(50) DEFAULT 'BENIGN',
            captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS systemd_services (
            id SERIAL PRIMARY KEY,
            hostname VARCHAR(100) NOT NULL,
            service_name VARCHAR(100) NOT NULL,
            load_state VARCHAR(30) DEFAULT 'loaded',
            active_state VARCHAR(30) DEFAULT 'active',
            sub_state VARCHAR(30) DEFAULT 'running',
            description VARCHAR(255) DEFAULT '',
            is_failed BOOLEAN DEFAULT FALSE,
            restart_count INTEGER DEFAULT 0,
            last_checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS process_security_alerts (
            id SERIAL PRIMARY KEY,
            hostname VARCHAR(100) NOT NULL,
            alert_type VARCHAR(60) NOT NULL,
            severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
            process_name VARCHAR(100) NOT NULL,
            pid INTEGER NOT NULL,
            details VARCHAR(500) NOT NULL,
            recommendation VARCHAR(500) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

    @staticmethod
    def _is_local_host(hostname: str) -> bool:
        import socket
        norm = (hostname or "").strip().lower()
        return norm in {"", "localhost", "127.0.0.1", "::1", socket.gethostname().lower()}

    @staticmethod
    def _collect_local_processes(limit: int = 50) -> List[Dict[str, Any]]:
        cpu_cores = max(int(psutil.cpu_count(logical=True) or 1), 1)
        procs = []
        for p in psutil.process_iter(['pid', 'ppid', 'name', 'username', 'cmdline', 'cpu_percent', 'memory_percent', 'status']):
            try:
                info = p.info
                pid = int(info.get("pid") or 0)
                pname = str(info.get("name") or "")
                # Skip Windows System Idle Process (PID 0), whose idle counter reports 100%+ * cores
                if pid == 0 or pname.lower() in {"system idle process", "idle"}:
                    continue
                raw_cpu = float(info["cpu_percent"] or 0.0)
                norm_cpu = round(min(100.0, raw_cpu / cpu_cores), 1)
                procs.append({
                    "pid": pid,
                    "ppid": info["ppid"] or 0,
                    "username": info["username"] or "system",
                    "process_name": pname or "unknown",
                    "cmdline": " ".join(info["cmdline"] or []) if isinstance(info["cmdline"], list) else str(info["cmdline"] or ""),
                    "cpu_percent": norm_cpu,
                    "memory_percent": float(round(info["memory_percent"] or 0.0, 2)),
                    "status": str(info["status"] or "running")
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        procs.sort(key=lambda x: (x["cpu_percent"], x["memory_percent"]), reverse=True)
        return procs[:limit]

    @staticmethod
    def _collect_local_services(hostname: str, limit: int = 40) -> List[Dict[str, Any]]:
        import os
        import subprocess
        services: List[Dict[str, Any]] = []
        if os.name == "nt" and hasattr(psutil, "win_service_iter"):
            for svc in psutil.win_service_iter():
                try:
                    info = svc.as_dict()
                    raw_status = str(info.get("status", "unknown")).lower()
                    active_state = "active" if raw_status == "running" else "inactive"
                    services.append({
                        "hostname": hostname,
                        "service_name": info.get("name") or svc.name(),
                        "unit_name": info.get("name") or svc.name(),
                        "load_state": "loaded",
                        "active_state": active_state,
                        "sub_state": raw_status,
                        "description": info.get("display_name") or info.get("name") or "",
                        "is_failed": False,
                        "restart_count": 0,
                    })
                except Exception:
                    continue
                if len(services) >= limit:
                    break
            services.sort(key=lambda s: (0 if s["active_state"] == "active" else 1, s["service_name"].lower()))
            return services
        try:
            proc = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain", "--no-legend"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    parts = line.split(None, 4)
                    if len(parts) >= 4:
                        unit, load_s, active_s, sub_s = parts[:4]
                        desc = parts[4] if len(parts) > 4 else ""
                        services.append({
                            "hostname": hostname,
                            "service_name": unit,
                            "unit_name": unit,
                            "load_state": load_s,
                            "active_state": active_s,
                            "sub_state": sub_s,
                            "description": desc,
                            "is_failed": active_s == "failed" or sub_s == "failed",
                            "restart_count": 0,
                        })
                        if len(services) >= limit:
                            break
        except Exception:
            pass
        return services

    def _init_defaults(self, hostname: str):
        if self._is_local_host(hostname):
            self.scan_host(hostname)
            return
        self._memory_processes[hostname] = []
        self._memory_services[hostname] = []

    def scan_host(self, hostname: str = "localhost", custom_processes: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Collect and analyze processes and services for a host.
        """
        if custom_processes is not None:
            procs = custom_processes
        elif self._is_local_host(hostname):
            procs = self._collect_local_processes()
            self._memory_services[hostname] = self._collect_local_services(hostname)
        else:
            procs = list(self._memory_processes.get(hostname, []))

        # Inspect each process
        analyzed_procs = []
        alerts = []
        for p in procs:
            analysis = ProcessAnalyzer.inspect_process(p)
            entry = dict(p)
            entry["hostname"] = hostname
            entry["is_suspicious"] = analysis["is_suspicious"]
            entry["threat_category"] = analysis["threat_category"]
            analyzed_procs.append(entry)

            if analysis["is_suspicious"]:
                alert = {
                    "hostname": hostname,
                    "alert_type": analysis["alert_type"],
                    "severity": analysis["severity"],
                    "process_name": p.get("process_name"),
                    "pid": p.get("pid"),
                    "details": analysis["details"],
                    "recommendation": analysis["recommendation"],
                    "created_at": datetime.now(timezone.utc).isoformat()
                }
                alerts.append(alert)
                self._memory_alerts.append(alert)

        self._memory_processes[hostname] = analyzed_procs

        # Inspect services
        services = self._memory_services.get(hostname, [])
        for s in services:
            s_alert = ProcessAnalyzer.inspect_service(s)
            if s_alert:
                alert = {
                    "hostname": hostname,
                    "alert_type": s_alert["alert_type"],
                    "severity": s_alert["severity"],
                    "process_name": s_alert["service_name"],
                    "pid": 0,
                    "details": s_alert["details"],
                    "recommendation": s_alert["recommendation"],
                    "created_at": datetime.now(timezone.utc).isoformat()
                }
                alerts.append(alert)
                self._memory_alerts.append(alert)

        # Database persistence (non-blocking)
        if is_database_online():
            try:
                with engine.begin() as conn:
                    for ap in analyzed_procs:
                        conn.execute(text("""
                            INSERT INTO monitored_processes
                            (hostname, pid, ppid, username, process_name, cmdline, cpu_percent, memory_percent, status, is_suspicious, threat_category)
                            VALUES (:host, :pid, :ppid, :user, :name, :cmd, :cpu, :mem, :status, :susp, :threat)
                        """), {
                            "host": hostname,
                            "pid": ap["pid"],
                            "ppid": ap.get("ppid", 0),
                            "user": ap["username"],
                            "name": ap["process_name"],
                            "cmd": ap.get("cmdline", "")[:1000],
                            "cpu": ap.get("cpu_percent", 0.0),
                            "mem": ap.get("memory_percent", 0.0),
                            "status": ap.get("status", "R"),
                            "susp": ap["is_suspicious"],
                            "threat": ap["threat_category"]
                        })
                    for al in alerts:
                        conn.execute(text("""
                            INSERT INTO process_security_alerts
                            (hostname, alert_type, severity, process_name, pid, details, recommendation)
                            VALUES (:host, :type, :sev, :name, :pid, :det, :rec)
                        """), {
                            "host": hostname,
                            "type": al["alert_type"],
                            "sev": al["severity"],
                            "name": al["process_name"],
                            "pid": al["pid"],
                            "det": al["details"],
                            "rec": al["recommendation"]
                        })
            except Exception:
                pass

        return {
            "hostname": hostname,
            "total_processes": len(analyzed_procs),
            "suspicious_count": sum(1 for p in analyzed_procs if p["is_suspicious"]),
            "services_count": len(services),
            "new_alerts_emitted": len(alerts),
            "scanned_at": datetime.now(timezone.utc).isoformat()
        }

    def list_processes(
        self,
        hostname: str = "localhost",
        suspicious_only: bool = False,
        sort_by: str = "cpu",
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """List running processes with sorting and filtering."""
        if self._is_local_host(hostname):
            host_key = "localhost"
            if host_key not in self._memory_processes:
                self.scan_host(host_key)
            procs = self._memory_processes.get(host_key, [])
        else:
            procs = self._memory_processes.get(hostname, [])
        if suspicious_only:
            procs = [p for p in procs if p.get("is_suspicious", False)]

        if sort_by == "cpu":
            procs = sorted(procs, key=lambda x: float(x.get("cpu_percent", 0.0)), reverse=True)
        elif sort_by == "memory":
            procs = sorted(procs, key=lambda x: float(x.get("memory_percent", 0.0)), reverse=True)

        return procs[:limit]

    def list_services(self, hostname: str = "localhost", failed_only: bool = False) -> List[Dict[str, Any]]:
        """List OS services for host."""
        if self._is_local_host(hostname):
            host_key = "localhost"
            if host_key not in self._memory_services:
                self.scan_host(host_key)
            services = self._memory_services.get(host_key, [])
        else:
            services = self._memory_services.get(hostname, [])
        if failed_only:
            services = [s for s in services if s.get("is_failed", False) or s.get("active_state") == "failed"]
        return services

    def list_alerts(self, hostname: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve emitted process security alerts."""
        alerts = list(self._memory_alerts)
        if hostname:
            host_key = "localhost" if self._is_local_host(hostname) else hostname
            alerts = [a for a in alerts if a.get("hostname") in {hostname, host_key}]
        return alerts[-limit:]

    def get_stats(self, hostname: str = "localhost") -> Dict[str, Any]:
        """Summary metrics for Process & Service Monitoring."""
        procs = self.list_processes(hostname=hostname, limit=1000)
        services = self.list_services(hostname=hostname)
        alerts = self.list_alerts(hostname=hostname)

        high_cpu_count = sum(1 for p in procs if float(p.get("cpu_percent", 0.0)) > 50.0)
        suspicious_count = sum(1 for p in procs if p.get("is_suspicious", False))
        failed_services = sum(1 for s in services if s.get("is_failed", False) or s.get("active_state") == "failed")

        return {
            "hostname": hostname,
            "running_processes_count": len(procs),
            "high_cpu_processes_count": high_cpu_count,
            "suspicious_processes_count": suspicious_count,
            "systemd_services_count": len(services),
            "failed_services_count": failed_services,
            "process_security_alerts_count": len(alerts)
        }


# Singleton service instance
process_service = ProcessMonitoringService()
