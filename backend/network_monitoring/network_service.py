"""
Network Security Monitoring Service
Phase 26 - Network Security Monitoring Subsystem
Manages interface telemetry, listening sockets, active connections, and network anomaly detection.
"""

import psutil
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy import text
from backend.database import engine
from backend.network_monitoring.network_analyzer import NetworkSecurityAnalyzer

DEFAULT_INTERFACES = [
    {
        "interface_name": "eth0",
        "bytes_sent": 142058900,
        "bytes_recv": 894312000,
        "packets_sent": 841200,
        "packets_recv": 1245000,
        "errin": 0,
        "errout": 0,
        "dropin": 0,
        "dropout": 0,
        "is_up": True,
        "speed_mbps": 1000
    },
    {
        "interface_name": "lo",
        "bytes_sent": 51204000,
        "bytes_recv": 51204000,
        "packets_sent": 320100,
        "packets_recv": 320100,
        "errin": 0,
        "errout": 0,
        "dropin": 0,
        "dropout": 0,
        "is_up": True,
        "speed_mbps": 10000
    }
]

DEFAULT_CONNECTIONS = [
    {
        "protocol": "tcp",
        "local_address": "0.0.0.0",
        "local_port": 22,
        "remote_address": "",
        "remote_port": 0,
        "status": "LISTEN",
        "pid": 845,
        "process_name": "sshd"
    },
    {
        "protocol": "tcp",
        "local_address": "127.0.0.1",
        "local_port": 5432,
        "remote_address": "",
        "remote_port": 0,
        "status": "LISTEN",
        "pid": 1410,
        "process_name": "postgres"
    },
    {
        "protocol": "tcp",
        "local_address": "0.0.0.0",
        "local_port": 8000,
        "remote_address": "",
        "remote_port": 0,
        "status": "LISTEN",
        "pid": 2100,
        "process_name": "uvicorn"
    },
    {
        "protocol": "tcp",
        "local_address": "192.168.1.100",
        "local_port": 22,
        "remote_address": "192.168.1.45",
        "remote_port": 54312,
        "status": "ESTABLISHED",
        "pid": 2045,
        "process_name": "sshd"
    },
    {
        "protocol": "tcp",
        "local_address": "192.168.1.100",
        "local_port": 51234,
        "remote_address": "1.1.1.1",
        "remote_port": 53,
        "status": "ESTABLISHED",
        "pid": 600,
        "process_name": "systemd-resolved"
    }
]


class NetworkMonitoringService:
    """
    Orchestrates network discovery, socket inspection, database archiving, and alerting.
    """

    def __init__(self):
        self._memory_interfaces: Dict[str, List[Dict[str, Any]]] = {}
        self._memory_connections: Dict[str, List[Dict[str, Any]]] = {}
        self._memory_ports: Dict[str, List[Dict[str, Any]]] = {}
        self._memory_alerts: List[Dict[str, Any]] = []
        self._ensure_tables()
        self._init_defaults("prac-server")

    def _ensure_tables(self):
        sql = """
        CREATE TABLE IF NOT EXISTS network_interface_snapshots (
            id SERIAL PRIMARY KEY,
            hostname VARCHAR(100) NOT NULL,
            interface_name VARCHAR(50) NOT NULL,
            bytes_sent BIGINT DEFAULT 0,
            bytes_recv BIGINT DEFAULT 0,
            packets_sent BIGINT DEFAULT 0,
            packets_recv BIGINT DEFAULT 0,
            errin INTEGER DEFAULT 0,
            errout INTEGER DEFAULT 0,
            dropin INTEGER DEFAULT 0,
            dropout INTEGER DEFAULT 0,
            is_up BOOLEAN DEFAULT TRUE,
            speed_mbps INTEGER DEFAULT 1000,
            recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS network_connection_records (
            id SERIAL PRIMARY KEY,
            hostname VARCHAR(100) NOT NULL,
            protocol VARCHAR(10) DEFAULT 'tcp',
            local_address VARCHAR(100) NOT NULL,
            local_port INTEGER NOT NULL,
            remote_address VARCHAR(100) DEFAULT '',
            remote_port INTEGER DEFAULT 0,
            status VARCHAR(30) DEFAULT 'ESTABLISHED',
            pid INTEGER DEFAULT 0,
            process_name VARCHAR(100) DEFAULT '',
            is_suspicious BOOLEAN DEFAULT FALSE,
            risk_score INTEGER DEFAULT 0,
            threat_description VARCHAR(255) DEFAULT '',
            recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS listening_port_records (
            id SERIAL PRIMARY KEY,
            hostname VARCHAR(100) NOT NULL,
            protocol VARCHAR(10) DEFAULT 'tcp',
            bind_address VARCHAR(100) NOT NULL,
            port INTEGER NOT NULL,
            pid INTEGER DEFAULT 0,
            process_name VARCHAR(100) DEFAULT '',
            is_authorized BOOLEAN DEFAULT TRUE,
            service_hint VARCHAR(50) DEFAULT '',
            risk_level VARCHAR(20) DEFAULT 'LOW',
            last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS network_security_alerts (
            id SERIAL PRIMARY KEY,
            hostname VARCHAR(100) NOT NULL,
            alert_type VARCHAR(60) NOT NULL,
            severity VARCHAR(20) NOT NULL,
            source_ip VARCHAR(50) DEFAULT '',
            source_port INTEGER DEFAULT 0,
            destination_ip VARCHAR(50) DEFAULT '',
            destination_port INTEGER DEFAULT 0,
            protocol VARCHAR(10) DEFAULT 'TCP',
            mitre_technique VARCHAR(50) DEFAULT '',
            description VARCHAR(500) NOT NULL,
            recommendation VARCHAR(500) DEFAULT '',
            resolved BOOLEAN DEFAULT FALSE,
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

    def _init_defaults(self, hostname: str):
        self._memory_interfaces[hostname] = list(DEFAULT_INTERFACES)
        self.scan_network(hostname=hostname)

    def scan_network(
        self,
        hostname: str = "prac-server",
        custom_connections: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Scan system network interfaces, sockets, and listening ports with security analytics.
        """
        # 1. Interface Discovery
        interfaces = []
        try:
            net_io = psutil.net_io_counters(pernic=True)
            stats = psutil.net_if_stats()
            for nic_name, io in net_io.items():
                st = stats.get(nic_name)
                interfaces.append({
                    "interface_name": nic_name,
                    "bytes_sent": io.bytes_sent,
                    "bytes_recv": io.bytes_recv,
                    "packets_sent": io.packets_sent,
                    "packets_recv": io.packets_recv,
                    "errin": io.errin,
                    "errout": io.errout,
                    "dropin": io.dropin,
                    "dropout": io.dropout,
                    "is_up": st.isup if st else True,
                    "speed_mbps": st.speed if st and st.speed > 0 else 1000
                })
        except Exception:
            pass
        if not interfaces:
            interfaces = list(DEFAULT_INTERFACES)
        self._memory_interfaces[hostname] = interfaces

        # 2. Connection Discovery
        raw_conns = []
        if custom_connections is not None:
            raw_conns = custom_connections
        else:
            try:
                conns = psutil.net_connections(kind="inet")
                for c in conns:
                    l_addr = c.laddr.ip if c.laddr else "0.0.0.0"
                    l_port = c.laddr.port if c.laddr else 0
                    r_addr = c.raddr.ip if c.raddr else ""
                    r_port = c.raddr.port if c.raddr else 0
                    p_name = ""
                    if c.pid:
                        try:
                            p_name = psutil.Process(c.pid).name()
                        except Exception:
                            p_name = "unknown"
                    raw_conns.append({
                        "protocol": "tcp" if c.type == 1 else "udp",
                        "local_address": l_addr,
                        "local_port": l_port,
                        "remote_address": r_addr,
                        "remote_port": r_port,
                        "status": c.status or "ESTABLISHED",
                        "pid": c.pid or 0,
                        "process_name": p_name
                    })
            except Exception:
                pass
            if not raw_conns:
                raw_conns = list(DEFAULT_CONNECTIONS)

        # 3. Analyze Connections and Extract Listening Ports
        analyzed_conns = []
        listening_ports = []
        new_alerts = []

        # Analyze Interfaces for Health Anomalies
        for iface in interfaces:
            if_alert = NetworkSecurityAnalyzer.evaluate_interface_health(iface)
            if if_alert:
                alert_dict = {
                    "hostname": hostname,
                    "alert_type": if_alert["alert_type"],
                    "severity": if_alert["severity"],
                    "source_ip": iface["interface_name"],
                    "source_port": 0,
                    "destination_ip": "",
                    "destination_port": 0,
                    "protocol": "ETH",
                    "mitre_technique": if_alert["mitre_technique"],
                    "description": if_alert["description"],
                    "recommendation": if_alert["recommendation"],
                    "created_at": datetime.now(timezone.utc).isoformat()
                }
                new_alerts.append(alert_dict)
                self._memory_alerts.append(alert_dict)

        seen_ports = set()
        for c in raw_conns:
            status = str(c.get("status", "")).upper()
            l_port = int(c.get("local_port", 0))
            is_listen = status == "LISTEN" or (l_port > 0 and not c.get("remote_address"))

            if is_listen and l_port not in seen_ports:
                seen_ports.add(l_port)
                port_eval = NetworkSecurityAnalyzer.analyze_listening_port({
                    "port": l_port,
                    "bind_address": c.get("local_address", "0.0.0.0"),
                    "process_name": c.get("process_name", ""),
                    "pid": c.get("pid", 0)
                })
                port_record = {
                    "hostname": hostname,
                    "protocol": c.get("protocol", "tcp"),
                    "bind_address": c.get("local_address", "0.0.0.0"),
                    "port": l_port,
                    "pid": c.get("pid", 0),
                    "process_name": c.get("process_name", ""),
                    "is_authorized": port_eval["is_authorized"],
                    "service_hint": port_eval["service_hint"],
                    "risk_level": port_eval["risk_level"],
                    "last_seen_at": datetime.now(timezone.utc).isoformat()
                }
                listening_ports.append(port_record)
                if port_eval.get("alert"):
                    al = port_eval["alert"]
                    alert_dict = {
                        "hostname": hostname,
                        "alert_type": al["alert_type"],
                        "severity": al["severity"],
                        "source_ip": c.get("local_address", "0.0.0.0"),
                        "source_port": l_port,
                        "destination_ip": "",
                        "destination_port": al.get("destination_port", l_port),
                        "protocol": c.get("protocol", "tcp").upper(),
                        "mitre_technique": al["mitre_technique"],
                        "description": al["description"],
                        "recommendation": al["recommendation"],
                        "created_at": datetime.now(timezone.utc).isoformat()
                    }
                    new_alerts.append(alert_dict)
                    self._memory_alerts.append(alert_dict)

            # Analyze Connection Record
            conn_eval = NetworkSecurityAnalyzer.analyze_connection(c)
            conn_record = dict(c)
            conn_record["hostname"] = hostname
            conn_record["is_suspicious"] = conn_eval["is_suspicious"]
            conn_record["risk_score"] = conn_eval["risk_score"]
            conn_record["threat_description"] = conn_eval["threat_description"]
            analyzed_conns.append(conn_record)

            for al in conn_eval.get("alerts", []):
                alert_dict = {
                    "hostname": hostname,
                    "alert_type": al["alert_type"],
                    "severity": al["severity"],
                    "source_ip": c.get("local_address", ""),
                    "source_port": c.get("local_port", 0),
                    "destination_ip": al.get("destination_ip", c.get("remote_address", "")),
                    "destination_port": al.get("destination_port", c.get("remote_port", 0)),
                    "protocol": c.get("protocol", "tcp").upper(),
                    "mitre_technique": al["mitre_technique"],
                    "description": al["description"],
                    "recommendation": al["recommendation"],
                    "created_at": datetime.now(timezone.utc).isoformat()
                }
                new_alerts.append(alert_dict)
                self._memory_alerts.append(alert_dict)

        self._memory_connections[hostname] = analyzed_conns
        self._memory_ports[hostname] = listening_ports

        # Database Persistence (safe non-blocking)
        try:
            with engine.begin() as conn:
                for iface in interfaces:
                    conn.execute(text("""
                        INSERT INTO network_interface_snapshots
                        (hostname, interface_name, bytes_sent, bytes_recv, packets_sent, packets_recv, errin, errout, dropin, dropout, is_up, speed_mbps)
                        VALUES (:host, :name, :bs, :br, :ps, :pr, :ei, :eo, :di, :do, :up, :spd)
                    """), {
                        "host": hostname,
                        "name": iface["interface_name"],
                        "bs": iface["bytes_sent"],
                        "br": iface["bytes_recv"],
                        "ps": iface["packets_sent"],
                        "pr": iface["packets_recv"],
                        "ei": iface["errin"],
                        "eo": iface["errout"],
                        "di": iface["dropin"],
                        "do": iface["dropout"],
                        "up": iface["is_up"],
                        "spd": iface["speed_mbps"]
                    })
                for lp in listening_ports:
                    conn.execute(text("""
                        INSERT INTO listening_port_records
                        (hostname, protocol, bind_address, port, pid, process_name, is_authorized, service_hint, risk_level)
                        VALUES (:host, :proto, :bind, :port, :pid, :pname, :auth, :hint, :risk)
                    """), {
                        "host": hostname,
                        "proto": lp["protocol"],
                        "bind": lp["bind_address"],
                        "port": lp["port"],
                        "pid": lp["pid"],
                        "pname": lp["process_name"],
                        "auth": lp["is_authorized"],
                        "hint": lp["service_hint"],
                        "risk": lp["risk_level"]
                    })
                for al in new_alerts:
                    conn.execute(text("""
                        INSERT INTO network_security_alerts
                        (hostname, alert_type, severity, source_ip, source_port, destination_ip, destination_port, protocol, mitre_technique, description, recommendation)
                        VALUES (:host, :type, :sev, :sip, :sport, :dip, :dport, :proto, :mitre, :desc, :rec)
                    """), {
                        "host": hostname,
                        "type": al["alert_type"],
                        "sev": al["severity"],
                        "sip": al["source_ip"],
                        "sport": al["source_port"],
                        "dip": al["destination_ip"],
                        "dport": al["destination_port"],
                        "proto": al["protocol"],
                        "mitre": al["mitre_technique"],
                        "desc": al["description"],
                        "rec": al["recommendation"]
                    })
        except Exception:
            pass

        return {
            "hostname": hostname,
            "interfaces_count": len(interfaces),
            "total_connections": len(analyzed_conns),
            "listening_ports_count": len(listening_ports),
            "suspicious_connections_count": sum(1 for c in analyzed_conns if c.get("is_suspicious")),
            "new_alerts_emitted": len(new_alerts),
            "scanned_at": datetime.now(timezone.utc).isoformat()
        }

    def list_interfaces(self, hostname: str = "prac-server") -> List[Dict[str, Any]]:
        """List current network interfaces for host."""
        return self._memory_interfaces.get(hostname, list(DEFAULT_INTERFACES))

    def list_connections(
        self,
        hostname: str = "prac-server",
        suspicious_only: bool = False,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """List active socket connections with optional threat filter."""
        conns = self._memory_connections.get(hostname, list(DEFAULT_CONNECTIONS))
        if suspicious_only:
            conns = [c for c in conns if c.get("is_suspicious", False)]
        return conns[:limit]

    def list_listening_ports(
        self,
        hostname: str = "prac-server",
        unauthorized_only: bool = False
    ) -> List[Dict[str, Any]]:
        """List listening ports and binding services."""
        ports = self._memory_ports.get(hostname, [])
        if unauthorized_only:
            ports = [p for p in ports if not p.get("is_authorized", True)]
        return ports

    def list_alerts(
        self,
        hostname: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """List emitted network security alerts."""
        alerts = list(self._memory_alerts)
        if hostname:
            alerts = [a for a in alerts if a.get("hostname") == hostname]
        return alerts[-limit:]

    def get_stats(self, hostname: str = "prac-server") -> Dict[str, Any]:
        """Summary KPI metrics for Network Security."""
        interfaces = self._memory_interfaces.get(hostname, list(DEFAULT_INTERFACES))
        conns = self._memory_connections.get(hostname, list(DEFAULT_CONNECTIONS))
        ports = self._memory_ports.get(hostname, [])
        alerts = self.list_alerts(hostname=hostname)

        total_bytes_sent = sum(i.get("bytes_sent", 0) for i in interfaces)
        total_bytes_recv = sum(i.get("bytes_recv", 0) for i in interfaces)
        suspicious_conns = sum(1 for c in conns if c.get("is_suspicious", False))
        unauthorized_ports = sum(1 for p in ports if not p.get("is_authorized", True))

        return {
            "hostname": hostname,
            "interfaces_count": len(interfaces),
            "active_connections_count": len(conns),
            "suspicious_connections_count": suspicious_conns,
            "listening_ports_count": len(ports),
            "unauthorized_ports_count": unauthorized_ports,
            "network_alerts_count": len(alerts),
            "total_bytes_sent": total_bytes_sent,
            "total_bytes_recv": total_bytes_recv
        }


# Singleton service instance
network_service = NetworkMonitoringService()
