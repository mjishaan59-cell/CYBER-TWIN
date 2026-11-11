"""
Threat Intelligence Service
Phase 22 - AI Threat Intelligence Subsystem
Manages IOC persistence, querying, audit logging, feed synchronization, and stats.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy import text
from backend.database import engine, is_database_online
from backend.threat_intel.feed_collector import (
    ThreatFeedCollector,
    detect_indicator_type,
    FALLBACK_SEED_IOCS
)
from backend.threat_intel.threat_classifier import ThreatClassifier
from backend.threat_intel.mitre_mapper import map_threat_to_mitre, get_all_mitre_techniques
from backend.threat_intel.threat_correlator import ThreatCorrelator


class ThreatIntelligenceService:
    """
    Central service for threat intelligence operations.
    """

    def __init__(self):
        self.collector = ThreatFeedCollector()
        self.correlator = ThreatCorrelator(self.lookup_indicator_dict)
        if is_database_online():
            self._ensure_tables()
            self._seed_if_empty()

    def _ensure_tables(self):
        """Ensure threat intelligence tables exist in the active database."""
        create_sql = """
        CREATE TABLE IF NOT EXISTS threat_indicators (
            id SERIAL PRIMARY KEY,
            indicator_value VARCHAR(255) UNIQUE NOT NULL,
            indicator_type VARCHAR(30) NOT NULL,
            threat_type VARCHAR(50) NOT NULL,
            severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
            confidence_score INTEGER NOT NULL DEFAULT 70,
            source_feed VARCHAR(100) NOT NULL,
            mitre_attack_id VARCHAR(20),
            mitre_tactic VARCHAR(50),
            description VARCHAR(500),
            tags VARCHAR(255) DEFAULT '',
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS threat_lookup_audit (
            id SERIAL PRIMARY KEY,
            indicator_value VARCHAR(255) NOT NULL,
            matched BOOLEAN NOT NULL DEFAULT FALSE,
            threat_score INTEGER NOT NULL DEFAULT 0,
            severity VARCHAR(20) NOT NULL DEFAULT 'LOW',
            queried_by VARCHAR(100) DEFAULT 'system',
            context VARCHAR(255) DEFAULT '',
            lookup_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS threat_feed_sync (
            id SERIAL PRIMARY KEY,
            feed_name VARCHAR(100) UNIQUE NOT NULL,
            feed_url VARCHAR(255) NOT NULL,
            indicator_count INTEGER NOT NULL DEFAULT 0,
            last_sync_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            sync_status VARCHAR(30) NOT NULL DEFAULT 'PENDING',
            error_message VARCHAR(500)
        );
        """
        # Adapt for SQLite if running on SQLite
        if str(engine.url).startswith("sqlite"):
            create_sql = create_sql.replace("SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")

        try:
            with engine.begin() as conn:
                for stmt in create_sql.split(";"):
                    stmt_clean = stmt.strip()
                    if stmt_clean:
                        conn.execute(text(stmt_clean))
        except Exception:
            pass

    def _seed_if_empty(self):
        """Populate seed indicators if the table is currently empty."""
        try:
            with engine.connect() as conn:
                res = conn.execute(text("SELECT COUNT(*) FROM threat_indicators")).scalar()
                if res and res > 0:
                    return

            # Insert baseline seed indicators
            self.ingest_indicators(FALLBACK_SEED_IOCS)
        except Exception:
            pass

    def ingest_indicators(self, indicators: List[Dict[str, Any]]) -> int:
        """Ingest or update a list of indicators in the database, with memory cache fallback."""
        inserted = 0
        upsert_clause = (
            "ON CONFLICT(indicator_value) DO UPDATE SET "
            "last_seen = CURRENT_TIMESTAMP, "
            "confidence_score = EXCLUDED.confidence_score, "
            "severity = EXCLUDED.severity"
        )

        if is_database_online():
            try:
                with engine.begin() as conn:
                    for ioc in indicators:
                        try:
                            val = ioc["indicator_value"].strip()
                            ioc_type = ioc.get("indicator_type") or detect_indicator_type(val)
                            threat_type = ioc.get("threat_type", "UNKNOWN")
                            severity = ioc.get("severity", "MEDIUM")
                            conf = int(ioc.get("confidence_score", 70))
                            feed = ioc.get("source_feed", "Manual Entry")
                            mitre_id = ioc.get("mitre_attack_id")
                            mitre_tactic = ioc.get("mitre_tactic")
                            if not mitre_id:
                                m = map_threat_to_mitre(threat_type)
                                mitre_id = m["attack_id"]
                                mitre_tactic = m["tactic"]
                            desc = ioc.get("description", "")
                            tags = ioc.get("tags", "")

                            sql = f"""
                            INSERT INTO threat_indicators
                            (indicator_value, indicator_type, threat_type, severity, confidence_score,
                             source_feed, mitre_attack_id, mitre_tactic, description, tags, is_active)
                            VALUES
                            (:val, :type, :threat, :severity, :conf, :feed, :mitre_id, :mitre_tactic, :desc, :tags, TRUE)
                            {upsert_clause};
                            """
                            conn.execute(text(sql), {
                                "val": val,
                                "type": ioc_type,
                                "threat": threat_type,
                                "severity": severity,
                                "conf": conf,
                                "feed": feed,
                                "mitre_id": mitre_id,
                                "mitre_tactic": mitre_tactic,
                                "desc": desc,
                                "tags": tags
                            })
                            inserted += 1
                        except Exception:
                            continue
                return inserted
            except Exception:
                pass

        # When persistent DB is offline, cache in fallback seed corpus
        for ioc in indicators:
            val = ioc["indicator_value"].strip()
            existing = next((s for s in FALLBACK_SEED_IOCS if s["indicator_value"] == val), None)
            if existing:
                existing.update(ioc)
            else:
                FALLBACK_SEED_IOCS.append(ioc)
            inserted += 1

        return inserted

    def lookup_indicator_dict(self, value: str) -> Optional[Dict[str, Any]]:
        """Fast lookup dictionary for an indicator."""
        clean_val = value.strip()
        if is_database_online():
            try:
                with engine.connect() as conn:
                    row = conn.execute(
                        text("SELECT * FROM threat_indicators WHERE indicator_value = :val AND is_active = TRUE"),
                        {"val": clean_val}
                    ).mappings().first()
                    if row:
                        return dict(row)
            except Exception:
                pass
        # Fallback to in-memory seed lookup if database is offline or query fails
        for seed in FALLBACK_SEED_IOCS:
            if seed["indicator_value"].lower() == clean_val.lower():
                return dict(seed)
        return None

    def lookup(self, value: str, user: str = "system", context: str = "web_lookup") -> Dict[str, Any]:
        """
        Public lookup method. Logs audit trail and returns full enriched threat intelligence.
        """
        clean_val = value.strip()
        ioc_type = detect_indicator_type(clean_val)
        matched_dict = self.lookup_indicator_dict(clean_val)

        if matched_dict:
            threat_type = matched_dict.get("threat_type", "UNKNOWN")
            conf = matched_dict.get("confidence_score", 70)
            score_data = ThreatClassifier.calculate_threat_score(
                threat_type=threat_type,
                feed_confidence=conf
            )
            mitre_data = map_threat_to_mitre(threat_type, matched_dict.get("description"))

            res = {
                "indicator_value": clean_val,
                "indicator_type": ioc_type,
                "matched": True,
                "threat_score": score_data["threat_score"],
                "severity": score_data["severity"],
                "confidence_score": conf,
                "threat_type": threat_type,
                "source_feed": matched_dict.get("source_feed"),
                "mitre_attack": mitre_data,
                "description": matched_dict.get("description"),
                "tags": matched_dict.get("tags", ""),
                "is_active": True,
                "recommendation": (
                    "BLOCK_INDICATOR" if score_data["threat_score"] >= 75 else "ENHANCED_LOGGING"
                )
            }
        else:
            res = {
                "indicator_value": clean_val,
                "indicator_type": ioc_type,
                "matched": False,
                "threat_score": 0,
                "severity": "CLEAN",
                "confidence_score": 50,
                "threat_type": "BENIGN",
                "source_feed": "None",
                "mitre_attack": None,
                "description": "Indicator not identified in active threat feeds or historical databases.",
                "tags": "",
                "is_active": False,
                "recommendation": "ALLOW"
            }

        # Audit logging (non-fatal)
        if is_database_online():
            try:
                with engine.begin() as conn:
                    conn.execute(
                        text("""
                        INSERT INTO threat_lookup_audit
                        (indicator_value, matched, threat_score, severity, queried_by, context)
                        VALUES (:val, :matched, :score, :sev, :user, :ctx)
                        """),
                        {
                            "val": clean_val,
                            "matched": res["matched"],
                            "score": res["threat_score"],
                            "sev": res["severity"],
                            "user": user,
                            "ctx": context
                        }
                    )
            except Exception:
                pass

        return res

    def list_indicators(
        self,
        indicator_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """List active threat indicators with filtering."""
        where_clauses = ["is_active = TRUE"]
        params: Dict[str, Any] = {"limit": limit, "offset": offset}

        if indicator_type:
            where_clauses.append("indicator_type = :type")
            params["type"] = indicator_type.upper().strip()
        if severity:
            where_clauses.append("severity = :severity")
            params["severity"] = severity.upper().strip()

        where_str = " AND ".join(where_clauses)
        sql = f"""
        SELECT id, indicator_value, indicator_type, threat_type, severity,
               confidence_score, source_feed, mitre_attack_id, mitre_tactic,
               description, tags, is_active, first_seen, last_seen
        FROM threat_indicators
        WHERE {where_str}
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
            END, id DESC
        LIMIT :limit OFFSET :offset;
        """
        if is_database_online():
            try:
                with engine.connect() as conn:
                    rows = conn.execute(text(sql), params).mappings().all()
                    return [dict(r) for r in rows]
            except Exception:
                pass

        # Return seed fallback filtered
        results = []
        for s in FALLBACK_SEED_IOCS:
            if indicator_type and s["indicator_type"].upper() != indicator_type.upper():
                continue
            if severity and s["severity"].upper() != severity.upper():
                continue
            results.append(s)
        return results[:limit]

    def add_custom_indicator(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Manually add a threat indicator with validation and MITRE mapping."""
        val = data["indicator_value"].strip()
        ioc_type = data.get("indicator_type") or detect_indicator_type(val)
        threat_type = data.get("threat_type", "UNKNOWN")
        conf = int(data.get("confidence_score", 80))
        desc = data.get("description", "Analyst registered custom indicator")
        tags = data.get("tags", "custom,analyst")

        score_res = ThreatClassifier.calculate_threat_score(
            threat_type=threat_type,
            feed_confidence=conf
        )
        mitre_data = map_threat_to_mitre(threat_type, desc)

        record = {
            "indicator_value": val,
            "indicator_type": ioc_type,
            "threat_type": threat_type,
            "severity": score_res["severity"],
            "confidence_score": conf,
            "source_feed": data.get("source_feed", "Analyst Submission"),
            "mitre_attack_id": mitre_data["attack_id"],
            "mitre_tactic": mitre_data["tactic"],
            "description": desc,
            "tags": tags
        }
        self.ingest_indicators([record])
        return record

    def sync_feeds(self) -> Dict[str, Any]:
        """Execute feed synchronization and update feed sync metadata."""
        feed_results = self.collector.collect_all_feeds()
        indicators = feed_results["indicators"]
        ingested_count = self.ingest_indicators(indicators)

        # Update feed sync tracking table
        if is_database_online():
            try:
                with engine.begin() as conn:
                    for feed_name, feed_info in feed_results["feeds"].items():
                        sql = """
                        INSERT INTO threat_feed_sync (feed_name, feed_url, indicator_count, sync_status, last_sync_at)
                        VALUES (:name, :url, :count, :status, CURRENT_TIMESTAMP)
                        ON CONFLICT(feed_name) DO UPDATE SET
                        indicator_count = EXCLUDED.indicator_count,
                        sync_status = EXCLUDED.sync_status,
                        last_sync_at = CURRENT_TIMESTAMP;
                        """
                        conn.execute(text(sql), {
                            "name": feed_name,
                            "url": "https://threat-feed.provider/api",
                            "count": feed_info["count"],
                            "status": feed_info["status"]
                        })
            except Exception:
                pass

        return {
            "synced_at": feed_results["synced_at"],
            "total_indicators_active": ingested_count,
            "feeds": feed_results["feeds"]
        }

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate statistical metrics for the threat intelligence dashboard."""
        if is_database_online():
            try:
                with engine.connect() as conn:
                    total_iocs = conn.execute(text("SELECT COUNT(*) FROM threat_indicators WHERE is_active = TRUE")).scalar() or 0
                    critical_count = conn.execute(text("SELECT COUNT(*) FROM threat_indicators WHERE severity = 'CRITICAL' AND is_active = TRUE")).scalar() or 0
                    high_count = conn.execute(text("SELECT COUNT(*) FROM threat_indicators WHERE severity = 'HIGH' AND is_active = TRUE")).scalar() or 0
                    ip_count = conn.execute(text("SELECT COUNT(*) FROM threat_indicators WHERE indicator_type = 'IP' AND is_active = TRUE")).scalar() or 0
                    domain_count = conn.execute(text("SELECT COUNT(*) FROM threat_indicators WHERE indicator_type = 'DOMAIN' AND is_active = TRUE")).scalar() or 0
                    hash_count = conn.execute(text("SELECT COUNT(*) FROM threat_indicators WHERE indicator_type = 'SHA256' AND is_active = TRUE")).scalar() or 0
                    lookups_total = conn.execute(text("SELECT COUNT(*) FROM threat_lookup_audit")).scalar() or 0
                    lookups_matched = conn.execute(text("SELECT COUNT(*) FROM threat_lookup_audit WHERE matched = TRUE")).scalar() or 0

                    return {
                        "total_active_iocs": total_iocs,
                        "critical_severity_count": critical_count,
                        "high_severity_count": high_count,
                        "ip_indicators": ip_count,
                        "domain_indicators": domain_count,
                        "hash_indicators": hash_count,
                        "total_lookups": lookups_total,
                        "threats_detected": lookups_matched,
                        "mitre_techniques_cataloged": len(get_all_mitre_techniques())
                    }
            except Exception:
                pass

        # Fallback stats from seed
        return {
            "total_active_iocs": len(FALLBACK_SEED_IOCS),
            "critical_severity_count": sum(1 for s in FALLBACK_SEED_IOCS if s["severity"] == "CRITICAL"),
            "high_severity_count": sum(1 for s in FALLBACK_SEED_IOCS if s["severity"] == "HIGH"),
            "ip_indicators": sum(1 for s in FALLBACK_SEED_IOCS if s["indicator_type"] == "IP"),
            "domain_indicators": sum(1 for s in FALLBACK_SEED_IOCS if s["indicator_type"] == "DOMAIN"),
            "hash_indicators": sum(1 for s in FALLBACK_SEED_IOCS if s["indicator_type"] == "SHA256"),
            "total_lookups": 0,
            "threats_detected": 0,
            "mitre_techniques_cataloged": len(get_all_mitre_techniques())
        }


# Singleton service instance
threat_intel_service = ThreatIntelligenceService()
