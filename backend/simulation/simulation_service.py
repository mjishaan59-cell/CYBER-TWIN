"""
What-If Attack Simulation Service
Phase 28 - What-If Attack Simulation Subsystem
Persistence, historical tracking, and simulation lifecycle orchestration.
"""

import json
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy import text
from backend.database import engine, is_database_online
from backend.simulation.simulation_engine import SimulationEngine, SCENARIO_CATALOG


class SimulationService:
    """
    Manages simulation executions, step logs, historical querying, and DB synchronization.
    """

    def __init__(self):
        self._history: Dict[str, Dict[str, Any]] = {}
        if is_database_online():
            self._ensure_tables()
        self._seed_history()

    def _ensure_tables(self):
        sql = """
        CREATE TABLE IF NOT EXISTS attack_simulation_runs (
            id SERIAL PRIMARY KEY,
            simulation_id VARCHAR(64) UNIQUE NOT NULL,
            scenario_id VARCHAR(60) NOT NULL,
            scenario_name VARCHAR(120) NOT NULL,
            target_hostname VARCHAR(100) NOT NULL,
            mitre_technique VARCHAR(50) NOT NULL,
            tactics VARCHAR(80) DEFAULT 'Initial Access',
            simulated_by VARCHAR(50) DEFAULT 'admin',
            status VARCHAR(30) DEFAULT 'COMPLETED',
            risk_score INTEGER DEFAULT 50,
            impact_level VARCHAR(20) DEFAULT 'MEDIUM',
            predicted_containment_probability DOUBLE PRECISION DEFAULT 85.0,
            estimated_mttd_seconds INTEGER DEFAULT 15,
            estimated_mttr_seconds INTEGER DEFAULT 120,
            defensive_recommendations JSON DEFAULT '[]'::json,
            impact_summary TEXT DEFAULT '',
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS simulation_step_logs (
            id SERIAL PRIMARY KEY,
            simulation_id VARCHAR(64) NOT NULL,
            step_number INTEGER NOT NULL,
            step_name VARCHAR(120) NOT NULL,
            mitre_subtechnique VARCHAR(50) DEFAULT '',
            action_type VARCHAR(50) DEFAULT 'SYNTHETIC_PROBE',
            observed_telemetry VARCHAR(255) DEFAULT '',
            detection_status VARCHAR(30) DEFAULT 'DETECTED',
            details TEXT DEFAULT '',
            logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

    def _seed_history(self):
        # Run 2 baseline seed simulations
        sim1 = SimulationEngine.run_simulation("SSH_BRUTE_FORCE", "prac-server", "secops-lead")
        sim2 = SimulationEngine.run_simulation("REVERSE_SHELL_INJECTION", "prod-web-01", "redteam-bot")
        self._history[sim1["simulation_id"]] = sim1
        self._history[sim2["simulation_id"]] = sim2

    def list_scenarios(self) -> List[Dict[str, Any]]:
        """List all available attack scenarios in catalog."""
        return SimulationEngine.list_scenarios()

    def run_simulation(
        self,
        scenario_id: str,
        target_hostname: str = "prac-server",
        simulated_by: str = "admin"
    ) -> Dict[str, Any]:
        """Execute a controlled attack simulation and record results."""
        result = SimulationEngine.run_simulation(
            scenario_id=scenario_id,
            target_hostname=target_hostname,
            simulated_by=simulated_by
        )
        sim_id = result["simulation_id"]
        self._history[sim_id] = result

        # Database persistence (non-blocking)
        if is_database_online():
            try:
                with engine.begin() as conn:
                    conn.execute(text("""
                        INSERT INTO attack_simulation_runs
                        (simulation_id, scenario_id, scenario_name, target_hostname, mitre_technique, tactics, simulated_by, status, risk_score, impact_level, predicted_containment_probability, estimated_mttd_seconds, estimated_mttr_seconds, defensive_recommendations, impact_summary)
                        VALUES (:sim_id, :scen_id, :name, :host, :mitre, :tact, :by, 'COMPLETED', :risk, :imp, :prob, :mttd, :mttr, :recs, :sum)
                    """), {
                        "sim_id": sim_id,
                        "scen_id": result["scenario_id"],
                        "name": result["scenario_name"],
                        "host": result["target_hostname"],
                        "mitre": result["mitre_technique"],
                        "tact": result["tactics"],
                        "by": result["simulated_by"],
                        "risk": result["risk_score"],
                        "imp": result["impact_level"],
                        "prob": result["predicted_containment_probability"],
                        "mttd": result["estimated_mttd_seconds"],
                        "mttr": result["estimated_mttr_seconds"],
                        "recs": json.dumps(result["defensive_recommendations"]),
                        "sum": result["impact_summary"]
                    })

                    for st in result.get("steps", []):
                        conn.execute(text("""
                            INSERT INTO simulation_step_logs
                            (simulation_id, step_number, step_name, mitre_subtechnique, action_type, observed_telemetry, detection_status, details)
                            VALUES (:sim_id, :num, :name, :sub, :action, :obs, :status, :det)
                        """), {
                            "sim_id": sim_id,
                            "num": st["step_number"],
                            "name": st["step_name"],
                            "sub": st["mitre_subtechnique"],
                            "action": st["action_type"],
                            "obs": st["observed_telemetry"],
                            "status": st["detection_status"],
                            "det": st["details"]
                        })
            except Exception:
                pass

        return result

    def list_history(
        self,
        target_hostname: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """List historical simulation exercises."""
        history = list(self._history.values())
        if target_hostname:
            history = [h for h in history if h.get("target_hostname") == target_hostname]
        history = sorted(history, key=lambda x: str(x.get("started_at")), reverse=True)
        return history[:limit]

    def get_simulation(self, simulation_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve full details and step log for a single simulation run."""
        return self._history.get(simulation_id)

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate metrics for attack simulations."""
        runs = list(self._history.values())
        total_runs = len(runs)
        critical_runs = sum(1 for r in runs if r.get("impact_level") == "CRITICAL")
        avg_risk = round(sum(r.get("risk_score", 0) for r in runs) / total_runs, 1) if total_runs else 0.0
        avg_containment = round(sum(r.get("predicted_containment_probability", 0.0) for r in runs) / total_runs, 1) if total_runs else 0.0

        return {
            "total_simulations_conducted": total_runs,
            "critical_scenario_runs": critical_runs,
            "average_risk_score": avg_risk,
            "average_containment_rate": avg_containment,
            "available_scenarios_count": len(SCENARIO_CATALOG)
        }


# Singleton simulation service
simulation_service = SimulationService()
