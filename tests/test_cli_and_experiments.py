"""
Tests for Unified Management CLI and Scientific Research Experimentation Suite.
"""

from pathlib import Path
import pytest
from backend.simulation.simulation_engine import SimulationEngine
from backend.analytics.predictive_engine import ResourceForecaster
from backend.utils.cache_optimizer import TTLCache
from scripts.run_research_experiments import (
    run_attack_simulation_experiments,
    run_predictive_ml_experiments,
    run_cache_latency_benchmarks
)

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent


def test_launcher_scripts_exist():
    """Verify one-click start scripts exist."""
    bat_file = WORKSPACE_ROOT / "start.bat"
    sh_file = WORKSPACE_ROOT / "start.sh"
    manage_file = WORKSPACE_ROOT / "manage.py"

    assert bat_file.exists(), "start.bat must exist"
    assert sh_file.exists(), "start.sh must exist"
    assert manage_file.exists(), "manage.py must exist"

    sh_content = sh_file.read_text(encoding="utf-8")
    assert "#!/usr/bin/env bash" in sh_content
    assert "python manage.py run" in sh_content


def test_adversary_simulation_experiments():
    """Verify research experiments execute adversary simulations and compute metrics."""
    res = run_attack_simulation_experiments(iterations=1)
    assert "SSH_BRUTE_FORCE" in res
    assert "REVERSE_SHELL_INJECTION" in res
    assert "RANSOMWARE_BURST" in res

    ssh_res = res["SSH_BRUTE_FORCE"]
    assert ssh_res["avg_mttd_seconds"] > 0
    assert ssh_res["avg_mttr_seconds"] > 0
    assert ssh_res["mttr_reduction_pct"] > 0


def test_predictive_ml_experiments():
    """Verify research experiments evaluate machine learning telemetry forecasting."""
    res = run_predictive_ml_experiments()
    assert "Nominal Steady State" in res
    assert "Rapid Resource Surge (Exhaustion)" in res
    surge = res["Rapid Resource Surge (Exhaustion)"]
    assert surge["r2_goodness_of_fit"] >= 0.9
    assert surge["trend_direction"] == "RISING"


def test_cache_latency_benchmarks():
    """Verify research cache benchmarks evaluate throughput and hit rates."""
    res = run_cache_latency_benchmarks(sample_size=100)
    assert res["operations_evaluated"] == 100
    assert res["throughput_speedup_factor"] > 0
    assert res["cache_hit_rate_pct"] == 100.0
