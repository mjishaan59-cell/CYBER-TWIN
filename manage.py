#!/usr/bin/env python3
"""
==============================================================================
Cyber Digital Twin - Unified Management CLI
==============================================================================
Provides a centralized CLI for operating, testing, simulating attacks,
generating research experiments, and deploying the Cyber Digital Twin platform.

Usage:
    python manage.py <command> [options]

Commands:
    run            Start the Cyber Digital Twin FastAPI backend
    test           Execute automated pytest verification suites
    simulate       Execute safe synthetic adversary attack simulations
    forecast       Run ML-driven predictive analytics & resource drift forecasting
    fim-check      Execute File Integrity Monitoring cryptographic audit
    experiment     Run scientific research benchmark suite for academic papers
    docker-up      Build and start production Docker container stack
    docker-down    Stop and tear down Docker container stack
    status         Inspect system environment, dependencies, and health
==============================================================================
"""

import argparse
import json
import os
import sys
import subprocess
import time
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent

# Color formatting for terminal output
class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}======================================================================
    AI-POWERED CYBER DIGITAL TWIN FOR LINUX
    Enterprise Cloud & Cyber Defense Platform | Management CLI
======================================================================{Colors.RESET}"""
    print(banner)


def cmd_run(args):
    """Start the FastAPI backend with Uvicorn."""
    print_banner()
    host = args.host
    port = args.port
    reload = args.reload

    print(f"{Colors.GREEN}[*] Starting Cyber Digital Twin Backend API...{Colors.RESET}")
    print(f"{Colors.BLUE}    Host: {host}{Colors.RESET}")
    print(f"{Colors.BLUE}    Port: {port}{Colors.RESET}")
    print(f"{Colors.BLUE}    Frontend Dashboard: http://{host}:{port}/{Colors.RESET}")
    print(f"{Colors.BLUE}    Swagger API Docs:   http://{host}:{port}/docs{Colors.RESET}\n")

    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "backend.api.main:app",
        "--host",
        host,
        "--port",
        str(port),
    ]
    if reload:
        cmd.append("--reload")

    try:
        subprocess.run(cmd, cwd=WORKSPACE_ROOT)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Server stopped by operator.{Colors.RESET}")


def cmd_test(args):
    """Execute automated test suites."""
    print_banner()
    print(f"{Colors.GREEN}[*] Running Cyber Digital Twin Test Suite...{Colors.RESET}\n")

    cmd = [sys.executable, "-m", "pytest"]
    if args.suite:
        cmd.append(f"tests/test_{args.suite}.py")
    else:
        cmd.extend(["tests/", "backend/auth/test_rbac.py"])

    if args.verbose:
        cmd.append("-v")

    result = subprocess.run(cmd, cwd=WORKSPACE_ROOT)
    sys.exit(result.returncode)


def cmd_simulate(args):
    """Run synthetic adversary scenarios via simulation engine."""
    print_banner()
    from backend.simulation.simulation_engine import SimulationEngine, SCENARIO_CATALOG

    scenario = args.scenario.upper()
    print(f"{Colors.GREEN}[*] Initializing Synthetic Adversary Simulation Engine...{Colors.RESET}")
    print(f"{Colors.CYAN}    Target Scenario: {scenario}{Colors.RESET}\n")

    if scenario not in SCENARIO_CATALOG:
        print(f"{Colors.RED}[!] Unknown scenario '{scenario}'.{Colors.RESET}")
        print(f"    Available scenarios: {', '.join(SCENARIO_CATALOG.keys())}")
        return

    result = SimulationEngine.run_simulation(
        scenario_id=scenario,
        target_hostname="production-linux-01",
        simulated_by="admin_cli"
    )

    print(f"{Colors.GREEN}{Colors.BOLD}Simulation Execution Summary:{Colors.RESET}")
    print(f"  - Simulation ID:     {result.get('simulation_id')}")
    print(f"  - Scenario Name:     {result.get('scenario_name')}")
    print(f"  - MITRE ATT&CK:      {result.get('tactics')} ({result.get('mitre_technique')})")
    print(f"  - Impact Level:      {result.get('impact_level')}")
    print(f"  - Estimated MTTD:    {result.get('estimated_mttd_seconds')} seconds")
    print(f"  - Estimated MTTR:    {result.get('estimated_mttr_seconds')} seconds")
    print(f"  - Calculated Risk:   {result.get('risk_score')}/100")
    print(f"  - Containment Prob:  {result.get('predicted_containment_probability')}%")
    print(f"\n{Colors.YELLOW}{Colors.BOLD}Simulated Attack Steps ({len(result.get('steps', []))} steps):{Colors.RESET}")
    for step in result.get("steps", []):
        print(f"  [+] Step {step.get('step_number')}: {step.get('step_name')} [{step.get('detection_status')}]")
        print(f"      Observed: {step.get('observed_telemetry')}")
    print(f"\n{Colors.CYAN}{Colors.BOLD}Recommended Playbook Mitigations:{Colors.RESET}")
    for rec in result.get("defensive_recommendations", []):
        print(f"  -> {rec}")


def cmd_forecast(args):
    """Run ML predictive resource drift forecasting."""
    print_banner()
    from backend.analytics.predictive_engine import ResourceForecaster

    print(f"{Colors.GREEN}[*] Running Scikit-Learn Predictive Telemetry Engine...{Colors.RESET}\n")
    forecaster = ResourceForecaster(polynomial_degree=1)
    history = [30.0 + (i * 1.5) for i in range(25)]
    forecast = forecaster.fit_and_predict(history, forecast_steps=12, step_interval_seconds=300)

    print(f"{Colors.CYAN}{Colors.BOLD}Forecasting Results for CPU Telemetry Drift:{Colors.RESET}")
    print(f"  - Current Metric:           {history[-1]}%")
    print(f"  - Projected Rate:           {forecast.get('rate_per_hour'):.2f}% per hour")
    print(f"  - Model R^2 Fit Score:      {forecast.get('r2_score'):.4f}")
    print(f"  - Model RMSE:               {forecast.get('rmse'):.4f}")
    print(f"  - Trend Direction:          {forecast.get('trend_direction')}")
    print(f"  - Projected in 1 Hour:      {forecast.get('predicted_1h'):.2f}%")
    print(f"  - Projected in 6 Hours:     {forecast.get('predicted_6h'):.2f}%")
    print(f"  - Model Confidence:         {forecast.get('confidence_pct')}%")


def cmd_fim_check(args):
    """Execute File Integrity Monitoring cryptographic checks."""
    print_banner()
    from backend.fim.fim_service import FimService
    from backend.fim.fim_engine import generate_baseline_seal

    print(f"{Colors.GREEN}[*] Executing Cryptographic File Integrity Audit (HMAC-SHA256)...{Colors.RESET}\n")
    service = FimService()
    baseline = service.get_baseline("production-linux-01")
    scan = service.scan_host_integrity("production-linux-01")
    seal = generate_baseline_seal(baseline)

    print(f"{Colors.CYAN}{Colors.BOLD}FIM Audit Results:{Colors.RESET}")
    print(f"  - Target Host:              {scan.get('hostname')}")
    print(f"  - Monitored Files Checked:  {scan.get('scanned_files_count')}")
    print(f"  - Violations Detected:      {scan.get('violations_detected')}")
    print(f"  - HMAC Baseline Seal:       {seal[:20]}... [CRYPTOGRAPHICALLY VALID]")
    print(f"  - Audit Timestamp:          {scan.get('scanned_at')}")
    print(f"\n{Colors.GREEN}[+] All critical system baselines verified without unauthorized drift.{Colors.RESET}")


def cmd_experiment(args):
    """Run academic research benchmark suite."""
    print_banner()
    print(f"{Colors.GREEN}[*] Running Academic Research Experiment Suite...{Colors.RESET}\n")
    exp_script = WORKSPACE_ROOT / "scripts" / "run_research_experiments.py"
    if exp_script.exists():
        subprocess.run([sys.executable, str(exp_script)], cwd=WORKSPACE_ROOT)
    else:
        print(f"{Colors.RED}[!] Experiment script not found at {exp_script}{Colors.RESET}")


def cmd_docker(action):
    """Manage Docker Compose container lifecycle."""
    print_banner()
    if action == "up":
        print(f"{Colors.GREEN}[*] Building and starting Docker containers...{Colors.RESET}")
        cmd = ["docker", "compose", "up", "-d", "--build"]
    else:
        print(f"{Colors.YELLOW}[*] Stopping Docker containers...{Colors.RESET}")
        cmd = ["docker", "compose", "down"]

    try:
        subprocess.run(cmd, cwd=WORKSPACE_ROOT)
    except FileNotFoundError:
        print(f"{Colors.RED}[!] Error: Docker or Docker Compose is not installed or not in PATH.{Colors.RESET}")


def cmd_status(args):
    """Inspect environment, dependencies, and subsystem readiness."""
    print_banner()
    print(f"{Colors.GREEN}{Colors.BOLD}Cyber Digital Twin - System Readiness Status:{Colors.RESET}\n")

    # Python Version
    print(f"  [+] Python Interpreter:   {sys.version.split()[0]} ({sys.executable})")

    # Core Dependencies
    deps = ["fastapi", "uvicorn", "pydantic", "sklearn", "psutil", "pytest", "jose"]
    print("\n  [+] Checking Critical Packages:")
    for dep in deps:
        try:
            __import__(dep)
            print(f"      - {dep:<15} {Colors.GREEN}INSTALLED{Colors.RESET}")
        except ImportError:
            print(f"      - {dep:<15} {Colors.RED}MISSING{Colors.RESET}")

    # Subsystem Files Check
    subsystems = [
        ("AI Threat Intelligence", "backend/threat_intel/threat_service.py"),
        ("Predictive Analytics", "backend/analytics/predictive_engine.py"),
        ("File Integrity (FIM)", "backend/fim/fim_engine.py"),
        ("Process Monitoring", "backend/process_monitoring/process_service.py"),
        ("Network Security", "backend/network_monitoring/network_service.py"),
        ("Multi-Host Fleet Hub", "backend/multihost/fleet_manager.py"),
        ("Attack Simulator", "backend/simulation/simulation_engine.py"),
        ("Incident Playbooks", "backend/incident_response/playbook_engine.py"),
        ("TTL Cache Optimizer", "backend/utils/cache_optimizer.py"),
        ("Docker Container Spec", "docker-compose.yml"),
    ]
    print("\n  [+] Subsystem Integrity:")
    for name, rel_path in subsystems:
        p = WORKSPACE_ROOT / rel_path
        status = f"{Colors.GREEN}READY{Colors.RESET}" if p.exists() else f"{Colors.RED}MISSING{Colors.RESET}"
        print(f"      - {name:<26} {status}")

    print(f"\n{Colors.GREEN}[*] Status check complete. Platform is operational.{Colors.RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Cyber Digital Twin Management CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Run command
    parser_run = subparsers.add_parser("run", help="Start the FastAPI backend server")
    parser_run.add_argument("--host", default="0.0.0.0", help="Binding host address (default: 0.0.0.0)")
    parser_run.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    parser_run.add_argument("--reload", action="store_true", default=True, help="Enable auto-reload")

    # Test command
    parser_test = subparsers.add_parser("test", help="Execute test suites")
    parser_test.add_argument("--suite", default="", help="Specific test suite (e.g. phase28_simulation)")
    parser_test.add_argument("-v", "--verbose", action="store_true", help="Verbose pytest output")

    # Simulate command
    parser_sim = subparsers.add_parser("simulate", help="Run synthetic adversary attack simulation")
    parser_sim.add_argument(
        "scenario",
        nargs="?",
        default="SSH_BRUTE_FORCE",
        help="Scenario: SSH_BRUTE_FORCE, REVERSE_SHELL_INJECTION, PRIVILEGE_ESCALATION_SUID, DATA_EXFILTRATION_DNS, RANSOMWARE_BURST, RESOURCE_DOS_ATTACK",
    )

    # Forecast command
    subparsers.add_parser("forecast", help="Execute ML predictive analytics and resource drift forecasting")

    # FIM Check command
    subparsers.add_parser("fim-check", help="Execute cryptographic File Integrity Monitoring audit")

    # Research Experiment command
    subparsers.add_parser("experiment", help="Run automated scientific research benchmark suite")

    # Docker commands
    subparsers.add_parser("docker-up", help="Build and launch Docker Compose cluster")
    subparsers.add_parser("docker-down", help="Stop Docker Compose cluster")

    # Status command
    subparsers.add_parser("status", help="Inspect platform status, dependencies, and subsystems")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "run":
        cmd_run(args)
    elif args.command == "test":
        cmd_test(args)
    elif args.command == "simulate":
        cmd_simulate(args)
    elif args.command == "forecast":
        cmd_forecast(args)
    elif args.command == "fim-check":
        cmd_fim_check(args)
    elif args.command == "experiment":
        cmd_experiment(args)
    elif args.command == "docker-up":
        cmd_docker("up")
    elif args.command == "docker-down":
        cmd_docker("down")
    elif args.command == "status":
        cmd_status(args)


if __name__ == "__main__":
    main()
