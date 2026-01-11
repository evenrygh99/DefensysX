# @even rygh
"""FastAPI routes for attack simulation endpoints.

This module supports two flows:
- simulate only (returns generated logs)
- simulate + analyze (creates BYOL sessions + alerts)

All simulations are demo-safe: they generate logs only.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from typing import Any, Dict, List, Optional
import logging

from config import settings
from rate_limiter import RateLimiter

from attack_simulator import (
    AttackSimulation,
    SimulationResult,
    simulate_attack,
    ATTACK_GENERATORS
)

from byol_analysis import analyze_log_bytes

_simulation_rate_limiter = RateLimiter(
    requests=settings.simulation_rate_limit_requests,
    period=settings.simulation_rate_limit_period_seconds,
)


def _client_ip(request: Request) -> str:
    # Prefer proxy header when running behind Caddy/reverse proxy.
    xff = request.headers.get("x-forwarded-for")
    if xff:
        # Take left-most IP.
        ip = xff.split(",")[0].strip()
        if ip:
            return ip
    return request.client.host if request.client else "unknown"


async def _require_simulation_access(request: Request) -> None:
    # Optional token gate
    if settings.simulation_token:
        token = request.headers.get("x-simulation-token")
        if token != settings.simulation_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Simulation access denied",
            )

    # Rate limit simulation endpoints (prod-on by default; dev/test-off by default).
    rate_limit_enabled = (
        (not settings.debug)
        if settings.simulation_rate_limit_enabled is None
        else bool(settings.simulation_rate_limit_enabled)
    )
    if rate_limit_enabled:
        ip = _client_ip(request)
        if not await _simulation_rate_limiter.is_allowed(ip):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "detail": "Simulation rate limit exceeded. Please try again later.",
                    "retry_after": settings.simulation_rate_limit_period_seconds,
                },
            )


router = APIRouter(
    prefix="/simulate",
    tags=["Attack Simulation"],
    dependencies=[Depends(_require_simulation_access)],
)
logger = logging.getLogger(__name__)


ATTACK_DETAILS: Dict[str, Dict[str, Any]] = {
    "ssh_brute_force": {
        "name": "SSH Brute Force",
        "description": "Simulates multiple failed SSH authentication attempts from a single IP",
        "log_type": "ssh",
        "example_intensity": "medium",
        "typical_duration": 30,
    },
    "web_scan": {
        "name": "Web Vulnerability Scanner",
        "description": "Simulates automated scanning for common web vulnerabilities",
        "log_type": "apache",
        "example_intensity": "medium",
        "typical_duration": 30,
    },
    "sql_injection": {
        "name": "SQL Injection Attempts",
        "description": "Simulates SQL injection attacks on web endpoints",
        "log_type": "apache",
        "example_intensity": "medium",
        "typical_duration": 30,
    },
    "xss_attack": {
        "name": "Cross-Site Scripting (XSS)",
        "description": "Simulates XSS payload injection attempts",
        "log_type": "nginx",
        "example_intensity": "medium",
        "typical_duration": 30,
    },
    "port_scan": {
        "name": "Port Scanning",
        "description": "Simulates network port scanning activity",
        "log_type": "auto",
        "example_intensity": "medium",
        "typical_duration": 20,
    },
    "credential_stuffing": {
        "name": "Credential Stuffing",
        "description": "Simulates automated login attempts from multiple IPs (botnet)",
        "log_type": "nginx",
        "example_intensity": "medium",
        "typical_duration": 40,
    },
}


def _attack_log_type(attack_type: str) -> str:
    details = ATTACK_DETAILS.get(attack_type)
    if not details:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown attack type: {attack_type}. Use /simulate/attacks to see available types.",
        )
    return str(details.get("log_type"))


async def _analyze_simulation_result(
    *,
    result: SimulationResult,
    log_type: str,
    intensity: Optional[str] = None,
    duration_seconds: Optional[int] = None,
    scenario: Optional[str] = None,
    scenario_step: Optional[int] = None,
) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {
        "source": "simulation",
        "simulation": {
            "attack_type": result.attack_type,
            "intensity": intensity,
            "duration_seconds": duration_seconds if duration_seconds is not None else result.duration_seconds,
            "attacker_ips": list(result.attacker_ips),
            "target_hosts": list(result.target_hosts),
        },
    }
    if scenario:
        metadata["simulation"]["scenario"] = scenario
    if scenario_step is not None:
        metadata["simulation"]["scenario_step"] = scenario_step

    return await analyze_log_bytes(
        log_bytes=result.log_content.encode("utf-8", errors="replace"),
        log_type=log_type,
        source_metadata=metadata,
    )


@router.get("/attacks")
async def list_attack_types():
    """
    List available attack simulation types.
    
    Returns available attack simulations with descriptions.
    """
    return {
        "available_attacks": list(ATTACK_DETAILS.keys()),
        "details": ATTACK_DETAILS,
        "intensity_levels": ["low", "medium", "high"],
        "duration_range": {"min": 10, "max": 300, "default": 30}
    }


@router.post("/attack", response_model=SimulationResult)
async def run_attack_simulation(simulation: AttackSimulation):
    """
    Run an attack simulation and generate logs.
    
    **DEMO ONLY**: This generates log data only, not actual attacks.
    
    Args:
        simulation: Attack configuration (type, intensity, duration)
    
    Returns:
        Simulation result with generated logs
        
    Example:
        ```json
        {
            "attack_type": "ssh_brute_force",
            "intensity": "medium",
            "duration_seconds": 30,
            "target_host": "auto"
        }
        ```
    """
    try:
        logger.info(
            f"Starting attack simulation: type={simulation.attack_type}, "
            f"intensity={simulation.intensity}, duration={simulation.duration_seconds}s"
        )
        
        result = simulate_attack(simulation)
        
        logger.info(
            f"Simulation complete: {result.log_lines_generated} log lines generated"
        )
        
        return result
        
    except ValueError as e:
        logger.error(f"Invalid simulation request: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Simulation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Attack simulation failed"
        )


@router.post("/attack/quick/{attack_type}")
async def quick_attack_simulation(attack_type: str, intensity: str = "medium"):
    """
    Quick attack simulation with default parameters.
    
    **DEMO ONLY**: Generates logs, not actual attacks.
    
    Args:
        attack_type: Type of attack to simulate
        intensity: Attack intensity (low/medium/high)
    
    Returns:
        Simulation result with generated logs
    """
    if attack_type not in ATTACK_GENERATORS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown attack type: {attack_type}. Use /simulate/attacks to see available types.",
        )
    
    simulation = AttackSimulation(
        attack_type=attack_type,  # type: ignore[arg-type]
        intensity=intensity,  # type: ignore[arg-type]
        duration_seconds=30,
        target_host="auto",
    )
    
    return await run_attack_simulation(simulation)


@router.post("/attack/quick/{attack_type}/analyze")
async def quick_attack_simulation_analyze(attack_type: str, intensity: str = "medium") -> Dict[str, Any]:
    """Quick simulation + detection analysis.

    Returns both the generated logs and a BYOL session_id containing parsed events + alerts.
    """
    if attack_type not in ATTACK_GENERATORS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown attack type: {attack_type}. Use /simulate/attacks to see available types.",
        )

    simulation = AttackSimulation(
        attack_type=attack_type,  # type: ignore[arg-type]
        intensity=intensity,  # type: ignore[arg-type]
        duration_seconds=30,
        target_host="auto",
    )

    try:
        result = simulate_attack(simulation)
        analysis = await _analyze_simulation_result(
            result=result,
            log_type=_attack_log_type(attack_type),
            intensity=intensity,
            duration_seconds=simulation.duration_seconds,
        )
        return {
            "mode": "simulate+analyze",
            "simulation": result,
            "analysis": analysis,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Simulation+analysis failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Attack simulation analysis failed",
        )


@router.post("/scenario/{scenario_name}")
async def run_attack_scenario(scenario_name: str):
    """
    Run a pre-defined attack scenario with multiple attack types.
    
    **DEMO ONLY**: Generates logs, not actual attacks.
    
    Available scenarios:
    - **apt_attack**: Advanced Persistent Threat simulation
    - **web_assault**: Comprehensive web application attack
    - **network_recon**: Network reconnaissance and scanning
    - **data_exfiltration**: Data theft attempt simulation
    
    Args:
        scenario_name: Name of the scenario to run
    
    Returns:
        Combined results from all attacks in the scenario
    """
    scenarios = {
        "apt_attack": [
            AttackSimulation(attack_type="port_scan", intensity="low", duration_seconds=20, target_host="auto"),
            AttackSimulation(attack_type="ssh_brute_force", intensity="medium", duration_seconds=30, target_host="auto"),
            AttackSimulation(attack_type="credential_stuffing", intensity="low", duration_seconds=40, target_host="auto"),
        ],
        "web_assault": [
            AttackSimulation(attack_type="web_scan", intensity="high", duration_seconds=30, target_host="auto"),
            AttackSimulation(attack_type="sql_injection", intensity="medium", duration_seconds=30, target_host="auto"),
            AttackSimulation(attack_type="xss_attack", intensity="medium", duration_seconds=30, target_host="auto"),
        ],
        "network_recon": [
            AttackSimulation(attack_type="port_scan", intensity="high", duration_seconds=30, target_host="auto"),
            AttackSimulation(attack_type="web_scan", intensity="low", duration_seconds=20, target_host="auto"),
        ],
        "data_exfiltration": [
            AttackSimulation(attack_type="sql_injection", intensity="high", duration_seconds=40, target_host="auto"),
            AttackSimulation(attack_type="credential_stuffing", intensity="medium", duration_seconds=30, target_host="auto"),
        ]
    }
    
    if scenario_name not in scenarios:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown scenario: {scenario_name}. Available: {list(scenarios.keys())}"
        )
    
    logger.info(f"Running attack scenario: {scenario_name}")
    
    simulation_results: List[SimulationResult] = []
    results: List[Dict[str, Any]] = []
    total_logs = 0
    all_attacker_ips = set()
    all_targets = set()

    for simulation in scenarios[scenario_name]:
        result = simulate_attack(simulation)
        simulation_results.append(result)
        results.append({"attack_type": result.attack_type, "log_lines": result.log_lines_generated})
        total_logs += result.log_lines_generated
        all_attacker_ips.update(result.attacker_ips)
        all_targets.update(result.target_hosts)

    combined_logs = "\n\n".join([r.log_content for r in simulation_results])
    
    logger.info(f"Scenario complete: {len(results)} attacks, {total_logs} total log lines")
    
    return {
        "scenario": scenario_name,
        "attacks_executed": results,
        "total_log_lines": total_logs,
        "attacker_ips": list(all_attacker_ips),
        "target_hosts": list(all_targets),
        "combined_logs": combined_logs
    }


@router.post("/scenario/{scenario_name}/analyze")
async def run_attack_scenario_analyze(scenario_name: str) -> Dict[str, Any]:
    """Run a pre-defined scenario and analyze each step into BYOL sessions."""
    scenarios = {
        "apt_attack": [
            AttackSimulation(attack_type="port_scan", intensity="low", duration_seconds=20, target_host="auto"),
            AttackSimulation(attack_type="ssh_brute_force", intensity="medium", duration_seconds=30, target_host="auto"),
            AttackSimulation(attack_type="credential_stuffing", intensity="low", duration_seconds=40, target_host="auto"),
        ],
        "web_assault": [
            AttackSimulation(attack_type="web_scan", intensity="high", duration_seconds=30, target_host="auto"),
            AttackSimulation(attack_type="sql_injection", intensity="medium", duration_seconds=30, target_host="auto"),
            AttackSimulation(attack_type="xss_attack", intensity="medium", duration_seconds=30, target_host="auto"),
        ],
        "network_recon": [
            AttackSimulation(attack_type="port_scan", intensity="high", duration_seconds=30, target_host="auto"),
            AttackSimulation(attack_type="web_scan", intensity="low", duration_seconds=20, target_host="auto"),
        ],
        "data_exfiltration": [
            AttackSimulation(attack_type="sql_injection", intensity="high", duration_seconds=40, target_host="auto"),
            AttackSimulation(attack_type="credential_stuffing", intensity="medium", duration_seconds=30, target_host="auto"),
        ],
    }

    if scenario_name not in scenarios:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown scenario: {scenario_name}. Available: {list(scenarios.keys())}",
        )

    logger.info(f"Running attack scenario (analyze): {scenario_name}")

    steps: List[Dict[str, Any]] = []
    all_attacker_ips = set()
    all_targets = set()
    total_logs = 0

    for idx, simulation in enumerate(scenarios[scenario_name], start=1):
        result = simulate_attack(simulation)
        total_logs += result.log_lines_generated
        all_attacker_ips.update(result.attacker_ips)
        all_targets.update(result.target_hosts)

        attack_type = result.attack_type
        analysis = await _analyze_simulation_result(
            result=result,
            log_type=_attack_log_type(attack_type),
            intensity=simulation.intensity,
            duration_seconds=simulation.duration_seconds,
            scenario=scenario_name,
            scenario_step=idx,
        )

        steps.append(
            {
                "attack_type": attack_type,
                "log_type": _attack_log_type(attack_type),
                "simulation": result,
                "analysis": analysis,
            }
        )

    return {
        "mode": "scenario+analyze",
        "scenario": scenario_name,
        "steps": steps,
        "total_log_lines": total_logs,
        "attacker_ips": list(all_attacker_ips),
        "target_hosts": list(all_targets),
    }


@router.get("/info")
async def simulation_info():
    """
    Get information about attack simulation capabilities.
    
    Returns:
        Information about simulation features and safety measures
    """
    return {
        "description": "Safe attack simulation for SOC demonstrations",
        "safety_features": [
            "Generates logs only - no actual network traffic",
            "No real vulnerabilities exploited",
            "Isolated to demo environment",
            "Rate limited and time-bounded",
            "Read-only operations"
        ],
        "capabilities": {
            "attack_types": len(ATTACK_GENERATORS),
            "intensity_levels": 3,
            "max_duration_seconds": 300,
            "scenarios": 4
        },
        "use_cases": [
            "SOC analyst training",
            "Detection rule testing",
            "Alert system validation",
            "Dashboard demonstrations",
            "Security awareness training"
        ],
        "warning": "FOR DEMO/TRAINING USE ONLY - Not for production security testing"
    }
