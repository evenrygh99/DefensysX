# @even rygh
"""
Safe Attack Simulation for SOC Demo Environment.
Generates realistic attack logs without performing actual attacks.
"""
from datetime import datetime
from typing import List, Dict, Literal
import random
from pydantic import BaseModel, Field

# Attack simulation configurations
ATTACKER_IPS = [
    "203.0.113.42",      # Scanning bot
    "198.51.100.88",     # Brute force attacker
    "192.0.2.15",        # Suspicious foreign IP
    "203.0.113.23",      # Tor exit node (example)
    "198.51.100.61",     # Known malicious IP (example)
    "192.0.2.188"        # APT infrastructure (example)
]

TARGET_HOSTS = [
    "web-server-1", "web-server-2", "api-gateway",
    "ssh-bastion", "mail-server", "database-proxy"
]

COMMON_USERNAMES = [
    "admin", "root", "test", "user", "administrator",
    "guest", "oracle", "postgres", "mysql", "jenkins"
]

WEB_ATTACK_PAYLOADS = [
    "' OR '1'='1",
    "1' UNION SELECT * FROM users--",
    "<script>alert('XSS')</script>",
    "../../../etc/passwd",
    "'; DROP TABLE users; --",
    "<img src=x onerror=alert(1)>",
    "../../windows/system32/config/sam",
    "${jndi:ldap://localhost/a}",  # Log4Shell (safe/local)
    "() { :; }; /bin/bash -c 'cat /etc/passwd'",  # Shellshock
]

SCAN_PATHS = [
    "/.env", "/.git/config", "/admin", "/wp-admin",
    "/phpmyadmin", "/config.php", "/backup.sql",
    "/shell.php", "/.aws/credentials", "/api/v1/admin"
]


class AttackSimulation(BaseModel):
    """Attack simulation request model."""
    attack_type: Literal["ssh_brute_force", "web_scan", "sql_injection", "xss_attack", "port_scan", "credential_stuffing"]
    intensity: Literal["low", "medium", "high"] = Field(default="medium")
    duration_seconds: int = Field(default=30, ge=10, le=300)
    target_host: str = Field(default="auto")


class SimulationResult(BaseModel):
    """Attack simulation result."""
    attack_type: str
    log_lines_generated: int
    duration_seconds: int
    attacker_ips: List[str]
    target_hosts: List[str]
    log_content: str


def generate_timestamp() -> str:
    """Generate current timestamp in common log format."""
    return datetime.now().strftime("%b %d %H:%M:%S")


def generate_ssh_brute_force(intensity: str = "medium", duration: int = 30, target: str = "auto") -> SimulationResult:
    """
    Simulate SSH brute force attack.
    Generates failed SSH authentication attempts from multiple IPs.
    """
    intensity_map = {"low": 10, "medium": 30, "high": 100}
    attempts_per_second = intensity_map[intensity]
    total_attempts = attempts_per_second * min(duration, 60)  # Cap at 60 seconds for safety
    
    attacker_ip = random.choice(ATTACKER_IPS)
    target_host = TARGET_HOSTS[3] if target == "auto" else target  # ssh-bastion
    
    logs = []
    for i in range(total_attempts):
        timestamp = generate_timestamp()
        username = random.choice(COMMON_USERNAMES)
        port = random.randint(40000, 65000)
        pid = random.randint(1000, 9999)
        
        # Generate failed authentication attempts
        log_entry = (
            f"{timestamp} {target_host} sshd[{pid}]: Failed password for "
            f"{username} from {attacker_ip} port {port} ssh2"
        )
        logs.append(log_entry)
        
        # Occasionally add "Invalid user" attempts
        if i % 5 == 0:
            logs.append(
                f"{timestamp} {target_host} sshd[{pid}]: Invalid user "
                f"{username} from {attacker_ip} port {port}"
            )
    
    log_content = "\n".join(logs)
    
    return SimulationResult(
        attack_type="ssh_brute_force",
        log_lines_generated=len(logs),
        duration_seconds=duration,
        attacker_ips=[attacker_ip],
        target_hosts=[target_host],
        log_content=log_content
    )


def generate_web_scan(intensity: str = "medium", duration: int = 30, target: str = "auto") -> SimulationResult:
    """
    Simulate web vulnerability scanner.
    Generates HTTP requests scanning for common vulnerabilities.
    """
    intensity_map = {"low": 5, "medium": 15, "high": 50}
    requests_per_second = intensity_map[intensity]
    total_requests = requests_per_second * min(duration, 60)
    
    scanner_ip = random.choice(ATTACKER_IPS)
    target_host = TARGET_HOSTS[0] if target == "auto" else target
    scanner_ua = random.choice([
        "Nikto/2.1.6",
        "sqlmap/1.6",
        "Nmap Scripting Engine",
        "python-requests/2.28.0"
    ])
    
    logs = []
    for i in range(total_requests):
        timestamp = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
        path = random.choice(SCAN_PATHS)
        status = random.choice([404, 403, 400, 404, 404])  # Mostly 404s
        bytes_sent = random.randint(200, 800)
        
        # Apache/Nginx combined log format
        log_entry = (
            f'{scanner_ip} - - [{timestamp}] "GET {path} HTTP/1.1" '
            f'{status} {bytes_sent} "-" "{scanner_ua}"'
        )
        logs.append(log_entry)
    
    log_content = "\n".join(logs)
    
    return SimulationResult(
        attack_type="web_scan",
        log_lines_generated=len(logs),
        duration_seconds=duration,
        attacker_ips=[scanner_ip],
        target_hosts=[target_host],
        log_content=log_content
    )


def generate_sql_injection(intensity: str = "medium", duration: int = 30, target: str = "auto") -> SimulationResult:
    """
    Simulate SQL injection attack attempts.
    Generates HTTP requests with SQL injection payloads.
    """
    intensity_map = {"low": 5, "medium": 10, "high": 30}
    attempts_per_second = intensity_map[intensity]
    total_attempts = attempts_per_second * min(duration, 60)
    
    attacker_ip = random.choice(ATTACKER_IPS)
    target_host = TARGET_HOSTS[0] if target == "auto" else target
    
    logs = []
    for i in range(total_attempts):
        timestamp = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
        payload = random.choice([p for p in WEB_ATTACK_PAYLOADS if "'" in p or "UNION" in p])
        endpoint = random.choice(["/login", "/search", "/api/users", "/products"])
        status = random.choice([400, 403, 500])
        bytes_sent = random.randint(300, 1500)
        
        # URL encode some characters for realism
        safe_payload = payload.replace(" ", "%20").replace("'", "%27")
        
        log_entry = (
            f'{attacker_ip} - - [{timestamp}] "GET {endpoint}?id={safe_payload} HTTP/1.1" '
            f'{status} {bytes_sent} "-" "sqlmap/1.6"'
        )
        logs.append(log_entry)
    
    log_content = "\n".join(logs)
    
    return SimulationResult(
        attack_type="sql_injection",
        log_lines_generated=len(logs),
        duration_seconds=duration,
        attacker_ips=[attacker_ip],
        target_hosts=[target_host],
        log_content=log_content
    )


def generate_xss_attack(intensity: str = "medium", duration: int = 30, target: str = "auto") -> SimulationResult:
    """
    Simulate XSS (Cross-Site Scripting) attack attempts.
    Generates HTTP requests with XSS payloads.
    """
    intensity_map = {"low": 5, "medium": 10, "high": 25}
    attempts_per_second = intensity_map[intensity]
    total_attempts = attempts_per_second * min(duration, 60)
    
    attacker_ip = random.choice(ATTACKER_IPS)
    target_host = TARGET_HOSTS[0] if target == "auto" else target
    
    logs = []
    for i in range(total_attempts):
        timestamp = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
        payload = random.choice([p for p in WEB_ATTACK_PAYLOADS if "script" in p or "onerror" in p])
        endpoint = random.choice(["/search", "/comment", "/feedback", "/profile"])
        status = random.choice([400, 403, 200])  # Sometimes accepted
        bytes_sent = random.randint(500, 2000)
        
        # URL encode payload
        safe_payload = payload.replace("<", "%3C").replace(">", "%3E").replace(" ", "%20")
        
        log_entry = (
            f'{attacker_ip} - - [{timestamp}] "GET {endpoint}?q={safe_payload} HTTP/1.1" '
            f'{status} {bytes_sent} "-" "Mozilla/5.0"'
        )
        logs.append(log_entry)
    
    log_content = "\n".join(logs)
    
    return SimulationResult(
        attack_type="xss_attack",
        log_lines_generated=len(logs),
        duration_seconds=duration,
        attacker_ips=[attacker_ip],
        target_hosts=[target_host],
        log_content=log_content
    )


def generate_port_scan(intensity: str = "medium", duration: int = 30, target: str = "auto") -> SimulationResult:
    """
    Simulate port scanning activity.
    Generates network connection logs showing port scan patterns.
    """
    intensity_map = {"low": 10, "medium": 50, "high": 200}
    ports_scanned = intensity_map[intensity]
    
    scanner_ip = random.choice(ATTACKER_IPS)
    target_host = TARGET_HOSTS[2] if target == "auto" else target
    
    logs = []
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
    
    # Scan common ports plus random ports (if needed)
    if ports_scanned <= len(common_ports):
        all_ports = common_ports[:ports_scanned]
    else:
        # Need more ports beyond common ones
        additional_ports_needed = ports_scanned - len(common_ports)
        all_ports = common_ports + random.sample(range(1, 65535), additional_ports_needed)
    
    for port in all_ports[:ports_scanned]:
        timestamp = generate_timestamp()
        
        # Generate firewall/connection log
        log_entry = (
            f"{timestamp} {target_host} kernel: [FIREWALL] SYN scan detected: "
            f"{scanner_ip}:{random.randint(40000, 65000)} -> {target_host}:{port} (TCP)"
        )
        logs.append(log_entry)
    
    log_content = "\n".join(logs)
    
    return SimulationResult(
        attack_type="port_scan",
        log_lines_generated=len(logs),
        duration_seconds=duration,
        attacker_ips=[scanner_ip],
        target_hosts=[target_host],
        log_content=log_content
    )


def generate_credential_stuffing(intensity: str = "medium", duration: int = 30, target: str = "auto") -> SimulationResult:
    """
    Simulate credential stuffing attack.
    Generates login attempts with various username/password combinations.
    """
    intensity_map = {"low": 5, "medium": 15, "high": 50}
    attempts_per_second = intensity_map[intensity]
    total_attempts = attempts_per_second * min(duration, 60)
    
    # Use multiple attacker IPs (botnet simulation)
    attacker_ips = random.sample(ATTACKER_IPS, min(3, len(ATTACKER_IPS)))
    target_host = TARGET_HOSTS[0] if target == "auto" else target
    
    logs = []
    common_emails = [
        "admin@example.com", "user@example.com", "test@example.com",
        "john.doe@example.com", "alice@example.com"
    ]
    
    for i in range(total_attempts):
        timestamp = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
        attacker_ip = random.choice(attacker_ips)
        email = random.choice(common_emails)
        status = 401  # Unauthorized
        bytes_sent = random.randint(200, 500)
        
        log_entry = (
            f'{attacker_ip} - - [{timestamp}] "POST /api/login HTTP/1.1" '
            f'{status} {bytes_sent} "-" "python-requests/2.28.0" '
            f'user="{email}"'
        )
        logs.append(log_entry)
    
    log_content = "\n".join(logs)
    
    return SimulationResult(
        attack_type="credential_stuffing",
        log_lines_generated=len(logs),
        duration_seconds=duration,
        attacker_ips=attacker_ips,
        target_hosts=[target_host],
        log_content=log_content
    )


# Attack type mapping
ATTACK_GENERATORS = {
    "ssh_brute_force": generate_ssh_brute_force,
    "web_scan": generate_web_scan,
    "sql_injection": generate_sql_injection,
    "xss_attack": generate_xss_attack,
    "port_scan": generate_port_scan,
    "credential_stuffing": generate_credential_stuffing,
}


def simulate_attack(simulation: AttackSimulation) -> SimulationResult:
    """
    Execute attack simulation based on request.
    
    Args:
        simulation: Attack simulation configuration
        
    Returns:
        SimulationResult with generated logs
    """
    generator = ATTACK_GENERATORS.get(simulation.attack_type)
    if not generator:
        raise ValueError(f"Unknown attack type: {simulation.attack_type}")
    
    return generator(
        intensity=simulation.intensity,
        duration=simulation.duration_seconds,
        target=simulation.target_host
    )
