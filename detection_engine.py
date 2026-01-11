# @even rygh
"""
Rule-Based Detection Engine for SOC Platform

Provides deterministic, explainable detection of security events.
Rules are configurable, extensible, and reusable across live SOC and BYOL analysis.

Architecture:
- Alert: Structured output with severity, explanation, evidence
- DetectionRule: Base class for all detection rules
- DetectionEngine: Applies rules to event streams
- RuleRegistry: Manages rule configuration and loading

Design Principles:
- Deterministic: Same events always produce same alerts
- Explainable: Every alert includes clear explanation
- Extensible: Easy to add new rules
- Performant: Efficient time-window tracking
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any, Set
from datetime import datetime, timedelta
from collections import defaultdict
from enum import Enum
import json

# Import our log parser for event types
from log_parser import ParsedEvent


class Severity(Enum):
    """
    Alert severity levels.
    
    Aligned with standard SOC severity classifications.
    """
    INFO = "info"           # Informational, no action needed
    LOW = "low"             # Minor issue, monitor
    MEDIUM = "medium"       # Suspicious activity, investigate
    HIGH = "high"           # Likely attack, respond immediately
    CRITICAL = "critical"   # Active attack, urgent response


@dataclass
class Alert:
    """
    Structured security alert.
    
    All detection rules produce this standardized output format.
    Ensures consistency and makes alert processing/routing easier.
    """
    # Core identification
    alert_id: str                      # Unique alert identifier
    rule_id: str                       # Rule that triggered this alert
    severity: Severity                 # Alert severity level
    
    # Description
    title: str                         # Short alert title
    description: str                   # Detailed explanation
    
    # Context
    timestamp: datetime                # When alert was generated
    affected_ips: List[str]           # IP addresses involved
    affected_hosts: List[str] = field(default_factory=list)  # Hostnames involved
    
    # Evidence
    event_count: int = 0              # Number of events that triggered rule
    evidence: Dict[str, Any] = field(default_factory=dict)  # Rule-specific data
    
    # Additional metadata
    tags: List[str] = field(default_factory=list)  # Categorization tags
    recommendations: List[str] = field(default_factory=list)  # Response actions

    def _format_key(self, key: str) -> str:
        return key.replace('_', ' ').strip().title()

    def _coerce_scalar(self, value: Any) -> Any:
        # Ensure JSON-serializable primitives where possible.
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        # Keep small containers readable; fallback to str.
        if isinstance(value, (list, tuple)):
            return [self._coerce_scalar(v) for v in value]
        if isinstance(value, dict):
            return {str(k): self._coerce_scalar(v) for k, v in value.items()}
        return str(value)

    def soc_explanation(self) -> Dict[str, Any]:
        """Return a SOC-friendly explanation for analysts.

        The goal is to make alerts immediately actionable:
        - why_triggered: short human explanation
        - data_points: key fields that influenced the decision
        - recommended_next_steps: analyst-oriented next actions
        """
        evidence = self.evidence or {}
        primary_ip = (self.affected_ips[0] if self.affected_ips else None)

        why_triggered = self.description
        data_points: List[Dict[str, Any]] = []

        # Always include common context.
        data_points.append({"label": "Rule", "value": self.rule_id})
        data_points.append({"label": "Severity", "value": self.severity.value})
        data_points.append({"label": "Event Count", "value": int(self.event_count)})
        if primary_ip:
            data_points.append({"label": "Primary IP", "value": primary_ip})
        if self.affected_hosts:
            data_points.append({"label": "Affected Hosts", "value": list(self.affected_hosts)})

        # Rule-specific story + highlight data points.
        if self.rule_id == "brute_force_detection":
            threshold = evidence.get("threshold")
            window = evidence.get("time_window_seconds")
            first = evidence.get("first_attempt")
            last = evidence.get("last_attempt")
            username = evidence.get("username")
            source = evidence.get("source")
            why_triggered = (
                f"Triggered because repeated authentication failures from {primary_ip or 'an IP'} "
                f"met/exceeded the brute force threshold"
                f"{f' ({self.event_count} >= {threshold})' if threshold is not None else ''}"
                f"{f' within ~{int(float(window))}s' if window is not None else ''}."
            )
            for label, val in [
                ("Username", username),
                ("First Attempt", first),
                ("Last Attempt", last),
                ("Threshold", threshold),
                ("Window (seconds)", window),
                ("Log Source", source),
                ("Alert Cooldown (seconds)", evidence.get("alert_cooldown_seconds")),
            ]:
                if val is not None:
                    data_points.append({"label": label, "value": self._coerce_scalar(val)})

        elif self.rule_id == "port_scan_detection":
            services = evidence.get("services_accessed") or []
            window = evidence.get("time_window_seconds")
            threshold = evidence.get("threshold")
            why_triggered = (
                f"Triggered because {primary_ip or 'an IP'} accessed many distinct services in a short time, "
                f"suggesting reconnaissance/port scanning"
                f"{f' ({len(services)} >= {threshold})' if threshold is not None else ''}"
                f"{f' over ~{int(float(window))}s' if window is not None else ''}."
            )
            if services:
                data_points.append({"label": "Services Accessed", "value": services[:10] + (["..."] if len(services) > 10 else [])})
            for label, val in [
                ("First Activity", evidence.get("first_activity")),
                ("Last Activity", evidence.get("last_activity")),
                ("Window (seconds)", window),
                ("Threshold", threshold),
                ("Log Source", evidence.get("source")),
            ]:
                if val is not None:
                    data_points.append({"label": label, "value": self._coerce_scalar(val)})

        elif self.rule_id == "web_scanner_detection":
            scanner = evidence.get("scanner")
            ua = evidence.get("user_agent")
            uri = evidence.get("uri")
            method = evidence.get("method")
            status = evidence.get("status")
            total = evidence.get("total_requests")
            scanner_fragment = f" ('{scanner}')" if scanner else ""
            why_triggered = (
                f"Triggered because the HTTP User-Agent matched a known scanner signature"
                f"{scanner_fragment}, indicating automated vulnerability scanning."
            )
            for label, val in [
                ("Scanner Signature", scanner),
                ("User-Agent", ua),
                ("Request URI", uri),
                ("HTTP Method", method),
                ("HTTP Status", status),
                ("Total Scanner Requests", total),
                ("Log Source", evidence.get("source")),
            ]:
                if val is not None:
                    data_points.append({"label": label, "value": self._coerce_scalar(val)})

        elif self.rule_id == "suspicious_uri_detection":
            uri = evidence.get("uri")
            patterns = evidence.get("detected_patterns") or []
            categories = evidence.get("attack_categories") or []
            categories_fragment = f" (categories: {', '.join(categories)})" if categories else ""
            why_triggered = (
                f"Triggered because a request URI matched suspicious attack patterns"
                f"{categories_fragment}."
            )
            for label, val in [
                ("Request URI", uri),
                ("Attack Categories", categories),
                ("Matched Patterns", patterns),
                ("HTTP Method", evidence.get("method")),
                ("HTTP Status", evidence.get("status")),
                ("User-Agent", evidence.get("user_agent")),
                ("Log Source", evidence.get("source")),
            ]:
                if val is not None and val != []:
                    data_points.append({"label": label, "value": self._coerce_scalar(val)})

        else:
            # Generic fallback: include top evidence keys.
            if evidence:
                for k in list(evidence.keys())[:12]:
                    data_points.append({"label": self._format_key(str(k)), "value": self._coerce_scalar(evidence.get(k))})

        # Recommended next steps: use rule's recommendations, with a couple SOC-oriented defaults.
        next_steps = list(self.recommendations or [])
        # Light-touch: add a couple generic steps if not already present.
        generic = [
            "Validate whether the source is expected/authorized",
            "Correlate with other alerts and recent activity for the same IP/host",
        ]
        for step in generic:
            if step not in next_steps:
                next_steps.append(step)

        return {
            "why_triggered": why_triggered,
            "data_points": data_points,
            "recommended_next_steps": next_steps,
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert alert to dictionary for serialization.
        
        Handles Enum and datetime conversions.
        """
        result = asdict(self)
        result['severity'] = self.severity.value
        result['timestamp'] = self.timestamp.isoformat()
        result['soc_explanation'] = self.soc_explanation()
        return result
    
    def to_json(self) -> str:
        """Convert alert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class DetectionRule:
    """
    Base class for all detection rules.
    
    Subclasses implement specific detection logic while maintaining
    consistent interface and state management.
    
    Design Pattern: Template Method
    - Base class defines structure
    - Subclasses implement specific detection logic
    """
    
    # Subclasses must set these
    rule_id: str = "base_rule"
    rule_name: str = "Base Detection Rule"
    severity: Severity = Severity.INFO
    description: str = "Base rule description"
    tags: List[str] = []
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize rule with optional configuration.
        
        Args:
            config: Rule-specific configuration parameters
        """
        self.config = config or {}
        self.state: Dict[str, Any] = {}  # Rule maintains internal state
        self.reset()
    
    def reset(self):
        """
        Reset rule state.
        
        Called when starting new analysis or after time window expires.
        Subclasses can override to add custom state initialization.
        """
        self.state = {}
    
    def process_event(self, event: ParsedEvent) -> Optional[Alert]:
        """
        Process a single event and potentially generate an alert.
        
        Args:
            event: Normalized event from log parser
            
        Returns:
            Alert if rule conditions are met, None otherwise
            
        Note:
            This is the main method subclasses must implement.
            Rules maintain state across events to detect patterns.
        """
        raise NotImplementedError("Subclasses must implement process_event")
    
    def process_events_batch(self, events: List[ParsedEvent]) -> List[Alert]:
        """
        Process multiple events and generate alerts.
        
        Convenience method for batch processing.
        Calls process_event for each event and collects alerts.
        
        Args:
            events: List of normalized events
            
        Returns:
            List of generated alerts
        """
        alerts = []
        for event in events:
            alert = self.process_event(event)
            if alert is not None:
                alerts.append(alert)
        return alerts
    
    def _generate_alert_id(self) -> str:
        """Generate unique alert ID."""
        import uuid
        return f"{self.rule_id}_{uuid.uuid4().hex[:8]}"


class BruteForceDetectionRule(DetectionRule):
    """
    Detects brute force attacks via multiple failed login attempts.
    
    Detection Logic:
    - Tracks failed authentication attempts per IP address
    - Triggers alert when threshold is exceeded within time window
    - Cleans up old events to prevent memory growth
    
    Configuration:
    - threshold: Number of failed attempts to trigger alert (default: 5)
    - time_window_seconds: Time window for attempts (default: 300 = 5 minutes)
    
    Use Cases:
    - SSH brute force attacks
    - Web application login attacks
    - API authentication attacks
    """
    
    rule_id = "brute_force_detection"
    rule_name = "Brute Force Attack Detection"
    severity = Severity.HIGH
    description = "Detects multiple failed authentication attempts from a single IP"
    tags = ["authentication", "brute_force", "attack"]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        # Configuration with defaults
        self.threshold = self.config.get('threshold', 5)
        self.time_window = timedelta(seconds=self.config.get('time_window_seconds', 300))
        # Avoid alert flooding: once an alert is raised for an IP, suppress repeats
        # for a cooldown window (default: same as time window).
        self.alert_cooldown = timedelta(seconds=self.config.get('alert_cooldown_seconds', int(self.time_window.total_seconds())))
    
    def reset(self):
        """
        Reset detection state.
        
        State tracking:
        - failed_attempts: Dict[IP -> List[timestamp]]
        """
        self.state = {
            'failed_attempts': defaultdict(list),  # IP -> [timestamps]
            'last_alert_time': {},  # IP -> datetime
        }
    
    def process_event(self, event: ParsedEvent) -> Optional[Alert]:
        """
        Process event and detect brute force patterns.
        
        Only processes authentication failure events.
        Maintains sliding time window of failed attempts per IP.
        """
        # Only process authentication failures
        if event.event_type not in ['auth_failed', 'invalid_user']:
            return None
        
        if not event.ip or not event.timestamp:
            return None
        
        ip = event.ip
        timestamp = event.timestamp
        
        # Add this attempt to tracking
        self.state['failed_attempts'][ip].append(timestamp)
        
        # Clean up old attempts outside time window
        cutoff_time = timestamp - self.time_window
        self.state['failed_attempts'][ip] = [
            ts for ts in self.state['failed_attempts'][ip]
            if ts > cutoff_time
        ]
        
        # Check if threshold exceeded
        attempt_count = len(self.state['failed_attempts'][ip])
        
        if attempt_count >= self.threshold:
            last_alert_time = self.state['last_alert_time'].get(ip)
            if last_alert_time is not None and (timestamp - last_alert_time) < self.alert_cooldown:
                return None

            # Generate alert
            self.state['last_alert_time'][ip] = timestamp
            return Alert(
                alert_id=self._generate_alert_id(),
                rule_id=self.rule_id,
                severity=self.severity,
                title=f"Brute Force Attack Detected from {ip}",
                description=(
                    f"IP address {ip} has made {attempt_count} failed "
                    f"authentication attempts within {self.time_window.total_seconds():.0f} seconds. "
                    f"This exceeds the threshold of {self.threshold} attempts and indicates "
                    f"a potential brute force attack."
                ),
                timestamp=timestamp,
                affected_ips=[ip],
                affected_hosts=[event.host] if event.host else [],
                event_count=attempt_count,
                evidence={
                    'first_attempt': self.state['failed_attempts'][ip][0].isoformat(),
                    'last_attempt': timestamp.isoformat(),
                    'time_window_seconds': self.time_window.total_seconds(),
                    'threshold': self.threshold,
                    'alert_cooldown_seconds': self.alert_cooldown.total_seconds(),
                    'source': event.source,
                    'username': event.metadata.get('username', 'unknown')
                },
                tags=self.tags,
                recommendations=[
                    f"Block IP address {ip} at firewall level",
                    f"Review all activity from {ip} for additional compromise indicators",
                    "Consider implementing rate limiting on authentication endpoints",
                    "Enable multi-factor authentication if not already active"
                ]
            )
        
        return None


class PortScanDetectionRule(DetectionRule):
    """
    Detects port scanning activity.
    
    Detection Logic:
    - Tracks unique services/ports accessed by each IP
    - Triggers when single IP accesses multiple distinct services
    - Distinguishes between legitimate multi-service usage and scanning
    
    Configuration:
    - threshold: Number of unique services to trigger alert (default: 5)
    - time_window_seconds: Time window for activity (default: 60)
    
    Use Cases:
    - Network reconnaissance
    - Automated vulnerability scanning
    - Attacker enumeration phase
    """
    
    rule_id = "port_scan_detection"
    rule_name = "Port Scan Detection"
    severity = Severity.MEDIUM
    description = "Detects single IP accessing multiple services (potential port scan)"
    tags = ["reconnaissance", "port_scan", "enumeration"]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        self.threshold = self.config.get('threshold', 5)
        self.time_window = timedelta(seconds=self.config.get('time_window_seconds', 60))
        self.alert_cooldown = timedelta(seconds=self.config.get('alert_cooldown_seconds', int(self.time_window.total_seconds())))
    
    def reset(self):
        """
        Reset detection state.
        
        State tracking:
        - ip_services: Dict[IP -> Set[service_identifier]]
        - ip_first_seen: Dict[IP -> timestamp]
        """
        self.state = {
            'ip_services': defaultdict(set),      # IP -> {service identifiers}
            'ip_first_seen': {},                   # IP -> first timestamp
            'ip_last_seen': {},                    # IP -> last timestamp
            'last_alert_time': {},                 # IP -> last alert timestamp
        }
    
    def process_event(self, event: ParsedEvent) -> Optional[Alert]:
        """
        Process event and detect port scanning patterns.
        
        Service identification depends on log type:
        - Web logs: Use URI path as service indicator
        - SSH logs: Service is implicit (ssh)
        """
        if not event.ip or not event.timestamp:
            return None
        
        ip = event.ip
        timestamp = event.timestamp
        
        # Determine service identifier based on log type
        service_id = self._extract_service_identifier(event)
        if not service_id:
            return None
        
        # Track first and last seen times
        if ip not in self.state['ip_first_seen']:
            self.state['ip_first_seen'][ip] = timestamp
        self.state['ip_last_seen'][ip] = timestamp
        
        # Add service to tracking
        self.state['ip_services'][ip].add(service_id)
        
        # Check if within time window
        first_seen = self.state['ip_first_seen'][ip]
        time_elapsed = timestamp - first_seen
        
        # Only alert if within time window (indicates rapid scanning)
        if time_elapsed > self.time_window:
            # Reset tracking for this IP - too much time has passed
            self.state['ip_services'][ip] = {service_id}
            self.state['ip_first_seen'][ip] = timestamp
            return None
        
        # Check if threshold exceeded
        service_count = len(self.state['ip_services'][ip])
        
        if service_count >= self.threshold:
            last_alert_time = self.state['last_alert_time'].get(ip)
            if last_alert_time is not None and (timestamp - last_alert_time) < self.alert_cooldown:
                return None

            self.state['last_alert_time'][ip] = timestamp
            services_list = list(self.state['ip_services'][ip])
            
            return Alert(
                alert_id=self._generate_alert_id(),
                rule_id=self.rule_id,
                severity=self.severity,
                title=f"Port Scan Detected from {ip}",
                description=(
                    f"IP address {ip} has accessed {service_count} different services "
                    f"within {time_elapsed.total_seconds():.0f} seconds. "
                    f"This rapid multi-service access pattern is indicative of "
                    f"automated port scanning or service enumeration."
                ),
                timestamp=timestamp,
                affected_ips=[ip],
                event_count=service_count,
                evidence={
                    'services_accessed': services_list,
                    'first_activity': first_seen.isoformat(),
                    'last_activity': timestamp.isoformat(),
                    'time_window_seconds': time_elapsed.total_seconds(),
                    'threshold': self.threshold,
                    'source': event.source,
                    'alert_cooldown_seconds': self.alert_cooldown.total_seconds(),
                },
                tags=self.tags,
                recommendations=[
                    f"Investigate IP address {ip} for malicious intent",
                    f"Review services accessed: {', '.join(services_list[:5])}{'...' if len(services_list) > 5 else ''}",
                    "Check if IP is from known scanner/vulnerability assessment tool",
                    "Consider implementing rate limiting per IP",
                    f"Block {ip} if activity is confirmed malicious"
                ]
            )
        
        return None
    
    def _extract_service_identifier(self, event: ParsedEvent) -> Optional[str]:
        """
        Extract service identifier from event.
        
        Different log types expose services differently:
        - Web logs: URI path segments indicate different services
        - SSH logs: Service is 'ssh'
        - Future: Could map ports to services
        """
        dest_port = (
            event.metadata.get('dest_port')
            or event.metadata.get('destination_port')
            or event.metadata.get('dst_port')
            or event.metadata.get('port')
        )
        if dest_port is not None:
            try:
                port_int = int(dest_port)
                if 0 < port_int <= 65535:
                    return f"tcp:{port_int}"
            except (TypeError, ValueError):
                pass

        if event.source in ['nginx', 'apache']:
            # For web logs, use first path segment as service indicator
            uri = event.metadata.get('uri', '')
            if uri:
                # Extract first path segment
                path_parts = uri.strip('/').split('/')
                if path_parts:
                    return f"web:{path_parts[0]}"
        
        elif event.source == 'ssh':
            return 'ssh'
        
        return None


class WebScannerDetectionRule(DetectionRule):
    """
    Detects web vulnerability scanners and automated security tools.
    
    Detection Logic:
    - Identifies known scanner user agents
    - Detects scanner-specific request patterns
    - Tracks multiple requests from scanner IPs
    
    Configuration:
    - scanner_user_agents: List of known scanner signatures
    - threshold: Number of scanner requests before alerting
    
    Use Cases:
    - Unauthorized security scanning
    - Reconnaissance activity
    - Penetration testing detection
    """
    
    rule_id = "web_scanner_detection"
    rule_name = "Web Vulnerability Scanner Detection"
    severity = Severity.HIGH
    description = "Detects automated web vulnerability scanners"
    tags = ["web_attack", "scanner", "reconnaissance"]
    
    # Known vulnerability scanner signatures
    DEFAULT_SCANNER_AGENTS = [
        'nikto', 'sqlmap', 'nmap', 'masscan', 'nessus', 
        'openvas', 'acunetix', 'burp', 'zap', 'w3af',
        'metasploit', 'wpscan', 'dirbuster', 'gobuster',
        'wfuzz', 'ffuf', 'nuclei', 'skipfish'
    ]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        # NOTE: DetectionRule.__init__ calls self.reset(). Since this class overrides
        # reset() and uses these attributes, they must exist before super().__init__.
        self.scanner_ips: Dict[str, int] = defaultdict(int)
        self.alerted_ips: Set[str] = set()

        super().__init__(config)

        self.scanner_agents = self.config.get('scanner_user_agents', self.DEFAULT_SCANNER_AGENTS)
        self.threshold = self.config.get('threshold', 1)  # Alert on first scanner detection
    
    def reset(self):
        """Reset scanner tracking state."""
        self.scanner_ips.clear()
        self.alerted_ips.clear()
    
    def process_event(self, event: ParsedEvent) -> Optional[Alert]:
        """
        Process web request and detect scanner user agents.
        
        Only processes web server logs (nginx, apache).
        Checks user agent against known scanner signatures.
        """
        # Only process web logs
        if event.source not in ['nginx', 'apache']:
            return None
        
        user_agent = event.metadata.get('user_agent', '').lower()
        if not user_agent:
            return None
        
        # Check for scanner signatures
        detected_scanner = None
        for scanner in self.scanner_agents:
            if scanner.lower() in user_agent:
                detected_scanner = scanner
                break
        
        if detected_scanner:
            ip = event.ip if event.ip else 'unknown'
            self.scanner_ips[ip] += 1
            
            # Generate alert if threshold reached and not already alerted
            if self.scanner_ips[ip] >= self.threshold and ip not in self.alerted_ips:
                self.alerted_ips.add(ip)
                
                return Alert(
                    alert_id=self._generate_alert_id(),
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title=f"Web Vulnerability Scanner Detected from {ip}",
                    description=(
                        f"IP address {ip} is using '{detected_scanner}' vulnerability scanner. "
                        f"Detected {self.scanner_ips[ip]} scanner requests. "
                        f"This may indicate reconnaissance or unauthorized security testing. "
                        f"URI: {event.metadata.get('uri', 'unknown')}"
                    ),
                    timestamp=event.timestamp or datetime.now(),
                    affected_ips=[ip],
                    event_count=self.scanner_ips[ip],
                    evidence={
                        'scanner': detected_scanner,
                        'user_agent': event.metadata.get('user_agent'),
                        'uri': event.metadata.get('uri'),
                        'method': event.metadata.get('method'),
                        'status': event.metadata.get('status'),
                        'total_requests': self.scanner_ips[ip],
                        'source': event.source
                    },
                    tags=self.tags + [detected_scanner],
                    recommendations=[
                        f"Investigate activity from {ip}",
                        f"Determine if {detected_scanner} scan is authorized",
                        "Review web application firewall (WAF) logs",
                        "Check for any successful exploits after scan",
                        f"Consider blocking {ip} if scan is unauthorized",
                        "Ensure all web applications are patched and hardened"
                    ]
                )
        
        return None


class SuspiciousURIDetectionRule(DetectionRule):
    """
    Detects suspicious URI patterns in web requests.
    
    Detection Logic:
    - Scans URIs for common attack patterns
    - Path traversal attempts (../)
    - SQL injection indicators
    - Command injection patterns
    - Admin/config file access attempts
    
    Configuration:
    - patterns: List of suspicious patterns to detect
    
    Use Cases:
    - Web application attacks
    - Directory traversal
    - Configuration file exposure
    """
    
    rule_id = "suspicious_uri_detection"
    rule_name = "Suspicious URI Pattern Detection"
    severity = Severity.MEDIUM
    description = "Detects suspicious patterns in HTTP request URIs"
    tags = ["web_attack", "injection", "path_traversal"]
    
    # Default suspicious patterns
    DEFAULT_PATTERNS = {
        'path_traversal': ['../', '..\\', '%2e%2e', 'etc/passwd', 'etc/shadow'],
        'sql_injection': ['union select', "' or '1'='1", 'drop table', '; drop'],
        'command_injection': ['|', '&&', ';cat ', '`', '$('],
        'admin_access': ['/admin', '/phpmyadmin', '/wp-admin', '/manager', '/.env'],
        'config_files': ['.config', '.env', 'web.config', 'application.properties']
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        # Allow custom patterns or use defaults
        self.patterns = self.config.get('patterns', self.DEFAULT_PATTERNS)
    
    def reset(self):
        """No persistent state needed for this rule."""
        self.state = {}
    
    def process_event(self, event: ParsedEvent) -> Optional[Alert]:
        """
        Process web request event and detect suspicious URI patterns.
        
        Only processes web server logs (nginx, apache).
        Checks URI against known attack patterns.
        """
        # Only process web logs
        if event.source not in ['nginx', 'apache']:
            return None
        
        uri = event.metadata.get('uri', '').lower()
        if not uri:
            return None
        
        # Check for suspicious patterns
        detected_patterns = []
        pattern_categories = []
        
        for category, patterns in self.patterns.items():
            for pattern in patterns:
                if pattern.lower() in uri:
                    detected_patterns.append(pattern)
                    if category not in pattern_categories:
                        pattern_categories.append(category)
        
        if detected_patterns:
            # Generate alert
            return Alert(
                alert_id=self._generate_alert_id(),
                rule_id=self.rule_id,
                severity=self.severity,
                title=f"Suspicious URI Pattern Detected from {event.ip}",
                description=(
                    f"IP address {event.ip} made a request with suspicious URI patterns. "
                    f"Detected patterns indicate potential {', '.join(pattern_categories)} attack. "
                    f"URI: {event.metadata.get('uri', 'unknown')}"
                ),
                timestamp=event.timestamp or datetime.now(),
                affected_ips=[event.ip] if event.ip else [],
                event_count=1,
                evidence={
                    'uri': event.metadata.get('uri'),
                    'method': event.metadata.get('method'),
                    'status': event.metadata.get('status'),
                    'user_agent': event.metadata.get('user_agent'),
                    'detected_patterns': detected_patterns,
                    'attack_categories': pattern_categories,
                    'source': event.source
                },
                tags=self.tags + pattern_categories,
                recommendations=[
                    f"Investigate activity from {event.ip}",
                    "Review web application logs for additional suspicious requests",
                    "Ensure web application firewall (WAF) is active",
                    "Check if targeted application has known vulnerabilities",
                    f"Consider blocking {event.ip} if attack continues"
                ]
            )
        
        return None


class DetectionEngine:
    """
    Main detection engine that applies rules to event streams.
    
    Orchestrates rule execution, alert collection, and state management.
    Designed to work with both real-time streams and batch analysis.
    
    Usage Patterns:
    1. Real-time: Process events one at a time as they arrive
    2. Batch: Process historical logs for analysis
    3. BYOL: Analyze user-uploaded logs
    """
    
    def __init__(self, rules: Optional[List[DetectionRule]] = None):
        """
        Initialize detection engine with rules.
        
        Args:
            rules: List of detection rules to apply. If None, loads default rules.
        """
        self.rules = rules if rules is not None else self._load_default_rules()
        self.alerts: List[Alert] = []
    
    def _load_default_rules(self) -> List[DetectionRule]:
        """
        Load default rule set.
        
        Returns a reasonable default configuration for common threats.
        Can be overridden to load from configuration file.
        """
        return [
            BruteForceDetectionRule(config={'threshold': 5, 'time_window_seconds': 300}),
            PortScanDetectionRule(config={'threshold': 5, 'time_window_seconds': 60}),
            WebScannerDetectionRule(),  # NEW: Detect Nikto, sqlmap, etc.
            SuspiciousURIDetectionRule(),
        ]
    
    def process_event(self, event: ParsedEvent) -> List[Alert]:
        """
        Process single event through all rules.
        
        Args:
            event: Normalized event from log parser
            
        Returns:
            List of alerts generated (may be empty)
        """
        new_alerts = []
        
        for rule in self.rules:
            alert = rule.process_event(event)
            if alert is not None:
                new_alerts.append(alert)
                self.alerts.append(alert)
        
        return new_alerts
    
    def process_events(self, events: List[ParsedEvent]) -> List[Alert]:
        """
        Process multiple events through all rules.
        
        Args:
            events: List of normalized events
            
        Returns:
            List of all alerts generated
        """
        all_alerts = []
        
        for event in events:
            alerts = self.process_event(event)
            all_alerts.extend(alerts)
        
        return all_alerts
    
    def reset(self):
        """
        Reset engine state.
        
        Clears all alerts and resets all rule states.
        Useful when starting new analysis session.
        """
        self.alerts = []
        for rule in self.rules:
            rule.reset()
    
    def get_alerts(self, 
                   severity: Optional[Severity] = None,
                   rule_id: Optional[str] = None) -> List[Alert]:
        """
        Get alerts with optional filtering.
        
        Args:
            severity: Filter by severity level
            rule_id: Filter by rule ID
            
        Returns:
            Filtered list of alerts
        """
        filtered = self.alerts
        
        if severity is not None:
            filtered = [a for a in filtered if a.severity == severity]
        
        if rule_id is not None:
            filtered = [a for a in filtered if a.rule_id == rule_id]
        
        return filtered
    
    def get_alerts_by_ip(self, ip: str) -> List[Alert]:
        """Get all alerts affecting a specific IP address."""
        return [a for a in self.alerts if ip in a.affected_ips]
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics of detected alerts.
        
        Useful for reporting and dashboard display.
        """
        if not self.alerts:
            return {
                'total_alerts': 0,
                'by_severity': {},
                'by_rule': {},
                'unique_ips': 0
            }
        
        # Count by severity
        by_severity = defaultdict(int)
        for alert in self.alerts:
            by_severity[alert.severity.value] += 1
        
        # Count by rule
        by_rule = defaultdict(int)
        for alert in self.alerts:
            by_rule[alert.rule_id] += 1
        
        # Unique IPs
        all_ips = set()
        for alert in self.alerts:
            all_ips.update(alert.affected_ips)
        
        return {
            'total_alerts': len(self.alerts),
            'by_severity': dict(by_severity),
            'by_rule': dict(by_rule),
            'unique_ips': len(all_ips),
            'affected_ips': list(all_ips)
        }


# Convenience function for quick analysis
def analyze_events(events: List[ParsedEvent], 
                   rules: Optional[List[DetectionRule]] = None) -> List[Alert]:
    """
    Convenience function to analyze events and return alerts.
    
    Args:
        events: List of normalized events
        rules: Optional custom rule list
        
    Returns:
        List of generated alerts
    
    Example:
        >>> from log_parser import parse_logs
        >>> events = list(parse_logs(log_lines, 'ssh'))
        >>> alerts = analyze_events(events)
        >>> print(f"Found {len(alerts)} security issues")
    """
    engine = DetectionEngine(rules)
    return engine.process_events(events)


if __name__ == '__main__':
    # Example usage
    print("Detection Engine - Example Usage\n")
    
    # Create sample events (normally from log parser)
    from log_parser import parse_logs
    
    ssh_logs = [
        'Jan 7 10:30:00 server sshd[1]: Failed password for root from 203.0.113.50 port 22 ssh2',
        'Jan 7 10:30:05 server sshd[2]: Failed password for root from 203.0.113.50 port 22 ssh2',
        'Jan 7 10:30:10 server sshd[3]: Failed password for root from 203.0.113.50 port 22 ssh2',
        'Jan 7 10:30:15 server sshd[4]: Failed password for admin from 203.0.113.50 port 22 ssh2',
        'Jan 7 10:30:20 server sshd[5]: Failed password for admin from 203.0.113.50 port 22 ssh2',
    ]
    
    # Parse events
    events = list(parse_logs(iter(ssh_logs), 'ssh'))
    
    # Analyze with detection engine
    alerts = analyze_events(events)
    
    print(f"Analyzed {len(events)} events")
    print(f"Generated {len(alerts)} alerts\n")
    
    for alert in alerts:
        print(f"[{alert.severity.value.upper()}] {alert.title}")
        print(f"  Rule: {alert.rule_id}")
        print(f"  Description: {alert.description}")
        print(f"  Affected IPs: {', '.join(alert.affected_ips)}")
        print()
