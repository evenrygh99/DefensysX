# @even rygh
"""
Log parsing utilities for different log formats.
Each parser is designed to handle specific log types safely.
"""
import re
from datetime import datetime
from typing import Optional, Dict
from session_manager import LogEvent


class BaseLogParser:
    """Base class for log parsers. Ensures consistent interface."""
    
    def parse_line(self, line: str, line_number: int) -> Optional[LogEvent]:
        """
        Parse a single log line into a structured event.
        
        Args:
            line: Raw log line
            line_number: Line number in file (for error reporting)
            
        Returns:
            LogEvent if parsing succeeds, None if line should be skipped
        """
        raise NotImplementedError("Subclasses must implement parse_line")


class SSHLogParser(BaseLogParser):
    """
    Parser for SSH authentication logs (e.g., /var/log/auth.log).
    
    Security considerations:
    - All regex patterns are pre-compiled to prevent ReDoS
    - Captures critical security events: failed logins, accepted logins, invalid users
    - Extracts attacker IPs for threat intelligence
    """
    
    # Pre-compiled regex patterns (more efficient and prevents ReDoS)
    # Pattern for SSH authentication attempts
    FAILED_PASSWORD_PATTERN = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
        r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
        r'Failed password for (?:invalid user )?(?P<username>\S+)\s+'
        r'from (?P<ip>\d+\.\d+\.\d+\.\d+)'
    )
    
    ACCEPTED_PASSWORD_PATTERN = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
        r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
        r'Accepted (?:password|publickey) for (?P<username>\S+)\s+'
        r'from (?P<ip>\d+\.\d+\.\d+\.\d+)'
    )
    
    INVALID_USER_PATTERN = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
        r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
        r'Invalid user (?P<username>\S+)\s+'
        r'from (?P<ip>\d+\.\d+\.\d+\.\d+)'
    )

    FIREWALL_SYN_SCAN_PATTERN = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
        r'(?P<hostname>\S+)\s+kernel:\s+\[FIREWALL\]\s+SYN scan detected:\s+'
        r'(?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+)\s+->\s+'
        r'(?P<dest_host>\S+):(?P<dest_port>\d+)\s+\(TCP\)'
    )
    
    def parse_line(self, line: str, line_number: int) -> Optional[LogEvent]:
        """Parse SSH log line into structured event."""
        
        # Try each pattern
        for pattern, event_type, severity in [
            (self.FAILED_PASSWORD_PATTERN, "failed_password", "warning"),
            (self.ACCEPTED_PASSWORD_PATTERN, "accepted_auth", "info"),
            (self.INVALID_USER_PATTERN, "invalid_user", "warning")
        ]:
            match = pattern.search(line)
            if match:
                data = match.groupdict()
                
                # Parse timestamp (SSH logs don't include year, assume current year)
                try:
                    timestamp = datetime.strptime(
                        data['timestamp'], 
                        '%b %d %H:%M:%S'
                    ).replace(year=datetime.now().year)
                except ValueError:
                    timestamp = None
                
                return LogEvent(
                    timestamp=timestamp,
                    log_type="ssh",
                    raw_line=line,
                    parsed_data={
                        "event_type": event_type,
                        "username": data.get('username'),
                        "source_ip": data.get('ip'),
                        "hostname": data.get('hostname')
                    },
                    severity=severity
                )

        match = self.FIREWALL_SYN_SCAN_PATTERN.search(line)
        if match:
            data = match.groupdict()
            try:
                timestamp = datetime.strptime(
                    data['timestamp'],
                    '%b %d %H:%M:%S'
                ).replace(year=datetime.now().year)
            except ValueError:
                timestamp = None

            dest_port: Optional[int]
            try:
                dest_port = int(data.get('dest_port', '') or 0)
            except ValueError:
                dest_port = None

            src_port: Optional[int]
            try:
                src_port = int(data.get('src_port', '') or 0)
            except ValueError:
                src_port = None

            return LogEvent(
                timestamp=timestamp,
                log_type="ssh",
                raw_line=line,
                parsed_data={
                    "event_type": "port_scan",
                    "source_ip": data.get('src_ip'),
                    "source_port": src_port,
                    "dest_host": data.get('dest_host'),
                    "dest_port": dest_port,
                    "hostname": data.get('hostname'),
                },
                severity="warning",
            )
        
        # Line didn't match any pattern - skip it
        return None


class NginxLogParser(BaseLogParser):
    """
    Parser for Nginx access logs (combined format).
    
    Security considerations:
    - Extracts HTTP status codes for error detection
    - Captures user agents for bot/attack detection
    - Identifies potential attack vectors via URI and referrer
    """
    
    # Nginx combined log format pattern
    LOG_PATTERN = re.compile(
        r'(?P<ip>[\d\.]+)\s+-\s+(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<uri>\S+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d+)\s+(?P<bytes>\d+)\s+'
        r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
    )
    
    def parse_line(self, line: str, line_number: int) -> Optional[LogEvent]:
        """Parse Nginx access log line into structured event."""
        
        match = self.LOG_PATTERN.search(line)
        if not match:
            return None
        
        data = match.groupdict()
        
        # Parse timestamp
        try:
            timestamp = datetime.strptime(
                data['timestamp'],
                '%d/%b/%Y:%H:%M:%S %z'
            )
        except ValueError:
            timestamp = None
        
        # Determine severity based on HTTP status code
        status_code = int(data['status'])
        if status_code >= 500:
            severity = "error"
        elif status_code >= 400:
            severity = "warning"
        else:
            severity = "info"
        
        return LogEvent(
            timestamp=timestamp,
            log_type="nginx",
            raw_line=line,
            parsed_data={
                "source_ip": data['ip'],
                "user": data['user'],
                "method": data['method'],
                "uri": data['uri'],
                "protocol": data['protocol'],
                "status_code": status_code,
                "bytes": int(data['bytes']),
                "referrer": data['referrer'],
                "user_agent": data['user_agent']
            },
            severity=severity
        )


class ApacheLogParser(BaseLogParser):
    """
    Parser for Apache access logs (combined format).
    
    Very similar to Nginx but with slight format differences.
    """
    
    # Apache combined log format pattern
    LOG_PATTERN = re.compile(
        r'(?P<ip>[\d\.]+)\s+\S+\s+(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<uri>\S+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d+)\s+(?P<bytes>[\d-]+)\s+'
        r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
    )
    
    def parse_line(self, line: str, line_number: int) -> Optional[LogEvent]:
        """Parse Apache access log line into structured event."""
        
        match = self.LOG_PATTERN.search(line)
        if not match:
            return None
        
        data = match.groupdict()
        
        # Parse timestamp
        try:
            timestamp = datetime.strptime(
                data['timestamp'],
                '%d/%b/%Y:%H:%M:%S %z'
            )
        except ValueError:
            timestamp = None
        
        # Determine severity based on HTTP status code
        status_code = int(data['status'])
        if status_code >= 500:
            severity = "error"
        elif status_code >= 400:
            severity = "warning"
        else:
            severity = "info"
        
        # Handle '-' for bytes (Apache uses '-' when no bytes sent)
        bytes_value = 0 if data['bytes'] == '-' else int(data['bytes'])
        
        return LogEvent(
            timestamp=timestamp,
            log_type="apache",
            raw_line=line,
            parsed_data={
                "source_ip": data['ip'],
                "user": data['user'],
                "method": data['method'],
                "uri": data['uri'],
                "protocol": data['protocol'],
                "status_code": status_code,
                "bytes": bytes_value,
                "referrer": data['referrer'],
                "user_agent": data['user_agent']
            },
            severity=severity
        )


class LogParserFactory:
    """
    Factory to get appropriate parser for log type.
    
    Security: Whitelist approach - only returns parsers for known types.
    """
    
    _parsers = {
        "ssh": SSHLogParser,
        "nginx": NginxLogParser,
        "apache": ApacheLogParser
    }
    
    @classmethod
    def get_parser(cls, log_type: str) -> BaseLogParser:
        """
        Get parser instance for specified log type.
        
        Args:
            log_type: Type of log (must be in whitelist)
            
        Returns:
            Parser instance
            
        Raises:
            ValueError: If log type is not supported
        """
        parser_class = cls._parsers.get(log_type.lower())
        if parser_class is None:
            raise ValueError(f"No parser available for log type: {log_type}")
        
        return parser_class()
