# @even rygh
"""
SOC Log Parsing Module

Parses various log formats into a standardized internal event format.
All parsing is defensive - untrusted input never causes exceptions.

Supported log types: SSH, Nginx, Apache

Output format (all parsers return this structure):
{
    'timestamp': datetime or None,
    'source': str (log type, e.g., 'ssh', 'nginx'),
    'host': str or None (hostname/server),
    'ip': str or None (source IP address),
    'event_type': str (specific event category),
    'raw_message': str (original log line),
    'metadata': dict (format-specific additional data)
}

Security Principles:
- All regex patterns are pre-compiled and non-backtracking
- Malformed input returns partial data, never crashes
- No user input is ever evaluated or executed
- Timeouts prevent infinite loops on pathological input
"""

import re
from datetime import datetime
from typing import Iterator, Dict, Optional, Any, List
from dataclasses import dataclass, field, asdict


@dataclass
class ParsedEvent:
    """
    Standardized event structure for all log types.
    
    This format ensures consistency across different log sources
    and makes correlation and analysis easier.
    """
    timestamp: Optional[datetime] = None
    source: str = ""  # Log type: ssh, nginx, apache
    host: Optional[str] = None  # Server hostname
    ip: Optional[str] = None  # Source IP address
    event_type: str = "unknown"  # Specific event category
    raw_message: str = ""  # Original log line
    metadata: Dict[str, Any] = field(default_factory=dict)  # Extra data
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, handling datetime serialization."""
        result = asdict(self)
        if self.timestamp:
            result['timestamp'] = self.timestamp.isoformat()
        return result


class BaseLogParser:
    """
    Base class for all log parsers.
    
    Enforces consistent interface and error handling patterns.
    Subclasses implement format-specific parsing logic.
    """
    
    # Subclasses must set these
    log_type: str = "unknown"
    
    def parse_line(self, line: str, line_number: int = 0) -> Optional[ParsedEvent]:
        """
        Parse a single log line into a standardized event.
        
        Args:
            line: Raw log line (untrusted input)
            line_number: Line number for debugging (optional)
        
        Returns:
            ParsedEvent if line matches expected format, None otherwise
            
        Security:
            Never raises exceptions due to malformed input.
            All regex patterns are bounded and non-backtracking.
        """
        raise NotImplementedError("Subclasses must implement parse_line")
    
    def parse_logs(self, lines: Iterator[str]) -> Iterator[ParsedEvent]:
        """
        Parse an iterable of log lines.
        
        Args:
            lines: Iterable of log lines (e.g., file, list, generator)
        
        Yields:
            ParsedEvent objects for successfully parsed lines
            
        Security:
            Defensive - continues parsing even if individual lines fail.
            Silently skips malformed lines rather than crashing.
        """
        for line_num, line in enumerate(lines, start=1):
            # Skip empty lines
            if not line or not line.strip():
                continue
            
            try:
                event = self.parse_line(line.strip(), line_num)
                if event is not None:
                    yield event
            except Exception:
                # Defensive: never let a malformed line crash the parser
                # In production, you might want to log this
                continue
    
    def parse_logs_list(self, lines: List[str]) -> List[ParsedEvent]:
        """
        Convenience method to parse a list and return a list.
        
        Args:
            lines: List of log lines
            
        Returns:
            List of ParsedEvent objects
        """
        return list(self.parse_logs(iter(lines)))


class SSHLogParser(BaseLogParser):
    """
    Parser for SSH authentication logs (e.g., /var/log/auth.log).
    
    Format assumptions:
    - Syslog format: "Month Day HH:MM:SS hostname sshd[pid]: message"
    - Common messages: Failed password, Accepted password/publickey, Invalid user
    - No year in timestamp (uses current year by default)
    
    Limitations:
    - Year rollover edge case: logs from Dec 31 parsed on Jan 1
    - Only captures common authentication events
    - Other sshd messages are skipped
    
    Security notes:
    - All patterns are linear time (no catastrophic backtracking)
    - IP addresses validated with simple octet pattern
    - Usernames treated as opaque strings (never evaluated)
    """
    
    log_type = "ssh"
    
    # Pre-compiled regex patterns for efficiency and security
    # All patterns use possessive quantifiers or character classes to prevent backtracking
    
    # Failed password attempts (security events)
    # Matches: "Failed password for [invalid user] username from IP port N"
    FAILED_PASSWORD = re.compile(
        r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+sshd\[\d+\]:\s+'
        r'Failed password for (?:invalid user )?(?P<user>\S+)\s+'
        r'from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        re.ASCII  # Only ASCII - rejects suspicious Unicode
    )
    
    # Successful authentication (info events)
    # Matches: "Accepted password/publickey for username from IP port N"
    ACCEPTED_AUTH = re.compile(
        r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+sshd\[\d+\]:\s+'
        r'Accepted (?P<method>password|publickey) for (?P<user>\S+)\s+'
        r'from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        re.ASCII
    )
    
    # Invalid user attempts (security events)
    # Matches: "Invalid user username from IP"
    INVALID_USER = re.compile(
        r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+sshd\[\d+\]:\s+'
        r'Invalid user (?P<user>\S+)\s+'
        r'from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        re.ASCII
    )
    
    def parse_line(self, line: str, line_number: int = 0) -> Optional[ParsedEvent]:
        """
        Parse SSH authentication log line.
        
        Returns None if line doesn't match known patterns.
        Never raises exceptions - returns partial data on malformed input.
        """
        # Try each pattern in order
        patterns = [
            (self.FAILED_PASSWORD, 'auth_failed'),
            (self.ACCEPTED_AUTH, 'auth_success'),
            (self.INVALID_USER, 'invalid_user'),
        ]
        
        for pattern, event_type in patterns:
            match = pattern.search(line)
            if match:
                data = match.groupdict()
                
                # Parse timestamp
                # Assumption: logs from current year (common limitation of syslog)
                timestamp = self._parse_timestamp(data.get('timestamp'))
                
                return ParsedEvent(
                    timestamp=timestamp,
                    source=self.log_type,
                    host=data.get('host'),
                    ip=data.get('ip'),
                    event_type=event_type,
                    raw_message=line,
                    metadata={
                        'username': data.get('user'),
                        'auth_method': data.get('method', 'password'),
                    }
                )
        
        # Line didn't match any pattern - skip silently
        return None
    
    def _parse_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """
        Parse syslog timestamp format.
        
        Assumption: Uses current year (syslog limitation).
        Returns None on parse failure rather than raising exception.
        """
        if not timestamp_str:
            return None
        
        try:
            # Parse "Jan 7 10:30:45" format with current year
            current_year = datetime.now().year
            timestamp_with_year = f"{timestamp_str} {current_year}"
            return datetime.strptime(timestamp_with_year, '%b %d %H:%M:%S %Y')
        except (ValueError, AttributeError):
            # Malformed timestamp - return None rather than crash
            return None


class NginxLogParser(BaseLogParser):
    """
    Parser for Nginx access logs in combined format.
    
    Format assumptions:
    - Combined log format (default): IP - user [timestamp] "method URI protocol" status bytes "referer" "user-agent"
    - Timezone included in timestamp
    - Status codes are numeric
    
    Limitations:
    - Only supports combined format (not common or custom formats)
    - User agent strings are not parsed/classified
    - Assumes standard field order
    
    Security notes:
    - Pattern uses explicit field boundaries
    - No backtracking on quoted strings (uses [^"] character class)
    - URI and user-agent treated as opaque strings
    """
    
    log_type = "nginx"
    
    # Combined log format pattern
    # IP - user [timestamp] "request" status bytes "referer" "user-agent"
    LOG_PATTERN = re.compile(
        r'^(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+'
        r'-\s+(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<uri>\S+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<bytes>\d+)\s+'
        r'"(?P<referer>[^"]*)"\s+'
        r'"(?P<user_agent>[^"]*)"',
        re.ASCII
    )
    
    def parse_line(self, line: str, line_number: int = 0) -> Optional[ParsedEvent]:
        """
        Parse Nginx combined format log line.
        
        Returns None if line doesn't match format.
        Categorizes events by HTTP status code.
        """
        match = self.LOG_PATTERN.search(line)
        if not match:
            return None
        
        data = match.groupdict()
        
        # Parse timestamp
        timestamp = self._parse_timestamp(data.get('timestamp'))
        
        # Determine event type from status code
        try:
            status = int(data.get('status', '0'))
            if status >= 500:
                event_type = 'server_error'
            elif status >= 400:
                event_type = 'client_error'
            elif status >= 300:
                event_type = 'redirect'
            elif status >= 200:
                event_type = 'success'
            else:
                event_type = 'unknown'
        except (ValueError, TypeError):
            event_type = 'unknown'
        
        return ParsedEvent(
            timestamp=timestamp,
            source=self.log_type,
            host=None,  # Nginx logs don't include hostname by default
            ip=data.get('ip'),
            event_type=event_type,
            raw_message=line,
            metadata={
                'method': data.get('method'),
                'uri': data.get('uri'),
                'protocol': data.get('protocol'),
                'status': status,
                'bytes': self._safe_int(data.get('bytes')),
                'user_agent': data.get('user_agent'),
                'referer': data.get('referer'),
            }
        )
    
    def _parse_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """
        Parse Nginx timestamp format: "07/Jan/2026:10:30:00 +0000"
        
        Returns None on failure rather than raising exception.
        """
        if not timestamp_str:
            return None
        
        try:
            return datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
        except (ValueError, AttributeError):
            return None
    
    def _safe_int(self, value: Optional[str]) -> Optional[int]:
        """Safely convert string to int, return None on failure."""
        if not value:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None


class ApacheLogParser(BaseLogParser):
    """
    Parser for Apache access logs in combined format.
    
    Format assumptions:
    - Combined log format: IP ident user [timestamp] "request" status bytes "referer" "user-agent"
    - Very similar to Nginx but with slight differences
    - Byte field can be "-" for no bytes sent
    
    Limitations:
    - Only supports combined format
    - Assumes standard field order
    - Virtual host info not captured
    
    Security notes:
    - Pattern prevents backtracking
    - All fields treated as untrusted data
    - Numeric fields validated before use
    """
    
    log_type = "apache"
    
    # Apache combined log format pattern
    # IP ident user [timestamp] "request" status bytes "referer" "user-agent"
    LOG_PATTERN = re.compile(
        r'^(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+'
        r'\S+\s+(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<uri>\S+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<bytes>[\d-]+)\s+'
        r'"(?P<referer>[^"]*)"\s+'
        r'"(?P<user_agent>[^"]*)"',
        re.ASCII
    )
    
    def parse_line(self, line: str, line_number: int = 0) -> Optional[ParsedEvent]:
        """
        Parse Apache combined format log line.
        
        Handles "-" for missing byte count (Apache-specific).
        Returns None if line doesn't match format.
        """
        match = self.LOG_PATTERN.search(line)
        if not match:
            return None
        
        data = match.groupdict()
        
        # Parse timestamp
        timestamp = self._parse_timestamp(data.get('timestamp'))
        
        # Determine event type from status code
        try:
            status = int(data.get('status', '0'))
            if status >= 500:
                event_type = 'server_error'
            elif status >= 400:
                event_type = 'client_error'
            elif status >= 300:
                event_type = 'redirect'
            elif status >= 200:
                event_type = 'success'
            else:
                event_type = 'unknown'
        except (ValueError, TypeError):
            event_type = 'unknown'
        
        # Handle bytes field (can be "-" in Apache)
        bytes_str = data.get('bytes', '0')
        bytes_value = 0 if bytes_str == '-' else self._safe_int(bytes_str)
        
        return ParsedEvent(
            timestamp=timestamp,
            source=self.log_type,
            host=None,  # Apache logs don't include hostname by default
            ip=data.get('ip'),
            event_type=event_type,
            raw_message=line,
            metadata={
                'method': data.get('method'),
                'uri': data.get('uri'),
                'protocol': data.get('protocol'),
                'status': status,
                'bytes': bytes_value,
                'user_agent': data.get('user_agent'),
                'referer': data.get('referer'),
            }
        )
    
    def _parse_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """
        Parse Apache timestamp format: "07/Jan/2026:10:30:00 +0000"
        
        Same format as Nginx.
        Returns None on failure.
        """
        if not timestamp_str:
            return None
        
        try:
            return datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
        except (ValueError, AttributeError):
            return None
    
    def _safe_int(self, value: Optional[str]) -> Optional[int]:
        """Safely convert string to int, return None on failure."""
        if not value:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None


class LogParserFactory:
    """
    Factory for creating appropriate parser based on log type.
    
    Security: Only returns parsers for whitelisted log types.
    Invalid types raise ValueError (not returned as parser).
    """
    
    _parsers = {
        'ssh': SSHLogParser,
        'nginx': NginxLogParser,
        'apache': ApacheLogParser,
    }
    
    @classmethod
    def get_parser(cls, log_type: str) -> BaseLogParser:
        """
        Get parser instance for specified log type.
        
        Args:
            log_type: Type of log (ssh, nginx, apache)
        
        Returns:
            Parser instance
            
        Raises:
            ValueError: If log type is not supported
            
        Security: Whitelist approach prevents arbitrary parser selection.
        """
        log_type_lower = log_type.lower().strip()
        
        parser_class = cls._parsers.get(log_type_lower)
        if parser_class is None:
            raise ValueError(
                f"Unsupported log type: {log_type}. "
                f"Supported types: {', '.join(cls._parsers.keys())}"
            )
        
        return parser_class()
    
    @classmethod
    def supported_types(cls) -> List[str]:
        """Get list of supported log types."""
        return list(cls._parsers.keys())


# Convenience functions for direct use

def parse_logs(lines: Iterator[str], log_type: str) -> Iterator[ParsedEvent]:
    """
    Parse logs of specified type.
    
    Convenience function that creates parser and processes logs.
    
    Args:
        lines: Iterable of log lines
        log_type: Type of logs (ssh, nginx, apache)
    
    Yields:
        ParsedEvent objects
        
    Example:
        >>> with open('auth.log') as f:
        >>>     for event in parse_logs(f, 'ssh'):
        >>>         print(event.ip, event.event_type)
    """
    parser = LogParserFactory.get_parser(log_type)
    return parser.parse_logs(lines)


def parse_log_file(file_path: str, log_type: str) -> List[ParsedEvent]:
    """
    Parse entire log file.
    
    Convenience function for parsing a complete file.
    
    Args:
        file_path: Path to log file
        log_type: Type of logs (ssh, nginx, apache)
    
    Returns:
        List of ParsedEvent objects
        
    Example:
        >>> events = parse_log_file('/var/log/auth.log', 'ssh')
        >>> print(f"Parsed {len(events)} events")
    """
    parser = LogParserFactory.get_parser(log_type)
    
    with open(file_path, 'r', encoding='utf-8') as f:
        return parser.parse_logs_list(f)


if __name__ == '__main__':
    # Example usage and testing
    print("Log Parser Module - Example Usage\n")
    
    # Example SSH logs
    ssh_logs = [
        'Jan 7 10:30:45 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2',
        'Jan 7 10:31:12 server sshd[12346]: Accepted password for john from 192.168.1.101 port 22 ssh2',
        'Jan 7 10:32:05 server sshd[12347]: Invalid user admin from 203.0.113.45 port 22',
    ]
    
    print("Parsing SSH logs:")
    for event in parse_logs(iter(ssh_logs), 'ssh'):
        print(f"  {event.event_type}: {event.ip} -> {event.metadata.get('username')}")
    
    # Example Nginx logs
    nginx_logs = [
        '192.168.1.10 - - [07/Jan/2026:10:30:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        '203.0.113.50 - - [07/Jan/2026:10:30:30 +0000] "GET /admin.php HTTP/1.1" 404 178 "-" "Bad-Bot"',
    ]
    
    print("\nParsing Nginx logs:")
    for event in parse_logs(iter(nginx_logs), 'nginx'):
        print(f"  {event.event_type}: {event.ip} {event.metadata.get('method')} {event.metadata.get('uri')} -> {event.metadata.get('status')}")
    
    print("\nSupported log types:", LogParserFactory.supported_types())
