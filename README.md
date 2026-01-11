<!-- @even rygh -->
# SOC Platform - BYOL Service

A security-focused "Bring Your Own Logs" (BYOL) analysis service built with FastAPI. This service provides secure log ingestion, parsing, and temporary analysis with strict security controls and zero-trust principles.

##  Security Features

- **Streaming Validation**: Files are processed in chunks, never fully loaded into memory
- **Multiple Validation Layers**: Size, encoding, format, and content validation
- **No Disk Persistence**: All data stored in memory only
- **Automatic Expiration**: Sessions auto-expire after configurable TTL (default: 1 hour)
- **Resource Limits**: Per-session event limits prevent memory exhaustion
- **Whitelist Approach**: Only pre-approved log types accepted
- **Input Sanitization**: All user input validated and sanitized
- **Binary Detection**: Rejects binary files and executables
- **Non-Root Container**: Docker runs as unprivileged user
- **Read-Only Filesystem**: Container filesystem is read-only

## Supported Log Types

- **SSH** (`ssh`): Authentication logs from /var/log/auth.log
- **Nginx** (`nginx`): Access logs in combined format
- **Apache** (`apache`): Access logs in combined format
- **Auto** (`auto`): Auto-detect based on content (recommended if unsure)

## Quick Start

### Local Development

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

  For running tests:
  ```bash
  pip install -r requirements-dev.txt
  ```

> Tip: If you use GitHub "Download ZIP", this repo is configured to export a minimal runtime package
> (tests/deploy/demo folders excluded) via `.gitattributes`.

2. **Configure environment** (optional):
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

3. **Run the service**:
   ```bash
   python main.py
   ```

   Or with uvicorn directly:
   ```bash
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

4. **Access the API**:
   - API: http://localhost:8000
   - Docs: http://localhost:8000/docs (dev mode only)
   - Health: http://localhost:8000/health

### Docker Deployment

1. **Build and run with Docker Compose**:
   ```bash
   docker-compose up -d
   ```

2. **View logs**:
   ```bash
   docker-compose logs -f
   ```

3. **Stop the service**:
   ```bash
   docker-compose down
   ```

## API Usage

### Upload Logs

Upload a log file for analysis:

```bash
curl -X POST "http://localhost:8000/byol/upload" \
  -F "file=@/path/to/logs.txt" \
  -F "log_type=ssh"
```

**Response**:
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "log_type": "ssh",
  "status": "uploaded",
  "summary": {
    "total_lines": 1000,
    "parsed_events": 950,
    "skipped_lines": 50,
    "file_size_bytes": 102400
  },
  "session_info": {
    "expires_at": "2026-01-07T13:00:00",
    "ttl_seconds": 3600
  }
}
```

### Retrieve Results

Get parsed events for a session:

```bash
curl "http://localhost:8000/byol/session/550e8400-e29b-41d4-a716-446655440000"
```

### Delete Session

Manually cleanup a session:

```bash
curl -X DELETE "http://localhost:8000/byol/session/550e8400-e29b-41d4-a716-446655440000"
```

### Service Statistics

Get current service stats:

```bash
curl "http://localhost:8000/byol/stats"
```

## Configuration

Key settings in [config.py](config.py):

| Setting | Default | Description |
|---------|---------|-------------|
| `max_file_size_bytes` | 5MB | Maximum upload file size |
| `max_line_length` | 10,000 | Maximum characters per line |
| `max_lines_per_file` | 100,000 | Maximum lines per file |
| `session_ttl_seconds` | 3,600 | Session expiration time |
| `max_events_per_session` | 50,000 | Maximum parsed events per session |

## Security Considerations

### Input Validation

Every uploaded file goes through multiple validation stages:

1. **MIME Type Check**: Only `text/plain` accepted
2. **Size Limit**: Enforced during streaming (5MB default)
3. **Binary Detection**: Checks for null bytes and non-printable characters
4. **Encoding Validation**: Must be valid UTF-8
5. **Line Constraints**: Length and count limits enforced
6. **Log Type Whitelist**: Only pre-approved formats accepted

### Session Isolation

Each upload is isolated in its own session:
- Unique UUID session ID (cryptographically random)
- Automatic expiration after TTL
- Per-session resource limits
- No cross-session data access

### Memory Safety

- **No disk persistence**: All data stored in memory only
- **Streaming processing**: Files never fully loaded
- **Automatic cleanup**: Background task removes expired sessions
- **Resource limits**: Per-session event caps prevent exhaustion

### Container Security

- Runs as non-root user (`socuser`)
- Read-only root filesystem
- Dropped capabilities
- No new privileges flag
- Resource limits (CPU, memory)

## Testing

Install test dependencies:
```bash
pip install -r requirements-dev.txt
```

### Test with Sample Logs

**SSH logs** (`test_ssh.log`):
```
Jan 7 10:30:45 server sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2
Jan 7 10:31:12 server sshd[12346]: Accepted password for john from 192.168.1.101 port 22 ssh2
```

**Upload**:
```bash
curl -X POST "http://localhost:8000/byol/upload" \
  -F "file=@test_ssh.log" \
  -F "log_type=ssh"
```

### Validation Testing

Test file size limit:
```bash
# Generate large file (>5MB)
dd if=/dev/zero of=large.txt bs=1M count=6
curl -X POST "http://localhost:8000/byol/upload" \
  -F "file=@large.txt" \
  -F "log_type=ssh"
# Expected: 413 Request Entity Too Large
```

Test invalid log type:
```bash
curl -X POST "http://localhost:8000/byol/upload" \
  -F "file=@test_ssh.log" \
  -F "log_type=invalid"
# Expected: 400 Bad Request
```

Test binary file:
```bash
curl -X POST "http://localhost:8000/byol/upload" \
  -F "file=@/bin/ls" \
  -F "log_type=ssh"
# Expected: 400 Bad Request (binary content)
```

## Roadmap

See [ROADMAP.md](ROADMAP.md) for prioritized next steps (stability, security, detection quality, scaling).

## Monitoring

### Health Check

```bash
curl http://localhost:8000/health
```

### Service Statistics

```bash
curl http://localhost:8000/byol/stats
```

**Response**:
```json
{
  "total_sessions": 5,
  "total_events_in_memory": 12500,
  "sessions_by_age": {
    "< 5min": 2,
    "5-15min": 2,
    "15-30min": 1,
    "> 30min": 0
  },
  "cleanup_interval_seconds": 300
}
```

## Development

### Project Structure

```
SOC/
|-- main.py                 # FastAPI application entry point
|-- config.py              # Configuration management
|-- byol_routes.py         # BYOL API endpoints
|-- validators.py          # File validation utilities
|-- session_manager.py     # Session lifecycle management
|-- parsers.py            # Log parsing for different formats
|-- requirements.txt      # Python dependencies
|-- Dockerfile           # Container image definition
|-- docker-compose.yml   # Docker Compose configuration
`-- .env.example        # Environment variable template
```

### Adding New Log Types

1. Create parser in [parsers.py](parsers.py):
   ```python
   class NewLogParser(BaseLogParser):
       def parse_line(self, line: str, line_number: int) -> Optional[LogEvent]:
           # Implement parsing logic
           pass
   ```

2. Register in `LogParserFactory`:
   ```python
   _parsers = {
       "ssh": SSHLogParser,
       "nginx": NginxLogParser,
       "apache": ApacheLogParser,
       "newtype": NewLogParser  # Add here
   }
   ```

3. Update whitelist in [config.py](config.py):
   ```python
   allowed_log_types: Set[str] = {"ssh", "nginx", "apache", "newtype"}
   ```

## Troubleshooting

### File Upload Fails

**Error**: `413 Request Entity Too Large`
- **Cause**: File exceeds 5MB limit
- **Solution**: Split file or increase `max_file_size_bytes` in config

**Error**: `400 Bad Request: File must be UTF-8 encoded text`
- **Cause**: File is not valid UTF-8 or is binary
- **Solution**: Ensure file is plain text with UTF-8 encoding

### Session Not Found

**Error**: `404 Not Found: Session not found or expired`
- **Cause**: Session expired (default TTL: 1 hour)
- **Solution**: Re-upload logs or increase `session_ttl_seconds`

### Parser Returns Few Events

**Issue**: Many lines marked as "skipped"
- **Cause**: Log format doesn't match expected patterns
- **Solution**: Verify log type is correct and logs match expected format

## License

This is a demonstration project for educational purposes.

## Contributing

This is a learning project. Security improvements and bug reports welcome!

## Production Deployment Checklist

Before deploying to production:

- [ ] Set `DEBUG=false`
- [ ] Update `CORS_ORIGINS` with actual frontend URL
- [ ] Configure `TrustedHostMiddleware` with production hosts
- [ ] Review and adjust resource limits
- [ ] Set up proper logging and monitoring
- [ ] Configure HTTPS/TLS termination
- [ ] Review and adjust TTL settings
- [ ] Implement rate limiting
- [ ] Add authentication/API keys
- [ ] Regular security audits
- [ ] Backup and disaster recovery plan
