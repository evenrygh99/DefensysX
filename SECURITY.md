<!-- @even rygh -->
# Security Architecture

## Overview

This document details the security design decisions and threat mitigations implemented in the SOC BYOL service.

## Threat Model

### Identified Threats

1. **DoS via Resource Exhaustion**
   - Large file uploads
   - Extremely long lines
   - Excessive line counts
   - Memory exhaustion from many sessions

2. **Code Injection**
   - Binary/executable uploads
   - Malicious log entries with executable code
   - Command injection via log type parameter

3. **Data Exfiltration**
   - Cross-session data access
   - Session ID guessing
   - Persistent storage of uploaded data

4. **Information Disclosure**
   - Detailed error messages
   - Stack traces in responses
   - Internal path disclosure

5. **Parser Exploits**
   - ReDoS (Regular Expression Denial of Service)
   - Buffer overflow in parsing
   - Encoding attacks

## Security Controls

### Input Validation

#### File Upload Validation
```
Layer 1: MIME Type Check
   |
   v
Layer 2: Size Limit (streaming)
   |
   v
Layer 3: Binary Detection
   |
   v
Layer 4: UTF-8 Encoding Validation
   |
   v
Layer 5: Line Constraints
   |
   v
Layer 6: Content Parsing (no execution)
```

**Why layered validation?**
- Defense in depth: If one layer fails, others catch the threat
- MIME type can be spoofed, so we validate actual content
- Streaming prevents memory exhaustion from large files
- Each layer addresses a specific attack vector

#### Log Type Validation

**Whitelist Approach**:
```python
allowed_log_types = {"ssh", "nginx", "apache"}
```

**Why whitelist?**
- Only accept known, safe formats
- Prevents arbitrary parser selection
- Each parser is security-reviewed
- Blacklist approach is inherently incomplete

### Session Isolation

**Design Principles**:
1. **Unique IDs**: UUID4 (cryptographically random)
   - 122 bits of entropy
   - Practically impossible to guess
   - No sequential patterns

2. **TTL Enforcement**: Automatic expiration
   - Default: 1 hour
   - Prevents indefinite memory growth
   - Forces cleanup of abandoned sessions

3. **Per-Session Limits**:
   - Max events: 50,000 per session
   - Prevents single session from exhausting memory
   - Allows fair resource sharing

4. **Memory Only**:
   - No disk persistence
   - Sensitive data never written to disk
   - No log file remnants after session expires

### Parser Security

#### ReDoS Prevention

**Threat**: Malicious regex patterns can cause exponential backtracking

**Mitigation**:
- All regex patterns pre-compiled
- Simple, non-backtracking patterns
- No user-provided regex
- Tested against pathological inputs

Example safe pattern:
```python
# Linear time complexity - no backtracking
PATTERN = re.compile(
    r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)'
)
```

#### No Code Execution

**Guarantee**: Parser never evaluates or executes user data

**How**:
- Regex extraction only
- No `eval()`, `exec()`, or similar
- No template rendering with user data
- Parsed data stored as plain strings/numbers

### Container Security

#### Dockerfile Security

```dockerfile
# Run as non-root user
USER socuser

# Read-only filesystem
read_only: true

# Drop all capabilities
cap_drop:
  - ALL

# No new privileges
security_opt:
  - no-new-privileges:true
```

**Why these measures?**
- **Non-root**: Limits damage if container is compromised
- **Read-only**: Prevents writing malicious files
- **No capabilities**: Removes privileged operations
- **No new privileges**: Prevents privilege escalation

#### Resource Limits

```yaml
resources:
  limits:
    cpus: '1.0'
    memory: 512M
```

**Purpose**:
- Prevents DoS from resource exhaustion
- Limits blast radius if compromised
- Ensures fair resource allocation

### API Security

#### CORS Policy

**Whitelist Only**:
```python
allow_origins = ["http://localhost:3000"]  # Explicit list
```

**Why**:
- Prevents unauthorized cross-origin requests
- Explicit is safer than wildcards
- Should be updated per deployment

#### Error Handling

**Production Mode**:
```python
return JSONResponse(
    status_code=500,
    content={"error": "Internal Server Error"}
)
```

**Why generic errors?**
- Prevents information leakage
- No stack traces exposed
- No internal paths revealed
- Full errors logged server-side only

### Memory Management

#### Streaming Processing

**Traditional Approach** (unsafe):
```python
content = await file.read()  # Loads entire file!
```

**Our Approach** (safe):
```python
while chunk := await file.read(8192):
    validate_chunk(chunk)  # Process incrementally
```

**Benefits**:
- Constant memory usage
- Can handle files near size limit
- Early rejection on violation

#### Automatic Cleanup

**Background Task**:
- Runs every 5 minutes
- Removes expired sessions
- Frees memory immediately
- Prevents memory leaks

**Session Lifecycle**:
```
Create -> Use -> Expire -> Auto-Delete
   v       v       v         v
 0min   15min   60min    60min+cleanup
```

## Attack Scenarios & Mitigations

### Scenario 1: Large File DoS

**Attack**: Upload 100MB file to exhaust memory

**Detection**:
- Streaming validator tracks total bytes
- Rejects at 5MB limit
- Returns 413 error

**Result**: OK - Attack blocked

### Scenario 2: Binary Exploit Upload

**Attack**: Upload executable disguised as text/plain

**Detection**:
1. MIME type check (can be spoofed)
2. Binary content detection (null bytes)
3. UTF-8 validation (fails for binary)

**Result**: OK - Attack blocked at multiple layers

### Scenario 3: ReDoS Attack

**Attack**: Log line crafted to cause regex backtracking

**Mitigation**:
- Pre-compiled patterns
- Linear-time regex
- Line length limit (10,000 chars)

**Result**: OK - Attack ineffective

### Scenario 4: Session Hijacking

**Attack**: Guess session IDs to access other users' data

**Mitigation**:
- UUID4 with 122 bits entropy
- Probability of collision: ~10^-36
- Sessions expire automatically

**Result**: OK - Practically impossible

### Scenario 5: Memory Exhaustion via Events

**Attack**: Upload file that parses to millions of events

**Mitigation**:
- Max 100,000 lines per file
- Max 50,000 events per session
- Early rejection when limit hit

**Result**: OK - Attack blocked

## Security Testing

### Recommended Tests

1. **Boundary Testing**:
   ```bash
   # Test exact size limit
   dd if=/dev/urandom of=5mb.txt bs=1M count=5
   # Test just over limit
   dd if=/dev/urandom of=5.1mb.txt bs=1M count=5 bs=102400
   ```

2. **Binary Upload**:
   ```bash
   curl -X POST -F "file=@/bin/bash" -F "log_type=ssh" ...
   # Expected: 400 Bad Request
   ```

3. **Encoding Attack**:
   ```bash
   # Create file with invalid UTF-8
   echo -ne '\xff\xfe\xfd' > invalid.txt
   # Upload should fail
   ```

4. **ReDoS Pattern**:
   ```bash
   # Create pathological line
   python -c "print('a' * 100000)" > long.txt
   # Should be rejected (line too long)
   ```

5. **Session Expiry**:
   ```bash
   # Upload file, note session ID
   # Wait > 1 hour
   # Attempt to retrieve session
   # Expected: 404 Not Found
   ```

## Compliance Considerations

### Data Privacy

- **No persistent storage**: GDPR "right to be forgotten" is automatic
- **Session isolation**: Each user's data is separate
- **Explicit deletion**: Users can delete sessions manually
- **Automatic expiry**: Data doesn't linger indefinitely

### Audit Trail

**Recommended Logging** (not yet implemented):
- Upload events (timestamp, file size, log type)
- Session creation/deletion
- Validation failures
- Error conditions
- Resource usage metrics

**Do NOT log**:
- Actual log content
- IP addresses (unless required)
- Session IDs in plaintext

## Future Security Enhancements

### Authentication
- API key validation
- Rate limiting per key
- OAuth2 integration

### Enhanced Monitoring
- Real-time resource usage alerts
- Anomaly detection (unusual upload patterns)
- Security event logging (SIEM integration)

### Additional Validation
- File signature verification
- Entropy analysis (detect encrypted/compressed)
- Content pattern matching (detect encoded binaries)

### Sandboxing
- Process isolation per session
- Dedicated worker processes
- Seccomp filters

## Security Contact

Report security issues to: [security contact - to be added]

## References

- OWASP Top 10
- CWE Top 25
- FastAPI Security (Tutorial: Security)
- Python Security Best Practices (Stdlib: security warnings)
