<!-- @even rygh -->
# Quick Start Guide

This guide will help you get the BYOL service running in under 5 minutes.

## Prerequisites

- Python 3.11+
- curl or Postman (for testing)

## Option 1: Local Python Development

### 1. Install Dependencies

```powershell
# Navigate to project directory
cd "<path-to-project>"

# Install requirements
pip install -r requirements.txt

# (Optional) Install test dependencies
pip install -r requirements-dev.txt
```

### 2. Run the Service

```powershell
# Start the server
python main.py
```

The service will be available at http://localhost:8000

If you also want to run the frontend locally:

```powershell
# Option A: one-click (Windows)
start.bat

# Option B: manual
python serve_frontend.py
```

### 3. Quick test (no files)

Use the built-in demo-safe simulation endpoints to generate logs and analyze them:

```powershell
curl -X POST "http://localhost:8000/simulate/attack/quick/port_scan"

# Or list all available simulations
curl http://localhost:8000/simulate/attacks

# Upload log
curl -X POST "http://localhost:8000/byol/upload" `
  -F "file=@PATH-TO-YOUR-LOG-FILE.log" `
  -F "log_type=ssh"
```

## Testing Different Log Types

If you don't have logs handy, you can generate tiny sample logs locally and upload them.

```powershell
# Create sample SSH log
@'
Jan 01 00:00:01 demo sshd[1234]: Failed password for invalid user admin from 203.0.113.10 port 2222 ssh2
'@ | Set-Content -Path .\sample_ssh.log -Encoding utf8

# Create sample Nginx access log
@'
203.0.113.10 - - [01/Jan/2026:00:00:01 +0000] "GET /wp-login.php HTTP/1.1" 404 123 "-" "Mozilla/5.0"
'@ | Set-Content -Path .\sample_nginx.log -Encoding utf8

# Create sample Apache access log
@'
203.0.113.10 - - [01/Jan/2026:00:00:01 +0000] "GET /phpmyadmin/ HTTP/1.1" 404 123
'@ | Set-Content -Path .\sample_apache.log -Encoding utf8
```

### SSH Logs
```powershell
curl -X POST "http://localhost:8000/byol/upload" `
  -F "file=@sample_ssh.log" `
  -F "log_type=ssh"
```

### Nginx Logs
```powershell
curl -X POST "http://localhost:8000/byol/upload" `
  -F "file=@sample_nginx.log" `
  -F "log_type=nginx"
```

### Apache Logs
```powershell
curl -X POST "http://localhost:8000/byol/upload" `
  -F "file=@sample_apache.log" `
  -F "log_type=apache"
```

## Retrieve Results

After uploading, save the `session_id` from the response:

```powershell
# Get session results
curl "http://localhost:8000/byol/session/YOUR-SESSION-ID"
```

## View API Documentation

When running in debug mode, visit:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Common Commands

```powershell
# Check service stats
curl http://localhost:8000/byol/stats

# Delete a session
curl -X DELETE "http://localhost:8000/byol/session/YOUR-SESSION-ID"

# Stop the API server
# - If you started it in the terminal: press Ctrl+C
# - If you started via the helper script: run .\stop.bat
```

## Troubleshooting

**Service won't start:**
- Check if port 8000 is already in use
- Verify Python version: `python --version` (need 3.11+)
- Check dependencies: `pip list`

**Upload fails:**
- Verify file is UTF-8 text
- Check file size < 5MB
- Ensure log_type is valid (ssh, nginx, apache)

**Can't connect:**
- Verify service is running: `curl http://localhost:8000/health`
- Check firewall settings
- Use `0.0.0.0` to bind all interfaces

## Next Steps

- Read [README.md](README.md) for detailed documentation
- Review [SECURITY.md](SECURITY.md) for security architecture
- Run tests: `pip install -r requirements-dev.txt ; pytest -q`
- Explore API at http://localhost:8000/docs
