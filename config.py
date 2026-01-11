# @even rygh
"""
Configuration management for SOC platform.
All security-critical settings are centralized here for easy auditing.
"""
from pydantic_settings import BaseSettings
from typing import Optional, Set


class Settings(BaseSettings):
    """
    Application settings with security defaults.
    Uses Pydantic for validation - invalid configs will fail fast at startup.
    """
    
    # Application
    app_name: str = "SOC Platform - BYOL Service"
    app_version: str = "1.0.0"
    debug: bool = True  # Enable for development

    # Development server behavior
    # NOTE: Auto-reload can be very unstable on Windows when the project is
    # located in a OneDrive-synced folder (lots of file change events).
    # Keep it opt-in to avoid random restarts during uploads.
    uvicorn_reload: bool = False

    # Simulation abuse protection
    # These apply to /simulate/* endpoints only.
    # - Rate limit is enabled by default in production (debug=False).
    #   In development/tests (debug=True) it is disabled by default to avoid follow-on failures.
    #   You can override with SIMULATION_RATE_LIMIT_ENABLED=true/false.
    # - Token gate is optional: if set, requests must include header X-Simulation-Token.
    simulation_rate_limit_enabled: Optional[bool] = None
    # Default: allow ~2 full rounds of all current attacks (6*2=12) before cooldown.
    simulation_rate_limit_requests: int = 12
    simulation_rate_limit_period_seconds: int = 30
    simulation_token: Optional[str] = None
    
    # API Security
    api_key_header: str = "X-API-Key"
    cors_origins: list[str] = [
        "http://localhost:3000",
        "http://localhost:8080",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8080",
        "null",
    ]  # Allow file:// (null origin)

    # When debug=False, these are used by FastAPI TrustedHostMiddleware
    # (Host header protection). Keep in sync with the domains you serve.
    allowed_hosts: list[str] = [
        "localhost",
        "127.0.0.1",
    ]
    
    # File Upload Security Limits
    # Prevent DoS attacks via large file uploads
    max_file_size_bytes: int = 5 * 1024 * 1024  # 5MB hard limit
    
    # Prevent memory exhaustion from maliciously long lines
    max_line_length: int = 10_000  # characters per line
    
    # Prevent processing of excessively large log sets
    max_lines_per_file: int = 100_000  # total lines per upload
    
    # Allowed log types - whitelist approach for security
    # Only accept known, parseable log formats
    allowed_log_types: Set[str] = {"ssh", "nginx", "apache"}
    
    # File validation
    # Accept both text/plain and application/octet-stream (browsers send .log as octet-stream)
    allowed_mime_types: Set[str] = {"text/plain", "application/octet-stream"}
    required_encoding: str = "utf-8"
    
    # Session Management
    # Auto-cleanup prevents storage exhaustion
    session_ttl_seconds: int = 3600  # 1 hour - sessions expire automatically
    session_cleanup_interval_seconds: int = 300  # Run cleanup every 5 minutes
    
    # Memory limits per session to prevent resource exhaustion
    max_events_per_session: int = 50_000  # parsed events limit
    
    # Storage
    # BYOL uses in-memory only - no disk persistence
    use_disk_storage: bool = False  # BYOL always uses memory
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = Settings()
