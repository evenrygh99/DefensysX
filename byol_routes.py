# @even rygh
"""
BYOL (Bring Your Own Logs) API endpoints.
Provides secure log upload and analysis functionality.
"""
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, status
from typing import Dict, List, Any

from validators import FileValidator, StreamingFileValidator
from session_manager import session_manager, LogEvent
from parsers import LogParserFactory
from config import settings

# Import detection engine for security analysis
from detection_engine import DetectionEngine, analyze_events
from log_parser import ParsedEvent


router = APIRouter(
    prefix="/byol",
    tags=["BYOL"],
    responses={
        413: {"description": "File too large"},
        415: {"description": "Unsupported media type"},
        400: {"description": "Validation error"}
    }
)


@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_logs(
    file: UploadFile = File(..., description="Log file to analyze (text/plain, max 5MB)"),
    log_type: str = Form("auto", description="Type of logs: ssh, nginx, apache, or auto")
) -> Dict[str, Any]:
    """
    Upload and analyze log files.
    
    Security features:
    - Streaming validation (never loads full file into memory)
    - Multiple layers of validation (size, encoding, format, content)
    - Per-session isolation with automatic expiration
    - No disk persistence (memory only)
    - Comprehensive input sanitization
    
    Process:
    1. Validate log type against whitelist
    2. Validate file MIME type
    3. Stream file content with size/encoding validation
    4. Parse each line without executing any user data
    5. Store parsed events in isolated session
    6. Return session ID for result retrieval
    
    Args:
        file: Uploaded log file (multipart/form-data)
        log_type: Type of log format (ssh|nginx|apache)
    
    Returns:
        JSON with session_id and upload summary
        
    Raises:
        HTTPException: Various 4xx codes for validation failures
    """
    
    log_type_lower = (log_type or "").lower().strip()
    validated_log_type = None
    if log_type_lower and log_type_lower != "auto":
        # SECURITY: Validate log type against whitelist FIRST
        # Prevents any processing if log type is invalid
        try:
            validated_log_type = FileValidator.validate_log_type(log_type)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid log_type parameter: {str(e)}"
            )
    
    # SECURITY: Validate MIME type before reading content
    # First line of defense against binary/executable uploads
    try:
        FileValidator.validate_content_type(file)
    except HTTPException:
        raise
    
    # SECURITY: Streaming validation to prevent memory exhaustion
    # Process file in chunks, never loading entire file at once
    validator = StreamingFileValidator()
    all_lines: List[str] = []
    
    try:
        # Read and validate file in chunks
        chunk_size = 8192  # 8KB chunks
        while True:
            chunk = await file.read(chunk_size)
            if not chunk:
                break
            
            # Validate this chunk and get complete lines
            complete_lines = await validator.validate_chunk(chunk)
            all_lines.extend(complete_lines)
        
        # Process any remaining buffered data
        final_lines = validator.finalize()
        all_lines.extend(final_lines)
        
    except HTTPException:
        # Re-raise validation errors with context
        raise
    except Exception as e:
        # Catch any unexpected errors during streaming
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error processing file: {str(e)}"
        )
    finally:
        # SECURITY: Always close file handle
        await file.close()

    # If log_type=auto, decide based on content.
    if validated_log_type is None:
        validated_log_type = FileValidator.auto_detect_log_type(all_lines)
    
    # Create isolated session for this upload
    # Each upload gets its own session with automatic TTL
    session = session_manager.create_session(validated_log_type)
    
    # Get appropriate parser for this log type
    try:
        parser = LogParserFactory.get_parser(validated_log_type)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    
    # Parse each line and store events
    # SECURITY: Parser never executes user data, only extracts patterns
    parsed_count = 0
    skipped_count = 0
    
    for line_num, line in enumerate(all_lines, start=1):
        # Skip empty lines
        if not line.strip():
            skipped_count += 1
            continue
        
        try:
            # Parse line into structured event
            event = parser.parse_line(line, line_num)
            
            if event is not None:
                # SECURITY: Enforce per-session event limit
                session.add_event(event)
                parsed_count += 1
            else:
                # Line didn't match expected format
                skipped_count += 1
                
        except ValueError as e:
            # Hit session event limit
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
        except Exception as e:
            # Unexpected parsing error - skip this line but continue
            skipped_count += 1
    
    # Run security detection analysis on parsed events
    # Convert LogEvents to ParsedEvents for detection engine
    detection_events = []
    for log_event in session.events:
        parsed_data = log_event.parsed_data
        
        # Map old parser fields to detection engine fields
        # Old parsers use source_ip, client_ip, etc
        ip = (parsed_data.get('ip') or 
              parsed_data.get('source_ip') or 
              parsed_data.get('client_ip'))
        
        host = (parsed_data.get('host') or 
                parsed_data.get('hostname'))
        
        # Map event types
        event_type = parsed_data.get('event_type', 'unknown')
        # Old parsers use 'failed_password', detection engine expects 'auth_failed'
        if event_type == 'failed_password':
            event_type = 'auth_failed'
        elif event_type == 'accepted_auth':
            event_type = 'auth_success'
        
        detection_event = ParsedEvent(
            timestamp=log_event.timestamp,
            source=validated_log_type,
            host=host,
            ip=ip,
            event_type=event_type,
            raw_message=log_event.raw_line,
            metadata=parsed_data
        )
        detection_events.append(detection_event)
    
    # Run detection engine
    alerts = analyze_events(detection_events)
    
    # Store alerts in session
    session.alerts = alerts
    
    # Update metadata with detection summary
    session.metadata['detection_summary'] = {
        'alerts_generated': len(alerts),
        'severity_distribution': {},
        'affected_ips': list(set(
            ip for alert in alerts 
            for ip in alert.affected_ips
        ))
    }
    
    # Count by severity
    for alert in alerts:
        severity = alert.severity.value
        session.metadata['detection_summary']['severity_distribution'][severity] = \
            session.metadata['detection_summary']['severity_distribution'].get(severity, 0) + 1
    
    # Return session details to client
    return {
        "session_id": session.session_id,
        "log_type": validated_log_type,
        "status": "completed",
        "summary": {
            "total_lines": len(all_lines),
            "parsed_events": parsed_count,
            "skipped_lines": skipped_count,
            "file_size_bytes": validator.total_bytes
        },
        "detection": session.metadata.get('detection_summary', {}),
        "session_info": {
            "expires_at": session.expires_at.isoformat(),
            "ttl_seconds": settings.session_ttl_seconds
        },
        "next_steps": {
            "retrieve_events": f"/byol/session/{session.session_id}",
            "retrieve_alerts": f"/byol/{session.session_id}/alerts",
            "delete_session": f"/byol/session/{session.session_id}"
        }
    }


@router.get("/session/{session_id}")
async def get_session(session_id: str) -> Dict[str, Any]:
    """
    Retrieve analysis results for a session.
    
    Security:
    - Session IDs are UUIDs (hard to guess)
    - Sessions auto-expire after TTL
    - Only returns data for valid, non-expired sessions
    
    Args:
        session_id: UUID of upload session
        
    Returns:
        Session data and parsed events
        
    Raises:
        404: Session not found or expired
    """

    session = session_manager.get_session(session_id)
    
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or expired"
        )
    
    # Return session summary and events
    return {
        "session": session.get_summary(),
        "events": [
            {
                "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                "severity": event.severity,
                "log_type": event.log_type,
                "parsed_data": event.parsed_data,
                # Optionally include raw line (might be large)
                # "raw_line": event.raw_line
            }
            for event in session.events
        ]
    }


@router.get("/sessions")
async def list_sessions(limit: int = 50) -> Dict[str, Any]:
    """List active sessions (newest-first).

    Intended for SOC dashboards to show recent analyses.
    """
    sessions = session_manager.list_sessions(limit=limit)

    def _summary(s) -> Dict[str, Any]:
        detection = s.metadata.get("detection_summary", {}) if isinstance(s.metadata, dict) else {}
        return {
            "session_id": s.session_id,
            "log_type": s.log_type,
            "created_at": s.created_at.isoformat(),
            "expires_at": s.expires_at.isoformat(),
            "alerts_generated": detection.get(
                "alerts_generated", len(getattr(s, "alerts", []) or [])
            ),
            "severity_distribution": detection.get("severity_distribution", {}),
            "metadata": s.metadata,
        }

    return {"count": len(sessions), "sessions": [_summary(s) for s in sessions]}


@router.delete("/session/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_session(session_id: str):
    """
    Manually delete a session and all associated data.
    
    Security:
    - Allows users to explicitly cleanup their data
    - Immediately frees memory
    
    Args:
        session_id: UUID of session to delete
        
    Returns:
        204 No Content on success
        
    Raises:
        404: Session not found
    """
    deleted = session_manager.delete_session(session_id)
    
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    return None


@router.get("/{session_id}/alerts")
async def get_session_alerts(session_id: str) -> Dict[str, Any]:
    """
    Retrieve security alerts and analysis results for a session.
    
    This endpoint provides read-only access to detection engine results,
    including security alerts, event summaries, and analysis metadata.
    
    Security:
    - Session IDs are UUIDs (unpredictable, hard to guess)
    - Sessions auto-expire after TTL (default 1 hour)
    - Only returns data for valid, non-expired sessions
    - Explicit session isolation - no cross-session data leakage
    - No data modification - read-only access only
    
    Args:
        session_id: UUID of upload session
        
    Returns:
        JSON containing:
        - alerts: List of security alerts with full details
        - summary: Analysis statistics (event counts, severity distribution)
        - session_info: Session metadata (creation time, expiration, log type)
        - timestamps: Time range of analyzed logs
        
    Raises:
        HTTPException 404: Session not found or expired
        HTTPException 400: Invalid session ID format
        
    Example Response:
        {
            "session_id": "123e4567-e89b-12d3-a456-426614174000",
            "session_info": {
                "log_type": "ssh",
                "created_at": "2026-01-07T10:00:00",
                "expires_at": "2026-01-07T11:00:00",
                "events_count": 150
            },
            "summary": {
                "total_alerts": 3,
                "by_severity": {"high": 2, "medium": 1},
                "affected_ips": ["203.0.113.50", "198.51.100.1"],
                "time_range": {
                    "start": "2026-01-07T08:00:00",
                    "end": "2026-01-07T09:30:00"
                }
            },
            "alerts": [
                {
                    "alert_id": "brute_force_detection_abc123",
                    "rule_id": "brute_force_detection",
                    "severity": "high",
                    "title": "Brute Force Attack Detected from 203.0.113.50",
                    "description": "IP address 203.0.113.50 has made 5 failed...",
                    "timestamp": "2026-01-07T08:05:00",
                    "affected_ips": ["203.0.113.50"],
                    "event_count": 5,
                    "evidence": {...},
                    "recommendations": [...]
                }
            ]
        }
    """
    
    # SECURITY: Validate session ID format (must be valid UUID)
    # Prevents injection attacks and malformed requests
    try:
        import uuid
        uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid session ID format. Must be a valid UUID."
        )
    
    # SECURITY: Retrieve session with automatic expiration check
    # SessionManager enforces session isolation and TTL
    session = session_manager.get_session(session_id)
    
    if session is None:
        # Session not found or expired
        # SECURITY: Same error message for both cases prevents information leakage
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or expired. Sessions expire after 1 hour of inactivity."
        )
    
    # Calculate time range of analyzed logs
    time_range = None
    if session.events:
        timestamps = [e.timestamp for e in session.events if e.timestamp is not None]
        if timestamps:
            time_range = {
                "start": min(timestamps).isoformat(),
                "end": max(timestamps).isoformat(),
                "duration_seconds": (max(timestamps) - min(timestamps)).total_seconds()
            }
    
    # Prepare alert data for response
    # Convert Alert objects to dictionaries for JSON serialization
    alerts_data = []
    for alert in session.alerts:
        alerts_data.append(alert.to_dict())
    
    # Calculate summary statistics
    severity_distribution = {}
    affected_ips = set()
    affected_hosts = set()
    
    for alert in session.alerts:
        # Count by severity
        severity = alert.severity.value
        severity_distribution[severity] = severity_distribution.get(severity, 0) + 1
        
        # Collect affected entities
        affected_ips.update(alert.affected_ips)
        affected_hosts.update(alert.affected_hosts)
    
    # Prepare response
    return {
        "session_id": session.session_id,
        "session_info": {
            "log_type": session.log_type,
            "created_at": session.created_at.isoformat(),
            "expires_at": session.expires_at.isoformat(),
            "is_expired": session.is_expired(),
            "events_count": len(session.events)
        },
        "summary": {
            "total_alerts": len(session.alerts),
            "by_severity": severity_distribution,
            "unique_ips_flagged": len(affected_ips),
            "unique_hosts_flagged": len(affected_hosts),
            "affected_ips": list(affected_ips),
            "affected_hosts": list(affected_hosts),
            "time_range": time_range
        },
        "alerts": alerts_data,
        "metadata": {
            "detection_rules_applied": [
                "brute_force_detection",
                "port_scan_detection", 
                "suspicious_uri_detection"
            ],
            "analysis_completed_at": session.metadata.get('analysis_completed_at', 
                                                          session.created_at.isoformat())
        }
    }


@router.get("/stats")
async def get_stats() -> Dict[str, Any]:
    """
    Get current BYOL service statistics.
    
    Useful for monitoring resource usage and performance.
    No sensitive data exposed.
    
    Returns:
        Service statistics including session counts and memory usage
    """
    return session_manager.get_stats()
