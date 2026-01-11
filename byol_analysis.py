# @even rygh
"""Shared BYOL analysis helpers.

This module exists so we can reuse the same parsing + detection logic for:
- manual uploads (BYOL)
- attack simulations that should be analyzed and surfaced in a SOC dashboard

It intentionally contains no FastAPI route code.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import HTTPException, status

from config import settings
from parsers import LogParserFactory
from session_manager import session_manager
from validators import FileValidator, StreamingFileValidator

from detection_engine import analyze_events
from log_parser import ParsedEvent


def _build_detection_events(validated_log_type: str, session_events) -> List[ParsedEvent]:
    detection_events: List[ParsedEvent] = []

    for log_event in session_events:
        parsed_data = log_event.parsed_data

        ip = (
            parsed_data.get("ip")
            or parsed_data.get("source_ip")
            or parsed_data.get("client_ip")
        )

        host = parsed_data.get("host") or parsed_data.get("hostname")

        event_type = parsed_data.get("event_type", "unknown")
        if event_type == "failed_password":
            event_type = "auth_failed"
        elif event_type == "accepted_auth":
            event_type = "auth_success"

        detection_events.append(
            ParsedEvent(
                timestamp=log_event.timestamp,
                source=validated_log_type,
                host=host,
                ip=ip,
                event_type=event_type,
                raw_message=log_event.raw_line,
                metadata=parsed_data,
            )
        )

    return detection_events


async def analyze_log_bytes(
    *,
    log_bytes: bytes,
    log_type: str,
    source_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Analyze a log payload (bytes) and create a BYOL session.

    Used by attack simulations to feed generated logs into the same detection pipeline.
    """
    log_type_lower = (log_type or "").lower().strip()
    validated_log_type: Optional[str] = None
    if log_type_lower and log_type_lower != "auto":
        # Validate log type against whitelist
        try:
            validated_log_type = FileValidator.validate_log_type(log_type)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid log_type parameter: {str(e)}",
            )

    # Validate + split lines
    validator = StreamingFileValidator()
    try:
        all_lines: List[str] = []
        all_lines.extend(await validator.validate_chunk(log_bytes))
        all_lines.extend(validator.finalize())
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error processing log content: {str(e)}",
        )

    if validated_log_type is None:
        validated_log_type = FileValidator.auto_detect_log_type(all_lines)

    # Create isolated session (include source metadata)
    session = session_manager.create_session(validated_log_type, metadata=source_metadata)
    session.metadata.setdefault("source", "simulation" if source_metadata else "upload")

    # Parse lines
    try:
        parser = LogParserFactory.get_parser(validated_log_type)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    parsed_count = 0
    skipped_count = 0

    for line_num, line in enumerate(all_lines, start=1):
        if not line.strip():
            skipped_count += 1
            continue

        try:
            event = parser.parse_line(line, line_num)
            if event is not None:
                session.add_event(event)
                parsed_count += 1
            else:
                skipped_count += 1
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        except Exception:
            skipped_count += 1

    # Detection
    detection_events = _build_detection_events(validated_log_type, session.events)
    alerts = analyze_events(detection_events)
    session.alerts = alerts

    session.metadata["detection_summary"] = {
        "alerts_generated": len(alerts),
        "severity_distribution": {},
        "affected_ips": list(
            {
                ip
                for alert in alerts
                for ip in getattr(alert, "affected_ips", [])
            }
        ),
    }

    for alert in alerts:
        severity = getattr(getattr(alert, "severity", None), "value", None)
        if not severity:
            severity = str(getattr(alert, "severity", "unknown"))
        session.metadata["detection_summary"]["severity_distribution"][severity] = (
            session.metadata["detection_summary"]["severity_distribution"].get(severity, 0)
            + 1
        )

    return {
        "session_id": session.session_id,
        "log_type": validated_log_type,
        "status": "completed",
        "summary": {
            "total_lines": len(all_lines),
            "parsed_events": parsed_count,
            "skipped_lines": skipped_count,
            "file_size_bytes": validator.total_bytes,
        },
        "detection": session.metadata.get("detection_summary", {}),
        "session_info": {
            "expires_at": session.expires_at.isoformat(),
            "ttl_seconds": settings.session_ttl_seconds,
        },
        "next_steps": {
            "retrieve_events": f"/byol/session/{session.session_id}",
            "retrieve_alerts": f"/byol/{session.session_id}/alerts",
            "delete_session": f"/byol/session/{session.session_id}",
        },
    }
