# @even rygh
"""
Session management for BYOL service.
Provides isolated, temporary storage for uploaded log analysis.
"""
import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, TYPE_CHECKING
from dataclasses import dataclass, field
import asyncio
from threading import Lock

from config import settings

# Configure logger for session lifecycle events
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Import Alert type for type hints
if TYPE_CHECKING:
    from detection_engine import Alert


@dataclass
class LogEvent:
    """
    Represents a single parsed log event.
    Stored in memory only - never persisted to disk.
    """
    timestamp: Optional[datetime]
    log_type: str
    raw_line: str
    parsed_data: Dict[str, Any] = field(default_factory=dict)
    severity: Optional[str] = None


@dataclass
class Session:
    """
    Represents a BYOL analysis session.
    
    Security properties:
    - Unique session ID prevents cross-session data leakage
    - TTL ensures automatic cleanup of abandoned sessions
    - Max events limit prevents memory exhaustion
    - All data stored in memory only (no disk persistence)
    
    Data cleanup policy:
    - Sessions expire after configured TTL (default: 1 hour)
    - Expired sessions are automatically deleted every 5 minutes
    - Manual deletion available via DELETE endpoint
    - All data (events, alerts, metadata) is purged on deletion
    - No data is persisted to disk - complete data removal guaranteed
    """
    session_id: str
    log_type: str
    created_at: datetime
    expires_at: datetime
    events: List[LogEvent] = field(default_factory=list)
    alerts: List[Any] = field(default_factory=list)  # List[Alert] from detection_engine
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_expired(self) -> bool:
        """Check if session has exceeded its TTL."""
        return datetime.utcnow() > self.expires_at
    
    def clear_data(self) -> None:
        """
        Explicitly clear all session data from memory.
        
        Called during cleanup to ensure no residual data remains.
        Clears:
        - All parsed log events
        - All generated security alerts
        - All session metadata
        """
        self.events.clear()
        self.alerts.clear()
        self.metadata.clear()
    
    def add_event(self, event: LogEvent) -> None:
        """
        Add a parsed event to this session.
        
        Security check: Enforce per-session event limit to prevent memory exhaustion.
        """
        if len(self.events) >= settings.max_events_per_session:
            raise ValueError(
                f"Session event limit reached: {settings.max_events_per_session}. "
                "This prevents memory exhaustion attacks."
            )
        self.events.append(event)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get session statistics without exposing full event data."""
        return {
            "session_id": self.session_id,
            "log_type": self.log_type,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "event_count": len(self.events),
            "time_remaining_seconds": int((self.expires_at - datetime.utcnow()).total_seconds()),
            "metadata": self.metadata
        }


class SessionManager:
    """
    Manages BYOL sessions with automatic cleanup and resource limits.
    
    Thread-safe singleton for managing all active sessions.
    Implements automatic expiration to prevent indefinite memory growth.
    """
    
    _instance = None
    _lock = Lock()
    
    def __new__(cls):
        """Singleton pattern to ensure one session manager across application."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        """Initialize session storage and start cleanup task."""
        if self._initialized:
            return
        
        # In-memory storage only - no disk persistence
        # Key: session_id, Value: Session object
        self._sessions: Dict[str, Session] = {}
        self._sessions_lock = Lock()
        
        # Track cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None
        self._initialized = True
    
    def create_session(self, log_type: str, metadata: Optional[Dict[str, Any]] = None) -> Session:
        """
        Create a new isolated session for log analysis.
        
        Security:
        - Generates cryptographically random UUID for session ID
        - Sets automatic expiration based on configured TTL
        - Isolates each upload into its own session
        
        Args:
            log_type: Type of logs being analyzed
            
        Returns:
            New Session object
        """
        session_id = str(uuid.uuid4())  # Cryptographically random
        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=settings.session_ttl_seconds)
        
        base_metadata: Dict[str, Any] = {
            "max_events": settings.max_events_per_session,
            "ttl_seconds": settings.session_ttl_seconds,
        }
        if metadata:
            # Merge caller-provided metadata (e.g., simulation context)
            base_metadata.update(metadata)

        session = Session(
            session_id=session_id,
            log_type=log_type,
            created_at=now,
            expires_at=expires_at,
            metadata=base_metadata,
        )
        
        with self._sessions_lock:
            self._sessions[session_id] = session
        
        logger.info(
            f"Session created: {session_id} | log_type={log_type} | "
            f"expires_at={expires_at.isoformat()} | ttl={settings.session_ttl_seconds}s"
        )
        
        return session

    def list_sessions(self, limit: int = 50) -> List[Session]:
        """Return active (non-expired) sessions, newest-first."""
        with self._sessions_lock:
            sessions = list(self._sessions.values())

        active = [s for s in sessions if not s.is_expired()]
        active.sort(key=lambda s: s.created_at, reverse=True)
        return active[: max(0, limit)]
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """
        Retrieve a session by ID.
        
        Security:
        - Returns None for non-existent sessions (no error leakage)
        - Automatically removes expired sessions on access
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session object if exists and not expired, None otherwise
        """
        with self._sessions_lock:
            session = self._sessions.get(session_id)
            
            if session is None:
                return None
            
            # Auto-cleanup expired sessions on access
            if session.is_expired():
                session.clear_data()
                del self._sessions[session_id]
                logger.info(
                    f"Session auto-expired on access: {session_id} | "
                    f"age={(datetime.utcnow() - session.created_at).total_seconds():.0f}s"
                )
                return None
            
            return session
    
    def delete_session(self, session_id: str) -> bool:
        """
        Explicitly delete a session.
        
        Security:
        - Allows users to manually cleanup their data
        - Removes all associated data from memory
        - Guarantees no residual user data remains
        
        Data deleted:
        - All parsed log events (raw lines and parsed data)
        - All security alerts and evidence
        - All session metadata
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if session was deleted, False if not found
        """
        with self._sessions_lock:
            if session_id in self._sessions:
                session = self._sessions[session_id]
                
                # Log deletion details before clearing
                event_count = len(session.events)
                alert_count = len(session.alerts)
                age_seconds = (datetime.utcnow() - session.created_at).total_seconds()
                
                # Explicitly clear all data structures
                session.clear_data()
                
                del self._sessions[session_id]
                
                logger.info(
                    f"Session deleted: {session_id} | "
                    f"events={event_count} alerts={alert_count} age={age_seconds:.0f}s | "
                    f"trigger=manual"
                )
                
                return True
            return False
    
    def cleanup_expired_sessions(self) -> int:
        """
        Remove all expired sessions from memory.
        
        Security:
        - Prevents indefinite memory growth from abandoned sessions
        - Enforces TTL policy strictly
        - Ensures complete data removal (no residual data)
        
        Data cleanup:
        - Identifies all sessions past their TTL
        - Clears all events, alerts, and metadata
        - Removes session from active storage
        - Logs cleanup statistics
        
        Returns:
            Number of sessions cleaned up
        """
        now = datetime.utcnow()
        expired_sessions = []
        total_events = 0
        total_alerts = 0
        
        with self._sessions_lock:
            # Identify expired sessions
            for session_id, session in self._sessions.items():
                if session.is_expired():
                    expired_sessions.append((session_id, session))
            
            # Remove expired sessions with detailed tracking
            for session_id, session in expired_sessions:
                event_count = len(session.events)
                alert_count = len(session.alerts)
                age_seconds = (now - session.created_at).total_seconds()
                
                total_events += event_count
                total_alerts += alert_count
                
                # Explicitly clear all data structures
                session.clear_data()
                
                del self._sessions[session_id]
                
                logger.debug(
                    f"Session expired: {session_id} | "
                    f"events={event_count} alerts={alert_count} age={age_seconds:.0f}s"
                )
        
        # Log summary if any sessions were cleaned
        if expired_sessions:
            logger.info(
                f"Cleanup completed: {len(expired_sessions)} sessions removed | "
                f"total_events={total_events} total_alerts={total_alerts}"
            )
        
        return len(expired_sessions)
    
    async def start_cleanup_task(self):
        """
        Start background task to periodically cleanup expired sessions.
        
        Runs every N seconds (configured in settings) to prevent memory leaks.
        Ensures reliable cleanup even if application experiences temporary issues.
        
        Cleanup guarantees:
        - Runs automatically every 5 minutes (configurable)
        - Survives transient errors (continues running)
        - Logs all cleanup actions for audit trail
        - Removes ALL session data (events, alerts, metadata)
        """
        logger.info(
            f"Cleanup task started: interval={settings.session_cleanup_interval_seconds}s | "
            f"session_ttl={settings.session_ttl_seconds}s"
        )
        
        while True:
            try:
                await asyncio.sleep(settings.session_cleanup_interval_seconds)
                cleaned = self.cleanup_expired_sessions()
                
                # Log periodic status even if no cleanup needed
                if cleaned == 0:
                    logger.debug(
                        f"Cleanup cycle: no expired sessions | "
                        f"active_sessions={len(self._sessions)}"
                    )
            except Exception as e:
                # Log errors but keep cleanup task running
                logger.error(
                    f"Cleanup task error: {type(e).__name__}: {str(e)} | "
                    f"Task will continue running"
                )
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get current session manager statistics.
        Useful for monitoring and alerting on resource usage.
        """
        with self._sessions_lock:
            total_sessions = len(self._sessions)
            total_events = sum(len(s.events) for s in self._sessions.values())
            
            # Calculate session age distribution
            now = datetime.utcnow()
            sessions_by_age = {
                "< 5min": 0,
                "5-15min": 0,
                "15-30min": 0,
                "> 30min": 0
            }
            
            for session in self._sessions.values():
                age_minutes = (now - session.created_at).total_seconds() / 60
                if age_minutes < 5:
                    sessions_by_age["< 5min"] += 1
                elif age_minutes < 15:
                    sessions_by_age["5-15min"] += 1
                elif age_minutes < 30:
                    sessions_by_age["15-30min"] += 1
                else:
                    sessions_by_age["> 30min"] += 1
            
            return {
                "total_sessions": total_sessions,
                "total_events_in_memory": total_events,
                "sessions_by_age": sessions_by_age,
                "session_ttl_seconds": settings.session_ttl_seconds,
                "cleanup_interval_seconds": settings.session_cleanup_interval_seconds,
            }


# Global session manager instance
session_manager = SessionManager()
