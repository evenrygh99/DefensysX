# @even rygh
"""
Main FastAPI application for SOC Platform BYOL Service.
Security-first design with comprehensive input validation and error handling.
"""
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from contextlib import asynccontextmanager
import asyncio
import logging

from config import settings
from byol_routes import router as byol_router
from simulation_routes import router as simulation_router
from session_manager import session_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    Handles startup and shutdown events.
    
    Cleanup guarantees:
    - Background cleanup starts on application startup
    - Cleanup runs automatically every 5 minutes (configurable)
    - All sessions cleaned up on graceful shutdown
    - No user data persists after shutdown
    """
    # Startup: Start session cleanup background task
    cleanup_task = asyncio.create_task(session_manager.start_cleanup_task())
    logger.info(
        f"Application started | cleanup_interval={settings.session_cleanup_interval_seconds}s | "
        f"session_ttl={settings.session_ttl_seconds}s"
    )
    
    yield
    
    # Shutdown: Cancel cleanup task and cleanup all sessions
    logger.info("Application shutdown initiated - cleaning up all sessions")
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass
    
    # Final cleanup of all sessions (even non-expired ones)
    with session_manager._sessions_lock:
        session_count = len(session_manager._sessions)
        total_events = sum(len(s.events) for s in session_manager._sessions.values())
        total_alerts = sum(len(s.alerts) for s in session_manager._sessions.values())
        
        for session_id, session in list(session_manager._sessions.items()):
            session.clear_data()
            del session_manager._sessions[session_id]
    
    logger.info(
        f"Application shutdown complete | "
        f"cleaned_sessions={session_count} events={total_events} alerts={total_alerts}"
    )


# Initialize FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Secure log analysis service with Bring Your Own Logs (BYOL) support",
    docs_url="/docs" if settings.debug else None,  # Disable docs in production
    redoc_url="/redoc" if settings.debug else None,
    lifespan=lifespan
)


# SECURITY: CORS middleware with strict origin whitelist
# Only allows requests from explicitly configured origins
logger.info(f"Configuring CORS with origins: {settings.cors_origins}")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,  # Whitelist only
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],  # Include OPTIONS for preflight
    allow_headers=["*"],  # Can be restricted further in production
    expose_headers=["*"],
    max_age=3600,
)


# SECURITY: Trusted host middleware prevents Host header attacks
# Protects against DNS rebinding and HTTP Host header attacks
if not settings.debug:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.allowed_hosts
    )


# SECURITY: Global exception handler
# Prevents leaking sensitive error details to clients
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Global exception handler to prevent information leakage.
    
    In production, never expose internal error details.
    Log full error server-side, return generic message to client.
    """
    # Log the full error server-side
    print(f"[ERROR] Unhandled exception: {type(exc).__name__}: {str(exc)}")
    
    if settings.debug:
        # In debug mode, return detailed error
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "Internal Server Error",
                "detail": str(exc),
                "type": type(exc).__name__
            }
        )
    else:
        # In production, return generic error
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "Internal Server Error",
                "detail": "An unexpected error occurred. Please try again later."
            }
        )


# Include BYOL routes
app.include_router(byol_router)

# Include attack simulation routes (demo only)
app.include_router(simulation_router)


# Health check endpoint
@app.get("/health", tags=["Health"])
async def health_check():
    """
    Health check endpoint for monitoring.
    Returns service status without sensitive information.
    """
    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version
    }


# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    """
    Root endpoint with API information.
    """
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "endpoints": {
            "upload_logs": "/byol/upload",
            "get_session": "/byol/session/{session_id}",
            "delete_session": "/byol/session/{session_id}",
            "stats": "/byol/stats",
            "health": "/health",
            "docs": "/docs" if settings.debug else "disabled"
        },
        "security_features": [
            "Streaming file validation",
            "Automatic session expiration",
            "No disk persistence",
            "Per-session resource limits",
            "Comprehensive input validation"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    
    # Run with uvicorn
    # SECURITY: Disable auto-reload in production
    uvicorn.run(
        "main:app",
        host="0.0.0.0",  # Bind to all interfaces
        port=8000,
        reload=settings.uvicorn_reload,
        log_level="info"
    )
