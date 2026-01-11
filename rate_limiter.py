#!/usr/bin/env python3
# @even rygh
"""
Rate limiting middleware for demo environment.
Prevents abuse of public-facing API.
"""
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from collections import defaultdict
from datetime import datetime, timedelta
import asyncio

class RateLimiter:
    """Simple in-memory rate limiter for demo purposes."""
    
    def __init__(self, requests: int = 100, period: int = 60):
        """
        Initialize rate limiter.
        
        Args:
            requests: Maximum requests allowed per period
            period: Time period in seconds
        """
        self.max_requests = requests
        self.period = period
        self.requests = defaultdict(list)
        self.lock = asyncio.Lock()
    
    async def is_allowed(self, client_id: str) -> bool:
        """Check if request is allowed for client."""
        async with self.lock:
            now = datetime.now()
            cutoff = now - timedelta(seconds=self.period)
            
            # Remove old requests
            self.requests[client_id] = [
                req_time for req_time in self.requests[client_id]
                if req_time > cutoff
            ]
            
            # Check limit
            if len(self.requests[client_id]) >= self.max_requests:
                return False
            
            # Add new request
            self.requests[client_id].append(now)
            return True
    
    async def cleanup_old_entries(self):
        """Periodic cleanup of old entries."""
        while True:
            await asyncio.sleep(300)  # Cleanup every 5 minutes
            async with self.lock:
                now = datetime.now()
                cutoff = now - timedelta(seconds=self.period * 2)
                
                # Remove clients with no recent requests
                to_remove = [
                    client_id for client_id, times in self.requests.items()
                    if not times or max(times) < cutoff
                ]
                for client_id in to_remove:
                    del self.requests[client_id]


# Global rate limiter instance
rate_limiter = RateLimiter(requests=100, period=60)


async def rate_limit_middleware(request: Request, call_next):
    """Rate limiting middleware."""
    # Get client identifier (IP address)
    client_ip = request.client.host if request.client else "unknown"
    
    # Skip rate limiting for health checks
    if request.url.path in ["/health", "/docs", "/openapi.json"]:
        return await call_next(request)
    
    # Check rate limit
    if not await rate_limiter.is_allowed(client_ip):
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "detail": "Rate limit exceeded. Please try again later.",
                "retry_after": rate_limiter.period
            }
        )
    
    # Process request
    response = await call_next(request)
    
    # Add rate limit headers
    response.headers["X-RateLimit-Limit"] = str(rate_limiter.max_requests)
    response.headers["X-RateLimit-Period"] = str(rate_limiter.period)
    
    return response
