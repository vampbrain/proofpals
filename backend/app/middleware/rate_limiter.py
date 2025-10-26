"""
Rate limiting middleware
"""

import time
import asyncio
import logging
from typing import Dict, Any
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from app.config import settings

logger = logging.getLogger(__name__)

class RateLimiter(BaseHTTPMiddleware):
    """Rate limiting middleware using sliding window"""
    
    def __init__(self, app, requests_per_minute: int = None, window_size: int = None):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute or settings.RATE_LIMIT_REQUESTS
        self.window_size = window_size or settings.RATE_LIMIT_WINDOW
        self.clients: Dict[str, Dict[str, Any]] = {}
        
    async def dispatch(self, request: Request, call_next):
        """Process request with rate limiting"""
        client_ip = self._get_client_ip(request)
        current_time = time.time()
        
        # Clean up old entries
        await self._cleanup_old_entries(current_time)
        
        # Check rate limit
        if not await self._check_rate_limit(client_ip, current_time):
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded",
                    "retry_after": self.window_size,
                    "limit": self.requests_per_minute,
                    "remaining": 0,
                    "reset_time": current_time + self.window_size
                }
            )
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers
        client_data = self.clients.get(client_ip, {})
        remaining = max(0, self.requests_per_minute - client_data.get("count", 0))
        
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(current_time + self.window_size))
        
        return response
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address"""
        # Check for forwarded IP first
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        # Check for real IP
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fallback to direct connection
        return request.client.host if request.client else "unknown"
    
    async def _check_rate_limit(self, client_ip: str, current_time: float) -> bool:
        """Check if client is within rate limit"""
        if client_ip not in self.clients:
            self.clients[client_ip] = {
                "count": 1,
                "window_start": current_time
            }
            return True
        
        client_data = self.clients[client_ip]
        window_start = client_data["window_start"]
        
        # Check if we're in a new window
        if current_time - window_start >= self.window_size:
            client_data["count"] = 1
            client_data["window_start"] = current_time
            return True
        
        # Check if under limit
        if client_data["count"] < self.requests_per_minute:
            client_data["count"] += 1
            return True
        
        return False
    
    async def _cleanup_old_entries(self, current_time: float):
        """Clean up old client entries"""
        to_remove = []
        for client_ip, client_data in self.clients.items():
            if current_time - client_data["window_start"] > self.window_size * 2:
                to_remove.append(client_ip)
        
        for client_ip in to_remove:
            del self.clients[client_ip]
