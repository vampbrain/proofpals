backend/middleware/rate_limiter.py
"""
ProofPals Rate Limiting Middleware
Redis-based rate limiting for API protection
"""

import logging
import time
from typing import Optional, Callable
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import redis.asyncio as redis
import hashlib

from config import settings

logger = logging.getLogger(_name_)


class RateLimiter(BaseHTTPMiddleware):
    """
    Rate limiting middleware using Redis
    
    Implements multiple rate limiting strategies:
    - Per-IP rate limiting
    - Per-user rate limiting (via token)
    - Per-API-key rate limiting
    """
    
    def _init_(self, app):
        super()._init_(app)
        self.redis_client: Optional[redis.Redis] = None
        self.enabled = True
        
        # Rate limit configurations
        self.configs = {
            "default": {
                "requests": settings.RATE_LIMIT_REQUESTS,
                "window": settings.RATE_LIMIT_WINDOW,
            },
            "vote": {
                "requests": 10,  # 10 votes per minute
                "window": 60,
            },
            "auth": {
                "requests": 5,  # 5 login attempts per 5 minutes
                "window": 300,
            },
            "submission": {
                "requests": 20,  # 20 submissions per hour
                "window": 3600,
            }
        }
    
    async def init_redis(self):
        """Initialize Redis connection"""
        if self.redis_client is None:
            try:
                self.redis_client = await redis.from_url(
                    settings.REDIS_URL,
                    encoding="utf-8",
                    decode_responses=True
                )
                await self.redis_client.ping()
                logger.info("Rate limiter Redis connection established")
            except Exception as e:
                logger.error(f"Failed to connect to Redis for rate limiting: {e}")
                self.enabled = False
    
    async def dispatch(self, request: Request, call_next: Callable):
        """Process request with rate limiting"""
        
        # Initialize Redis if needed
        if self.redis_client is None and self.enabled:
            await self.init_redis()
        
        # Skip rate limiting if disabled or for health checks
        if not self.enabled or request.url.path in ["/health", "/docs", "/redoc", "/openapi.json"]:
            return await call_next(request)
        
        # Determine rate limit config based on endpoint
        config = self._get_rate_limit_config(request.url.path)
        
        # Get identifier for rate limiting
        identifier = await self._get_identifier(request)
        
        # Check rate limit
        is_allowed, retry_after = await self._check_rate_limit(
            identifier, 
            config["requests"], 
            config["window"]
        )
        
        if not is_allowed:
            logger.warning(
                f"Rate limit exceeded for {identifier} on {request.url.path}"
            )
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Rate limit exceeded",
                    "detail": f"Too many requests. Please try again in {retry_after} seconds.",
                    "retry_after": retry_after
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(config["requests"]),
                    "X-RateLimit-Window": str(config["window"])
                }
            )
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers to response
        remaining, reset_time = await self._get_rate_limit_info(
            identifier, 
            config["requests"], 
            config["window"]
        )
        
        response.headers["X-RateLimit-Limit"] = str(config["requests"])
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_time)
        
        return response
    
    def _get_rate_limit_config(self, path: str) -> dict:
        """Get rate limit configuration based on endpoint"""
        if "/vote" in path:
            return self.configs["vote"]
        elif "/auth/" in path or "/login" in path or "/register" in path:
            return self.configs["auth"]
        elif "/submissions" in path:
            return self.configs["submission"]
        else:
            return self.configs["default"]
    
    async def _get_identifier(self, request: Request) -> str:
        """
        Get identifier for rate limiting
        
        Priority:
        1. User ID from token (if authenticated)
        2. API key (if present)
        3. IP address
        """
        # Check for authentication token
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.replace("Bearer ", "")
            # Hash token for privacy
            token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
            return f"token:{token_hash}"
        
        # Check for API key
        api_key = request.headers.get("X-API-Key")
        if api_key:
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()[:16]
            return f"apikey:{key_hash}"
        
        # Fall back to IP address
        client_ip = request.client.host if request.client else "unknown"
        return f"ip:{client_ip}"
    
    async def _check_rate_limit(
        self, 
        identifier: str, 
        max_requests: int, 
        window: int
    ) -> tuple[bool, int]:
        """
        Check if request is within rate limit
        
        Uses sliding window log algorithm
        
        Returns:
            Tuple of (is_allowed, retry_after_seconds)
        """
        if not self.redis_client:
            # If Redis is unavailable, allow request
            return True, 0
        
        try:
            now = time.time()
            window_start = now - window
            
            key = f"rate_limit:{identifier}"
            
            # Use Redis pipeline for atomic operations
            pipe = self.redis_client.pipeline()
            
            # Remove old entries
            pipe.zremrangebyscore(key, 0, window_start)
            
            # Count current requests in window
            pipe.zcard(key)
            
            # Execute pipeline
            results = await pipe.execute()
            current_count = results[1]
            
            if current_count >= max_requests:
                # Get oldest entry to calculate retry_after
                oldest_entries = await self.redis_client.zrange(key, 0, 0, withscores=True)
                if oldest_entries:
                    oldest_timestamp = oldest_entries[0][1]
                    retry_after = int(oldest_timestamp + window - now) + 1
                else:
                    retry_after = window
                
                return False, retry_after
            
            # Add current request
            await self.redis_client.zadd(key, {str(now): now})
            
            # Set expiry on key
            await self.redis_client.expire(key, window + 10)
            
            return True, 0
            
        except Exception as e:
            logger.error(f"Rate limit check error: {e}", exc_info=True)
            # On error, allow request (fail open)
            return True, 0
    
    async def _get_rate_limit_info(
        self, 
        identifier: str, 
        max_requests: int, 
        window: int
    ) -> tuple[int, int]:
        """
        Get remaining requests and reset time
        
        Returns:
            Tuple of (remaining_requests, reset_timestamp)
        """
        if not self.redis_client:
            return max_requests, int(time.time() + window)
        
        try:
            now = time.time()
            window_start = now - window
            
            key = f"rate_limit:{identifier}"
            
            # Count current requests
            current_count = await self.redis_client.zcount(key, window_start, now)
            
            remaining = max(0, max_requests - current_count)
            
            # Get oldest entry for reset time
            oldest_entries = await self.redis_client.zrange(key, 0, 0, withscores=True)
            if oldest_entries:
                oldest_timestamp = oldest_entries[0][1]
                reset_time = int(oldest_timestamp + window)
            else:
                reset_time = int(now + window)
            
            return remaining, reset_time
            
        except Exception as e:
            logger.error(f"Rate limit info error: {e}", exc_info=True)
            return max_requests, int(time.time() + window)
    
    async def close(self):
        """Close Redis connection"""
        if self.redis_client:
            await self.redis_client.close()
            logger.info("Rate limiter Redis connection closed")


# Helper function for manual rate limit checks
async def check_rate_limit(
    identifier: str,
    max_requests: int = 100,
    window: int = 60
) -> bool:
    """
    Manually check rate limit for a specific identifier
    
    Args:
        identifier: Unique identifier (user_id, ip, etc.)
        max_requests: Maximum requests allowed
        window: Time window in seconds
        
    Returns:
        True if within limit, False otherwise
    """
    try:
        redis_client = await redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True
        )
        
        now = time.time()
        window_start = now - window
        
        key = f"rate_limit:{identifier}"
        
        # Remove old entries
        await redis_client.zremrangebyscore(key, 0, window_start)
        
        # Count current requests
        current_count = await redis_client.zcard(key)
        
        await redis_client.close()
        
        return current_count < max_requests
        
    except Exception as e:
        logger.error(f"Manual rate limit check error: {e}", exc_info=True)
        return True  # Fail open