"""
Concurrency protection middleware
"""

import asyncio
import logging
from typing import Dict, Set
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from app.config import settings

logger = logging.getLogger(__name__)

class ConcurrencyProtection(BaseHTTPMiddleware):
    """Concurrency protection middleware to prevent race conditions"""
    
    def __init__(self, app, max_concurrent_requests: int = 100):
        super().__init__(app)
        self.max_concurrent_requests = max_concurrent_requests
        self.active_requests: Set[str] = set()
        self.request_semaphore = asyncio.Semaphore(max_concurrent_requests)
        self.locks: Dict[str, asyncio.Lock] = {}
        
    async def dispatch(self, request: Request, call_next):
        """Process request with concurrency protection"""
        request_id = self._generate_request_id(request)
        
        # Check if we're at capacity
        if len(self.active_requests) >= self.max_concurrent_requests:
            return JSONResponse(
                status_code=503,
                content={
                    "detail": "Service temporarily unavailable due to high load",
                    "retry_after": 5
                }
            )
        
        # Acquire semaphore
        async with self.request_semaphore:
            # Add to active requests
            self.active_requests.add(request_id)
            
            try:
                # Get or create lock for this resource
                resource_key = self._get_resource_key(request)
                if resource_key:
                    lock = self._get_or_create_lock(resource_key)
                    async with lock:
                        response = await call_next(request)
                else:
                    response = await call_next(request)
                
                return response
                
            finally:
                # Remove from active requests
                self.active_requests.discard(request_id)
    
    def _generate_request_id(self, request: Request) -> str:
        """Generate unique request ID"""
        import uuid
        return str(uuid.uuid4())
    
    def _get_resource_key(self, request: Request) -> str:
        """Get resource key for locking"""
        # Lock on specific resources to prevent race conditions
        if request.method in ["POST", "PUT", "PATCH"]:
            # For vote submissions, lock on submission_id
            if "/vote" in str(request.url):
                try:
                    # Extract submission_id from request body
                    # This is a simplified approach - in practice, you'd need to
                    # parse the request body or use request state
                    return f"vote_submission"
                except:
                    pass
            
            # For token operations, lock on token_id
            if "/present-credential" in str(request.url):
                return f"credential_presentation"
            
            # For blind signatures, lock on vetter
            if "/blind-sign" in str(request.url):
                return f"blind_signature"
        
        return None
    
    def _get_or_create_lock(self, resource_key: str) -> asyncio.Lock:
        """Get or create lock for resource"""
        if resource_key not in self.locks:
            self.locks[resource_key] = asyncio.Lock()
        return self.locks[resource_key]
    
    async def cleanup_locks(self):
        """Clean up unused locks"""
        # Remove locks that are not currently in use
        to_remove = []
        for key, lock in self.locks.items():
            if not lock.locked():
                to_remove.append(key)
        
        for key in to_remove:
            del self.locks[key]
    
    async def get_concurrency_stats(self) -> Dict[str, int]:
        """Get concurrency statistics"""
        return {
            "active_requests": len(self.active_requests),
            "max_concurrent_requests": self.max_concurrent_requests,
            "active_locks": len([lock for lock in self.locks.values() if lock.locked()]),
            "total_locks": len(self.locks)
        }
