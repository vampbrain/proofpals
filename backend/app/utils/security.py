"""
Security utilities for authentication and authorization
"""

import hashlib
import secrets
import logging
from typing import Optional, Dict, Any
from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.config import settings

logger = logging.getLogger(__name__)

# Security instance
security = HTTPBearer()

def hash_ip_address(ip_address: str) -> str:
    """Hash an IP address for privacy"""
    return hashlib.sha256(f"{ip_address}{settings.SECRET_KEY}".encode()).hexdigest()

def hash_mac_address(mac_address: str) -> str:
    """Hash a MAC address for privacy"""
    return hashlib.sha256(f"{mac_address}{settings.SECRET_KEY}".encode()).hexdigest()

def generate_api_key() -> str:
    """Generate a secure API key"""
    return secrets.token_urlsafe(32)

def verify_api_key(api_key: str) -> bool:
    """Verify an API key"""
    # In production, this would check against a database
    # For now, we'll use a simple check against configured keys
    valid_keys = [
        "admin-key-123",  # Admin key
        "vetter-key-456",  # Vetter key
        "server-internal-key-789"  # Server internal key
    ]
    return api_key in valid_keys

def get_user_from_api_key(api_key: str) -> Dict[str, Any]:
    """Get user information from API key"""
    # In production, this would query a database
    # For now, we'll use hardcoded mappings
    user_mappings = {
        "admin-key-123": {
            "user_id": "admin-001",
            "is_admin": True,
            "is_vetter": True,
            "is_server_internal": True
        },
        "vetter-key-456": {
            "user_id": "vetter-001",
            "is_admin": False,
            "is_vetter": True,
            "is_server_internal": False
        },
        "server-internal-key-789": {
            "user_id": "server-001",
            "is_admin": False,
            "is_vetter": False,
            "is_server_internal": True
        }
    }
    
    return user_mappings.get(api_key, {
        "user_id": None,
        "is_admin": False,
        "is_vetter": False,
        "is_server_internal": False
    })

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """Get current user from API key"""
    try:
        api_key = credentials.credentials
        
        if not verify_api_key(api_key):
            raise HTTPException(
                status_code=401,
                detail="Invalid API key"
            )
        
        user = get_user_from_api_key(api_key)
        return user
        
    except Exception as e:
        logger.error(f"Error getting current user: {e}")
        raise HTTPException(
            status_code=401,
            detail="Authentication failed"
        )

def require_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Require admin privileges"""
    if not user.get("is_admin", False):
        raise HTTPException(
            status_code=403,
            detail="Admin access required"
        )
    return user

def require_vetter(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Require vetter privileges"""
    if not user.get("is_vetter", False):
        raise HTTPException(
            status_code=403,
            detail="Vetter access required"
        )
    return user

def require_server_internal(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Require server internal access"""
    if not user.get("is_server_internal", False):
        raise HTTPException(
            status_code=403,
            detail="Server internal access required"
        )
    return user

def validate_submission_data(data: Dict[str, Any]) -> bool:
    """Validate submission data"""
    required_fields = ["genre", "content_ref", "submitter_ip_hash"]
    
    for field in required_fields:
        if field not in data:
            return False
    
    # Validate genre
    valid_genres = ["news", "opinion", "analysis", "investigation", "other"]
    if data["genre"] not in valid_genres:
        return False
    
    return True

def validate_vote_data(data: Dict[str, Any]) -> bool:
    """Validate vote data"""
    required_fields = [
        "submission_id", "ring_id", "signature_blob", 
        "vote_type", "token_id", "message"
    ]
    
    for field in required_fields:
        if field not in data:
            return False
    
    # Validate vote type
    valid_vote_types = ["approve", "reject", "flag", "escalate"]
    if data["vote_type"] not in valid_vote_types:
        return False
    
    return True

def sanitize_input(input_string: str, max_length: int = 1000) -> str:
    """Sanitize user input"""
    if not input_string:
        return ""
    
    # Truncate if too long
    if len(input_string) > max_length:
        input_string = input_string[:max_length]
    
    # Remove potentially dangerous characters
    dangerous_chars = ["<", ">", "\"", "'", "&", "\x00"]
    for char in dangerous_chars:
        input_string = input_string.replace(char, "")
    
    return input_string.strip()

def generate_nonce() -> str:
    """Generate a cryptographic nonce"""
    return secrets.token_urlsafe(16)

def validate_nonce(nonce: str) -> bool:
    """Validate a nonce format"""
    if not nonce:
        return False
    
    # Check length (should be 16 characters base64 encoded)
    if len(nonce) != 22:  # 16 bytes = 22 base64 characters
        return False
    
    # Check if it's valid base64
    try:
        import base64
        base64.b64decode(nonce)
        return True
    except:
        return False

def create_audit_hash(data: Dict[str, Any]) -> str:
    """Create a hash for audit purposes"""
    # Sort keys for consistent hashing
    sorted_data = {k: v for k, v in sorted(data.items())}
    
    # Convert to JSON string
    import json
    json_string = json.dumps(sorted_data, sort_keys=True)
    
    # Hash with secret key
    return hashlib.sha256(f"{json_string}{settings.SECRET_KEY}".encode()).hexdigest()

def verify_audit_hash(data: Dict[str, Any], expected_hash: str) -> bool:
    """Verify an audit hash"""
    actual_hash = create_audit_hash(data)
    return actual_hash == expected_hash

def get_client_fingerprint(request: Request) -> str:
    """Get client fingerprint for tracking"""
    # Collect various client information
    user_agent = request.headers.get("User-Agent", "")
    accept_language = request.headers.get("Accept-Language", "")
    accept_encoding = request.headers.get("Accept-Encoding", "")
    
    # Create fingerprint
    fingerprint_data = f"{user_agent}{accept_language}{accept_encoding}"
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()

def is_suspicious_request(request: Request) -> bool:
    """Check if request is suspicious"""
    # Check for common attack patterns
    suspicious_patterns = [
        "script", "javascript", "vbscript", "onload", "onerror",
        "union", "select", "insert", "update", "delete", "drop",
        "exec", "eval", "system", "shell"
    ]
    
    # Check URL
    url = str(request.url).lower()
    for pattern in suspicious_patterns:
        if pattern in url:
            return True
    
    # Check headers
    for header_name, header_value in request.headers.items():
        if any(pattern in header_value.lower() for pattern in suspicious_patterns):
            return True
    
    return False

def log_security_event(event_type: str, details: Dict[str, Any], request: Request):
    """Log a security event"""
    logger.warning(f"Security event: {event_type}", extra={
        "event_type": event_type,
        "details": details,
        "client_ip": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("User-Agent", ""),
        "url": str(request.url)
    })
