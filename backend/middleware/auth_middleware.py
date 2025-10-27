"""
ProofPals Authentication Middleware
JWT validation and authorization for FastAPI
"""

from fastapi import Depends, HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List, Callable
from functools import wraps
import logging

from database import get_db
from auth_service import get_auth_service
from schemas.auth_schemas import CurrentUser, UserRoleEnum

logger = logging.getLogger(__name__)

# Security schemes
security = HTTPBearer()
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# ============================================================================
# Token Validation Dependencies
# ============================================================================

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security),
    db: AsyncSession = Depends(get_db)
) -> CurrentUser:
    """
    Dependency to get current authenticated user from JWT token
    
    Args:
        credentials: Bearer token from Authorization header
        db: Database session
        
    Returns:
        CurrentUser object
        
    Raises:
        HTTPException: If token is invalid or user not found
    """
    auth_service = get_auth_service()
    
    # Extract token
    token = credentials.credentials
    
    # Verify token
    payload = auth_service.verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check token type
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Extract user info
    user_id = int(payload.get("sub"))
    username = payload.get("username")
    role = payload.get("role")
    
    if not all([user_id, username, role]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verify user still exists and is active
    user_data = await auth_service.get_user_by_id(user_id, db)
    if not user_data or not user_data.get("is_active"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return CurrentUser(
        id=user_id,
        username=username,
        role=role
    )


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security, auto_error=False),
    db: AsyncSession = Depends(get_db)
) -> Optional[CurrentUser]:
    """
    Optional authentication - returns user if token provided, None otherwise
    
    Used for endpoints that work with or without authentication
    """
    if not credentials:
        return None
    
    try:
        return await get_current_user(credentials, db)
    except HTTPException:
        return None


async def verify_api_key(
    api_key: Optional[str] = Security(api_key_header),
    db: AsyncSession = Depends(get_db)
) -> Optional[dict]:
    """
    Verify API key for service-to-service authentication
    
    Args:
        api_key: API key from X-API-Key header
        db: Database session
        
    Returns:
        API key data or None
    """
    if not api_key:
        return None
    
    auth_service = get_auth_service()
    key_data = await auth_service.verify_api_key(api_key, db)
    
    return key_data


# ============================================================================
# Role-Based Access Control Decorators
# ============================================================================

def require_role(required_role: str):
    """
    Decorator to require specific role or higher
    
    Args:
        required_role: Required role (admin, vetter, reviewer, submitter)
        
    Usage:
        @app.get("/admin/endpoint")
        @require_role("admin")
        async def admin_endpoint(current_user: CurrentUser = Depends(get_current_user)):
            ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, current_user: CurrentUser = Depends(get_current_user), **kwargs):
            auth_service = get_auth_service()
            
            if not auth_service.check_permission(current_user.role, required_role):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Requires {required_role} role or higher"
                )
            
            return await func(*args, current_user=current_user, **kwargs)
        return wrapper
    return decorator


def require_admin(
    current_user: CurrentUser = Depends(get_current_user)
) -> CurrentUser:
    """
    Dependency to require admin role
    
    Usage:
        @app.get("/admin/endpoint")
        async def admin_endpoint(current_user: CurrentUser = Depends(require_admin)):
            ...
    """
    if not current_user.is_admin():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user


def require_vetter(
    current_user: CurrentUser = Depends(get_current_user)
) -> CurrentUser:
    """
    Dependency to require vetter role or higher
    
    Usage:
        @app.post("/vetter/blind-sign")
        async def blind_sign(current_user: CurrentUser = Depends(require_vetter)):
            ...
    """
    if not current_user.is_vetter():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Vetter access required"
        )
    return current_user


def require_reviewer(
    current_user: CurrentUser = Depends(get_current_user)
) -> CurrentUser:
    """
    Dependency to require reviewer role or higher
    
    Usage:
        @app.post("/vote")
        async def submit_vote(current_user: CurrentUser = Depends(require_reviewer)):
            ...
    """
    if not current_user.is_reviewer():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Reviewer access required"
        )
    return current_user


def require_any_role(allowed_roles: List[str]):
    """
    Dependency factory to require any of the specified roles
    
    Args:
        allowed_roles: List of allowed roles
        
    Usage:
        @app.get("/endpoint")
        async def endpoint(
            current_user: CurrentUser = Depends(require_any_role(["admin", "vetter"]))
        ):
            ...
    """
    def check_roles(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of: {', '.join(allowed_roles)}"
            )
        return current_user
    
    return check_roles


# ============================================================================
# Permission Checking Functions
# ============================================================================

def check_permission(current_user: CurrentUser, required_role: str) -> bool:
    """
    Check if current user has required permission
    
    Args:
        current_user: Current user
        required_role: Required role
        
    Returns:
        True if user has permission
    """
    return current_user.has_permission(required_role)


def check_resource_owner(
    current_user: CurrentUser,
    resource_owner_id: int
) -> bool:
    """
    Check if current user owns the resource or is admin
    
    Args:
        current_user: Current user
        resource_owner_id: Owner ID of the resource
        
    Returns:
        True if user is owner or admin
    """
    return current_user.is_admin() or current_user.id == resource_owner_id


def require_permission(permission: str):
    """
    Check if user has specific permission (for future scope-based permissions)
    
    Args:
        permission: Permission string (e.g., "vote:submit", "submission:create")
        
    Usage:
        if require_permission("vote:submit"):
            # Allow action
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, current_user: CurrentUser = Depends(get_current_user), **kwargs):
            # For now, map permissions to roles
            # In future, implement fine-grained permissions
            permission_role_map = {
                "submission:create": UserRoleEnum.SUBMITTER.value,
                "vote:submit": UserRoleEnum.REVIEWER.value,
                "credential:issue": UserRoleEnum.VETTER.value,
                "ring:create": UserRoleEnum.ADMIN.value,
                "escalation:review": UserRoleEnum.ADMIN.value,
            }
            
            required_role = permission_role_map.get(permission, UserRoleEnum.ADMIN.value)
            
            if not current_user.has_permission(required_role):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing permission: {permission}"
                )
            
            return await func(*args, current_user=current_user, **kwargs)
        return wrapper
    return decorator


# ============================================================================
# Combined Authentication (JWT or API Key)
# ============================================================================

async def get_current_user_or_api_key(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security, auto_error=False),
    api_key: Optional[str] = Security(api_key_header),
    db: AsyncSession = Depends(get_db)
) -> CurrentUser:
    """
    Authenticate via JWT token OR API key
    
    Tries JWT first, falls back to API key
    
    Usage:
        @app.post("/endpoint")
        async def endpoint(
            user: CurrentUser = Depends(get_current_user_or_api_key)
        ):
            ...
    """
    # Try JWT first
    if credentials:
        try:
            return await get_current_user(credentials, db)
        except HTTPException:
            pass
    
    # Try API key
    if api_key:
        key_data = await verify_api_key(api_key, db)
        if key_data:
            # Get user from API key
            auth_service = get_auth_service()
            user_data = await auth_service.get_user_by_id(key_data["user_id"], db)
            
            if user_data and user_data.get("is_active"):
                return CurrentUser(
                    id=user_data["id"],
                    username=user_data["username"],
                    role=user_data["role"]
                )
    
    # No valid authentication
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required (JWT token or API key)",
        headers={"WWW-Authenticate": "Bearer"},
    )