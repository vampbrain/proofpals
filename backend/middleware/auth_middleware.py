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

# ============================================================================
# Security Schemes (Fixed for FastAPI >= 0.111)
# ============================================================================
security = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# ============================================================================
# Token Validation Dependencies
# ============================================================================

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security),
    db: AsyncSession = Depends(get_db)
) -> CurrentUser:
    """Dependency to get current authenticated user from JWT token"""
    auth_service = get_auth_service()

    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    payload = auth_service.verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = int(payload.get("sub"))
    username = payload.get("username")
    role = payload.get("role")

    if not all([user_id, username, role]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_data = await auth_service.get_user_by_id(user_id, db)
    if not user_data or not user_data.get("is_active"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return CurrentUser(id=user_id, username=username, role=role)


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security),
    db: AsyncSession = Depends(get_db)
) -> Optional[CurrentUser]:
    """Optional authentication - returns user if token provided, None otherwise"""
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
    """Verify API key for service-to-service authentication"""
    if not api_key:
        return None

    auth_service = get_auth_service()
    key_data = await auth_service.verify_api_key(api_key, db)
    return key_data


# ============================================================================
# Combined Authentication (JWT or API Key)
# ============================================================================

async def get_current_user_or_api_key(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security),
    api_key: Optional[str] = Security(api_key_header),
    db: AsyncSession = Depends(get_db)
) -> CurrentUser:
    """Authenticate via JWT token OR API key"""
    if credentials:
        try:
            return await get_current_user(credentials, db)
        except HTTPException:
            pass

    if api_key:
        auth_service = get_auth_service()
        key_data = await auth_service.verify_api_key(api_key, db)
        if key_data:
            user_data = await auth_service.get_user_by_id(key_data["user_id"], db)
            if user_data and user_data.get("is_active"):
                return CurrentUser(
                    id=user_data["id"],
                    username=user_data["username"],
                    role=user_data["role"]
                )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required (JWT token or API key)",
        headers={"WWW-Authenticate": "Bearer"},
    )


# ============================================================================
# Role-Based Access Control Decorators
# ============================================================================

def require_role(required_role: str):
    """Decorator to require specific role or higher"""
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


def require_admin(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    """Require admin role"""
    if not current_user.is_admin():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user


def require_vetter(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    """Require vetter or higher"""
    if not current_user.is_vetter():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Vetter access required"
        )
    return current_user


def require_reviewer(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    """Require reviewer or higher"""
    if not current_user.is_reviewer():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Reviewer access required"
        )
    return current_user


def require_any_role(allowed_roles: List[str]):
    """Require any of specified roles"""
    def check_roles(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of: {', '.join(allowed_roles)}"
            )
        return current_user
    return check_roles


# ============================================================================
# Permission Checking Helpers
# ============================================================================

def check_permission(current_user: CurrentUser, required_role: str) -> bool:
    """Check if user has required permission"""
    return current_user.has_permission(required_role)


def check_resource_owner(current_user: CurrentUser, resource_owner_id: int) -> bool:
    """Check if user owns the resource or is admin"""
    return current_user.is_admin() or current_user.id == resource_owner_id


def require_permission(permission: str):
    """Future scope-based permission checker"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, current_user: CurrentUser = Depends(get_current_user), **kwargs):
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
