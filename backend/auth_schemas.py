"""
ProofPals Authentication Schemas
Pydantic models for authentication requests and responses
"""

from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List
from datetime import datetime
from enum import Enum


# ============================================================================
# Enumerations
# ============================================================================

class UserRoleEnum(str, Enum):
    """User role enumeration"""
    ADMIN = "admin"
    VETTER = "vetter"
    REVIEWER = "reviewer"
    SUBMITTER = "submitter"


# ============================================================================
# Request Schemas
# ============================================================================

class RegisterRequest(BaseModel):
    """User registration request"""
    username: str = Field(..., min_length=3, max_length=50, pattern="^[a-zA-Z0-9_-]+$")
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=100)
    role: UserRoleEnum = Field(default=UserRoleEnum.SUBMITTER)
    
    @validator('password')
    def validate_password(cls, v):
        """Validate password strength"""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "username": "john_reviewer",
                "email": "john@example.com",
                "password": "SecurePass123",
                "role": "reviewer"
            }
        }


class LoginRequest(BaseModel):
    """User login request"""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=1)
    
    class Config:
        schema_extra = {
            "example": {
                "username": "john_reviewer",
                "password": "SecurePass123"
            }
        }


class RefreshTokenRequest(BaseModel):
    """Refresh token request"""
    refresh_token: str = Field(..., min_length=1)
    
    class Config:
        schema_extra = {
            "example": {
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }


class PasswordChangeRequest(BaseModel):
    """Password change request"""
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, max_length=100)
    
    @validator('new_password')
    def validate_password(cls, v):
        """Validate password strength"""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v


class ApiKeyCreateRequest(BaseModel):
    """API key creation request"""
    name: str = Field(..., min_length=3, max_length=100)
    scopes: Optional[List[str]] = Field(default=None)
    expires_in_days: Optional[int] = Field(default=None, ge=1, le=365)
    
    class Config:
        schema_extra = {
            "example": {
                "name": "Production API Key",
                "scopes": ["vote:submit", "submission:create"],
                "expires_in_days": 90
            }
        }


# ============================================================================
# Response Schemas
# ============================================================================

class UserResponse(BaseModel):
    """User data response"""
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: Optional[datetime] = None
    last_login_at: Optional[datetime] = None
    
    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "id": 1,
                "username": "john_reviewer",
                "email": "john@example.com",
                "role": "reviewer",
                "is_active": True,
                "created_at": "2024-10-26T12:00:00Z",
                "last_login_at": "2024-10-26T14:30:00Z"
            }
        }


class TokenResponse(BaseModel):
    """JWT token response"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    user: UserResponse
    
    class Config:
        schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 1800,
                "user": {
                    "id": 1,
                    "username": "john_reviewer",
                    "email": "john@example.com",
                    "role": "reviewer",
                    "is_active": True,
                    "created_at": "2024-10-26T12:00:00Z"
                }
            }
        }


class ApiKeyResponse(BaseModel):
    """API key response"""
    id: int
    name: str
    key: Optional[str] = None  # Only returned on creation
    key_preview: Optional[str] = None  # Last 4 characters
    scopes: Optional[List[str]] = None
    is_active: bool
    created_at: datetime
    last_used_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    
    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "id": 1,
                "name": "Production API Key",
                "key": "sk_live_abc123def456...",  # Only on creation
                "key_preview": "...xyz9",
                "scopes": ["vote:submit", "submission:create"],
                "is_active": True,
                "created_at": "2024-10-26T12:00:00Z",
                "last_used_at": "2024-10-26T14:30:00Z",
                "expires_at": "2025-01-26T12:00:00Z"
            }
        }


class PermissionsResponse(BaseModel):
    """User permissions response"""
    user_id: int
    username: str
    role: str
    permissions: List[str]
    
    class Config:
        schema_extra = {
            "example": {
                "user_id": 1,
                "username": "john_reviewer",
                "role": "reviewer",
                "permissions": [
                    "vote:submit",
                    "submission:view",
                    "ring:view",
                    "tally:view"
                ]
            }
        }


class ErrorResponse(BaseModel):
    """Error response"""
    error: str
    detail: Optional[str] = None
    status_code: int
    
    class Config:
        schema_extra = {
            "example": {
                "error": "Authentication failed",
                "detail": "Invalid username or password",
                "status_code": 401
            }
        }


# ============================================================================
# Internal Schemas (for dependencies)
# ============================================================================

class CurrentUser(BaseModel):
    """Current authenticated user (from token)"""
    id: int
    username: str
    role: str
    
    def is_admin(self) -> bool:
        """Check if user is admin"""
        return self.role == UserRoleEnum.ADMIN.value
    
    def is_vetter(self) -> bool:
        """Check if user is vetter or admin"""
        return self.role in [UserRoleEnum.ADMIN.value, UserRoleEnum.VETTER.value]
    
    def is_reviewer(self) -> bool:
        """Check if user is reviewer or above"""
        return self.role in [
            UserRoleEnum.ADMIN.value,
            UserRoleEnum.VETTER.value,
            UserRoleEnum.REVIEWER.value
        ]
    
    def has_permission(self, required_role: str) -> bool:
        """Check if user has required permission level"""
        role_hierarchy = {
            UserRoleEnum.ADMIN.value: 4,
            UserRoleEnum.VETTER.value: 3,
            UserRoleEnum.REVIEWER.value: 2,
            UserRoleEnum.SUBMITTER.value: 1
        }
        
        user_level = role_hierarchy.get(self.role, 0)
        required_level = role_hierarchy.get(required_role, 0)
        
        return user_level >= required_level