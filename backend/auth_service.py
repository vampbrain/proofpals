"""
ProofPals Authentication Service
Handles user authentication, JWT tokens, and authorization
"""

import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import hashlib
import secrets
import jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from pydantic import BaseModel, EmailStr, Field

from config import settings

logger = logging.getLogger(__name__)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ============================================================================
# Pydantic Models
# ============================================================================

class UserRole(str):
    """User role enumeration"""
    ADMIN = "admin"
    VETTER = "vetter"
    REVIEWER = "reviewer"
    SUBMITTER = "submitter"


class UserCreate(BaseModel):
    """User creation request"""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    role: str = Field(default="submitter")


class UserLogin(BaseModel):
    """User login request"""
    username: str
    password: str


class TokenResponse(BaseModel):
    """Token response"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Dict[str, Any]


class User(BaseModel):
    """User model for responses"""
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime


# ============================================================================
# Authentication Service
# ============================================================================

class AuthService:
    """Service for authentication and authorization"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.secret_key = settings.SECRET_KEY
        self.algorithm = settings.ALGORITHM
        self.access_token_expire = settings.ACCESS_TOKEN_EXPIRE_MINUTES
    
    # ========================================================================
    # Password Hashing
    # ========================================================================
    
    def hash_password(self, password: str) -> str:
        """
        Hash a password using bcrypt
        
        Args:
            password: Plain text password
            
        Returns:
            Hashed password
        """
        return pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash
        
        Args:
            plain_password: Plain text password
            hashed_password: Hashed password from database
            
        Returns:
            True if password matches
        """
        try:
            return pwd_context.verify(plain_password, hashed_password)
        except Exception as e:
            self.logger.error(f"Password verification error: {e}")
            return False
    
    # ========================================================================
    # JWT Token Generation
    # ========================================================================
    
    def create_access_token(
        self,
        user_id: int,
        username: str,
        role: str,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create JWT access token
        
        Args:
            user_id: User ID
            username: Username
            role: User role
            expires_delta: Optional custom expiration
            
        Returns:
            Encoded JWT token
        """
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire)
        
        to_encode = {
            "sub": str(user_id),
            "username": username,
            "role": role,
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access"
        }
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def create_refresh_token(
        self,
        user_id: int,
        username: str
    ) -> str:
        """
        Create JWT refresh token (long-lived)
        
        Args:
            user_id: User ID
            username: Username
            
        Returns:
            Encoded JWT refresh token
        """
        expire = datetime.utcnow() + timedelta(days=30)  # 30 days
        
        to_encode = {
            "sub": str(user_id),
            "username": username,
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "refresh"
        }
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify and decode JWT token
        
        Args:
            token: JWT token
            
        Returns:
            Decoded token payload or None if invalid
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm]
            )
            return payload
        except jwt.ExpiredSignatureError:
            self.logger.warning("Token has expired")
            return None
        except jwt.InvalidTokenError as e:
            self.logger.warning(f"Invalid token: {e}")
            return None
    
    # ========================================================================
    # User Management
    # ========================================================================
    
    async def create_user(
        self,
        user_data: UserCreate,
        db: AsyncSession
    ) -> tuple[bool, Optional[int], Optional[str]]:
        """
        Create a new user
        
        Args:
            user_data: User creation data
            db: Database session
            
        Returns:
            Tuple of (success, user_id, error_message)
        """
        try:
            # Check if username already exists
            from models import User as UserModel
            
            result = await db.execute(
                select(UserModel).where(UserModel.username == user_data.username)
            )
            existing_user = result.scalar_one_or_none()
            
            if existing_user:
                return False, None, "Username already exists"
            
            # Check if email already exists
            result = await db.execute(
                select(UserModel).where(UserModel.email == user_data.email)
            )
            existing_email = result.scalar_one_or_none()
            
            if existing_email:
                return False, None, "Email already exists"
            
            # Validate role
            valid_roles = [UserRole.ADMIN, UserRole.VETTER, UserRole.REVIEWER, UserRole.SUBMITTER]
            if user_data.role not in valid_roles:
                return False, None, f"Invalid role. Must be one of: {', '.join(valid_roles)}"
            
            # Hash password
            hashed_password = self.hash_password(user_data.password)
            
            # Create user
            user = UserModel(
                username=user_data.username,
                email=user_data.email,
                password_hash=hashed_password,
                role=user_data.role,
                is_active=True,
                created_at=datetime.utcnow()
            )
            
            db.add(user)
            await db.commit()
            await db.refresh(user)
            
            self.logger.info(f"Created user: {user.username} (ID: {user.id})")
            
            return True, user.id, None
            
        except Exception as e:
            self.logger.error(f"Error creating user: {e}", exc_info=True)
            await db.rollback()
            return False, None, f"Failed to create user: {str(e)}"
    
    async def authenticate_user(
        self,
        username: str,
        password: str,
        db: AsyncSession
    ) -> Optional[Dict[str, Any]]:
        """
        Authenticate a user
        
        Args:
            username: Username
            password: Plain text password
            db: Database session
            
        Returns:
            User data dict or None if authentication fails
        """
        try:
            from models import User as UserModel
            
            # Get user by username
            result = await db.execute(
                select(UserModel).where(UserModel.username == username)
            )
            user = result.scalar_one_or_none()
            
            if not user:
                self.logger.warning(f"Authentication failed: user not found: {username}")
                return None
            
            if not user.is_active:
                self.logger.warning(f"Authentication failed: user inactive: {username}")
                return None
            
            # Verify password
            if not self.verify_password(password, user.password_hash):
                self.logger.warning(f"Authentication failed: invalid password: {username}")
                return None
            
            # Return user data
            return {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "is_active": user.is_active
            }
            
        except Exception as e:
            self.logger.error(f"Error authenticating user: {e}", exc_info=True)
            return None
    
    async def get_user_by_id(
        self,
        user_id: int,
        db: AsyncSession
    ) -> Optional[Dict[str, Any]]:
        """
        Get user by ID
        
        Args:
            user_id: User ID
            db: Database session
            
        Returns:
            User data dict or None
        """
        try:
            from models import User as UserModel
            
            result = await db.execute(
                select(UserModel).where(UserModel.id == user_id)
            )
            user = result.scalar_one_or_none()
            
            if not user:
                return None
            
            return {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "is_active": user.is_active,
                "created_at": user.created_at
            }
            
        except Exception as e:
            self.logger.error(f"Error getting user: {e}", exc_info=True)
            return None
    
    # ========================================================================
    # Authorization Helpers
    # ========================================================================
    
    def check_permission(self, user_role: str, required_role: str) -> bool:
        """
        Check if user role has required permission
        
        Role hierarchy: admin > vetter > reviewer > submitter
        
        Args:
            user_role: User's role
            required_role: Required role
            
        Returns:
            True if user has permission
        """
        role_hierarchy = {
            UserRole.ADMIN: 4,
            UserRole.VETTER: 3,
            UserRole.REVIEWER: 2,
            UserRole.SUBMITTER: 1
        }
        
        user_level = role_hierarchy.get(user_role, 0)
        required_level = role_hierarchy.get(required_role, 0)
        
        return user_level >= required_level
    
    def is_admin(self, user_role: str) -> bool:
        """Check if user is admin"""
        return user_role == UserRole.ADMIN
    
    def is_vetter(self, user_role: str) -> bool:
        """Check if user is vetter or admin"""
        return user_role in [UserRole.ADMIN, UserRole.VETTER]
    
    def is_reviewer(self, user_role: str) -> bool:
        """Check if user is reviewer or above"""
        return user_role in [UserRole.ADMIN, UserRole.VETTER, UserRole.REVIEWER]
    
    # ========================================================================
    # API Key Management (for service-to-service)
    # ========================================================================
    
    def generate_api_key(self) -> str:
        """
        Generate a secure API key
        
        Returns:
            API key string
        """
        return secrets.token_urlsafe(32)
    
    def hash_api_key(self, api_key: str) -> str:
        """
        Hash an API key for storage
        
        Args:
            api_key: Plain API key
            
        Returns:
            Hashed API key
        """
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    async def verify_api_key(
        self,
        api_key: str,
        db: AsyncSession
    ) -> Optional[Dict[str, Any]]:
        """
        Verify an API key
        
        Args:
            api_key: API key to verify
            db: Database session
            
        Returns:
            API key data or None
        """
        try:
            from models import ApiKey
            
            api_key_hash = self.hash_api_key(api_key)
            
            result = await db.execute(
                select(ApiKey).where(
                    ApiKey.key_hash == api_key_hash,
                    ApiKey.is_active == True
                )
            )
            key_record = result.scalar_one_or_none()
            
            if not key_record:
                return None
            
            # Update last used timestamp
            await db.execute(
                update(ApiKey)
                .where(ApiKey.id == key_record.id)
                .values(last_used_at=datetime.utcnow())
            )
            await db.commit()
            
            return {
                "id": key_record.id,
                "name": key_record.name,
                "user_id": key_record.user_id,
                "scopes": key_record.scopes
            }
            
        except Exception as e:
            self.logger.error(f"Error verifying API key: {e}", exc_info=True)
            return None


# Global auth service instance
_auth_service: Optional[AuthService] = None


def get_auth_service() -> AuthService:
    """Get global auth service instance"""
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service