"""
Authentication Models Extension for models.py

Add these two model classes to backend/models.py after the existing models.
These models support the authentication system.
"""

from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text, 
    JSON, ForeignKey, Index
)
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from database import Base


# ============================================================================
# Table 10: Users
# ============================================================================

class User(Base):
    """
    User accounts for authentication
    
    Supports multiple roles: admin, vetter, reviewer, submitter
    """
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, index=True)  # admin, vetter, reviewer, submitter
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    api_keys = relationship("ApiKey", back_populates="user", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index('idx_user_username_active', 'username', 'is_active'),
        Index('idx_user_email_active', 'email', 'is_active'),
        Index('idx_user_role', 'role'),
    )
    
    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}')>"


# ============================================================================
# Table 11: API Keys
# ============================================================================

class ApiKey(Base):
    """
    API keys for service-to-service authentication
    
    Allows programmatic access without user credentials
    """
    __tablename__ = "api_keys"
    
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    name = Column(String(100), nullable=False)  # Descriptive name for the key
    key_hash = Column(String(64), unique=True, nullable=False, index=True)  # SHA256 hash of actual key
    scopes = Column(JSON, nullable=True)  # List of permitted scopes/permissions
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="api_keys")
    
    # Indexes
    __table_args__ = (
        Index('idx_apikey_hash_active', 'key_hash', 'is_active'),
        Index('idx_apikey_user', 'user_id'),
    )
    
    def __repr__(self):
        return f"<ApiKey(id={self.id}, name='{self.name}', user_id={self.user_id})>"


# ============================================================================
# Update get_all_models() function in models.py
# ============================================================================

"""
Add to the get_all_models() function in models.py:

def get_all_models():
    return [
        Submission,
        Ring,
        Reviewer,
        Vote,
        Token,
        Escalation,
        AuditLog,
        Tally,
        Revocation,
        User,        # <-- Add this
        ApiKey       # <-- Add this
    ]
"""