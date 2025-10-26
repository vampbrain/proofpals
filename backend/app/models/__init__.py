"""
Database models for ProofPals Backend
"""

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, JSON, ForeignKey, Index
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base
import uuid
from datetime import datetime

class Submission(Base):
    """Submissions table for content review"""
    __tablename__ = "submissions"
    
    id = Column(Integer, primary_key=True, index=True)
    genre = Column(String(50), nullable=False, index=True)
    content_ref = Column(String(255), nullable=False)  # Reference to content storage
    submitter_ip_hash = Column(String(64), nullable=False)  # Hashed IP for tracking
    submitter_mac_hash = Column(String(64), nullable=True)  # Hashed MAC for tracking
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(String(20), default="pending", index=True)  # pending, approved, rejected, flagged
    last_tallied_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    votes = relationship("Vote", back_populates="submission")
    escalations = relationship("Escalation", back_populates="submission")

class Ring(Base):
    """Rings table for anonymous voting groups"""
    __tablename__ = "rings"
    
    id = Column(Integer, primary_key=True, index=True)
    genre = Column(String(50), nullable=False, index=True)
    pubkeys = Column(JSON, nullable=False)  # List of public keys
    epoch = Column(Integer, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    active = Column(Boolean, default=True, index=True)
    
    # Relationships
    votes = relationship("Vote", back_populates="ring")
    
    # Indexes
    __table_args__ = (
        Index('ix_rings_genre_epoch', 'genre', 'epoch'),
        Index('ix_rings_active_epoch', 'active', 'epoch'),
    )

class Reviewer(Base):
    """Reviewers table for credential management"""
    __tablename__ = "reviewers"
    
    id = Column(Integer, primary_key=True, index=True)
    profile_hash = Column(String(64), nullable=True, index=True)  # Optional profile hash
    credential_meta = Column(Text, nullable=True)  # Encrypted credential metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    revoked_bool = Column(Boolean, default=False, index=True)
    
    # Relationships
    tokens = relationship("Token", back_populates="reviewer")

class Vote(Base):
    """Votes table for anonymous voting records"""
    __tablename__ = "votes"
    
    id = Column(Integer, primary_key=True, index=True)
    submission_id = Column(Integer, ForeignKey("submissions.id"), nullable=False, index=True)
    ring_id = Column(Integer, ForeignKey("rings.id"), nullable=False, index=True)
    signature_blob = Column(Text, nullable=False)  # Ring signature
    key_image = Column(String(64), nullable=False, index=True)  # Key image for linkability
    vote_type = Column(String(20), nullable=False, index=True)  # approve, reject, flag, escalate
    token_id = Column(String(64), nullable=False, index=True)  # Token used for this vote
    verified_bool = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    submission = relationship("Submission", back_populates="votes")
    ring = relationship("Ring", back_populates="votes")
    
    # Indexes
    __table_args__ = (
        Index('ix_votes_submission_key_image', 'submission_id', 'key_image'),
        Index('ix_votes_ring_vote_type', 'ring_id', 'vote_type'),
        Index('ix_votes_token_id', 'token_id'),
    )

class Token(Base):
    """Tokens table for epoch-based voting tokens"""
    __tablename__ = "tokens"
    
    token_id = Column(String(64), primary_key=True, index=True)
    cred_id_hash = Column(String(64), nullable=False, index=True)  # Credential hash
    reviewer_id = Column(Integer, ForeignKey("reviewers.id"), nullable=True)
    epoch = Column(Integer, nullable=False, index=True)
    redeemed_bool = Column(Boolean, default=False, index=True)
    redeemed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    reviewer = relationship("Reviewer", back_populates="tokens")
    
    # Indexes
    __table_args__ = (
        Index('ix_tokens_cred_epoch', 'cred_id_hash', 'epoch'),
        Index('ix_tokens_redeemed_epoch', 'redeemed_bool', 'epoch'),
    )

class Escalation(Base):
    """Escalations table for flagged content"""
    __tablename__ = "escalations"
    
    id = Column(Integer, primary_key=True, index=True)
    submission_id = Column(Integer, ForeignKey("submissions.id"), nullable=False, index=True)
    reason = Column(String(100), nullable=False)
    evidence_blob = Column(Text, nullable=False)  # Encrypted evidence package
    status = Column(String(20), default="pending", index=True)  # pending, resolved, dismissed
    requested_at = Column(DateTime(timezone=True), server_default=func.now())
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolved_by = Column(String(64), nullable=True)  # Trustee identifier
    
    # Relationships
    submission = relationship("Submission", back_populates="escalations")

class AuditLog(Base):
    """Audit logs table for append-only logging"""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(50), nullable=False, index=True)
    user_id = Column(String(64), nullable=True, index=True)
    data = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Indexes
    __table_args__ = (
        Index('ix_audit_logs_event_type_created', 'event_type', 'created_at'),
        Index('ix_audit_logs_user_created', 'user_id', 'created_at'),
    )

class Tally(Base):
    """Tally results table for vote aggregation"""
    __tablename__ = "tallies"
    
    id = Column(Integer, primary_key=True, index=True)
    submission_id = Column(Integer, ForeignKey("submissions.id"), nullable=False, index=True)
    count_approve = Column(Integer, default=0)
    count_reject = Column(Integer, default=0)
    count_flag = Column(Integer, default=0)
    count_escalate = Column(Integer, default=0)
    total_votes = Column(Integer, default=0)
    decision = Column(String(20), nullable=False)  # approved, rejected, escalated
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    submission = relationship("Submission")

class Revocation(Base):
    """Revocation list for credentials"""
    __tablename__ = "revocations"
    
    id = Column(Integer, primary_key=True, index=True)
    credential_hash = Column(String(64), nullable=False, index=True)
    reason = Column(String(100), nullable=False)
    revoked_by = Column(String(64), nullable=False)
    revoked_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Indexes
    __table_args__ = (
        Index('ix_revocations_cred_hash', 'credential_hash'),
    )
