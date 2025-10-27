"""
ProofPals Database Models
All 9 tables with proper relationships and indexes
"""

from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text, 
    LargeBinary, JSON, ForeignKey, Index, BigInteger, 
    Enum as SQLEnum, UniqueConstraint
)
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base
import enum


# ============================================================================
# Enumerations
# ============================================================================

class SubmissionStatus(str, enum.Enum):
    """Submission status enumeration"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    ESCALATED = "escalated"
    FLAGGED = "flagged"


class VoteType(str, enum.Enum):
    """Vote type enumeration"""
    APPROVE = "approve"
    ESCALATE = "escalate"
    REJECT = "reject"
    FLAG = "flag"


class EscalationStatus(str, enum.Enum):
    """Escalation status enumeration"""
    PENDING = "pending"
    UNDER_REVIEW = "under_review"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


# ============================================================================
# Table 1: Submissions
# ============================================================================

class Submission(Base):
    """
    Content submissions from users
    
    Stores minimal metadata about submitted content.
    IP/MAC hashes are ONLY used for escalation/legal requests.
    """
    __tablename__ = "submissions"
    
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    genre = Column(String(100), nullable=False, index=True)
    content_ref = Column(String(500), nullable=False)  # URL or hash reference
    submitter_ip_hash = Column(String(64), nullable=False)  # SHA256 hash
    submitter_mac_hash = Column(String(64), nullable=True)  # SHA256 hash (optional)
    status = Column(
        SQLEnum(SubmissionStatus), 
        default=SubmissionStatus.PENDING, 
        nullable=False,
        index=True
    )
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_tallied_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    votes = relationship("Vote", back_populates="submission", cascade="all, delete-orphan")
    tally = relationship("Tally", back_populates="submission", uselist=False, cascade="all, delete-orphan")
    escalations = relationship("Escalation", back_populates="submission", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index('idx_submission_genre_status', 'genre', 'status'),
        Index('idx_submission_created', 'created_at'),
    )
    
    def __repr__(self):
        return f"<Submission(id={self.id}, genre='{self.genre}', status='{self.status}')>"


# ============================================================================
# Table 2: Rings
# ============================================================================

class Ring(Base):
    """
    Anonymity rings of reviewer public keys
    
    Each ring contains multiple public keys (PKs) for a specific genre and epoch.
    Signatures prove membership in ring without revealing which PK signed.
    """
    __tablename__ = "rings"
    
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    genre = Column(String(100), nullable=False, index=True)
    pubkeys = Column(JSON, nullable=False)  # List of public key hex strings
    epoch = Column(Integer, nullable=False, index=True)
    active = Column(Boolean, default=True, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    votes = relationship("Vote", back_populates="ring")
    
    # Indexes
    __table_args__ = (
        Index('idx_ring_genre_epoch_active', 'genre', 'epoch', 'active'),
        Index('idx_ring_epoch', 'epoch'),
    )
    
    def __repr__(self):
        return f"<Ring(id={self.id}, genre='{self.genre}', epoch={self.epoch}, members={len(self.pubkeys) if self.pubkeys else 0})>"


# ============================================================================
# Table 3: Reviewers
# ============================================================================

class Reviewer(Base):
    """
    Verified reviewers with blind credentials
    
    credential_hash is derived from blind signature.
    No link to real identity is stored.
    """
    __tablename__ = "reviewers"
    
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    credential_hash = Column(String(64), unique=True, nullable=False, index=True)
    profile_hash = Column(String(64), nullable=True)  # Optional opaque identifier
    credential_meta = Column(JSON, nullable=True)  # Encrypted metadata if needed
    reputation_score = Column(Integer, default=100, nullable=False, index=True)  # Reputation for weighted voting
    reputation_history = Column(JSON, nullable=True)  # Track reputation changes
    revoked = Column(Boolean, default=False, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    tokens = relationship("Token", back_populates="reviewer", cascade="all, delete-orphan")
    revocations = relationship("Revocation", back_populates="reviewer", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index('idx_reviewer_revoked', 'revoked'),
    )
    
    def __repr__(self):
        return f"<Reviewer(id={self.id}, credential_hash='{self.credential_hash[:16]}...', revoked={self.revoked})>"


# ============================================================================
# Table 4: Votes
# ============================================================================

class Vote(Base):
    """
    Individual votes on submissions
    
    Each vote contains:
    - CLSAG ring signature (proves authenticity + anonymity)
    - key_image (enables linkability - same credential = same key_image)
    - token_id (consumed token for sybil resistance)
    
    CRITICAL: (submission_id, key_image) must be unique to prevent double voting
    """
    __tablename__ = "votes"
    
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    submission_id = Column(Integer, ForeignKey('submissions.id', ondelete='CASCADE'), nullable=False, index=True)
    ring_id = Column(Integer, ForeignKey('rings.id', ondelete='CASCADE'), nullable=False, index=True)
    signature_blob = Column(Text, nullable=False)  # JSON string of CLSAG signature
    key_image = Column(String(64), nullable=False, index=True)  # Hex string for linkability
    vote_type = Column(SQLEnum(VoteType), nullable=False, index=True)
    token_id = Column(String(64), nullable=False, index=True)
    verified = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    submission = relationship("Submission", back_populates="votes")
    ring = relationship("Ring", back_populates="votes")
    
    # Indexes and Constraints
    __table_args__ = (
        # CRITICAL: Prevent duplicate votes from same credential on same submission
        UniqueConstraint('submission_id', 'key_image', name='uq_vote_submission_keyimage'),
        Index('idx_vote_submission_keyimage', 'submission_id', 'key_image'),
        Index('idx_vote_submission_created', 'submission_id', 'created_at'),
        Index('idx_vote_token', 'token_id'),
        Index('idx_vote_keyimage', 'key_image'),
    )
    
    def __repr__(self):
        return f"<Vote(id={self.id}, submission_id={self.submission_id}, type='{self.vote_type}', verified={self.verified})>"


# ============================================================================
# Table 5: Tokens
# ============================================================================

class Token(Base):
    """
    Epoch tokens for vote consumption
    
    Each reviewer credential gets N tokens per epoch.
    Tokens are consumed atomically to prevent double-voting.
    """
    __tablename__ = "tokens"
    
    token_id = Column(String(64), primary_key=True)  # SHA256 hash
    credential_hash = Column(
        String(64), 
        ForeignKey('reviewers.credential_hash', ondelete='CASCADE'), 
        nullable=False, 
        index=True
    )
    epoch = Column(Integer, nullable=False, index=True)
    redeemed = Column(Boolean, default=False, nullable=False, index=True)
    redeemed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    reviewer = relationship("Reviewer", back_populates="tokens")
    
    # Indexes
    __table_args__ = (
        Index('idx_token_redeemed_epoch', 'redeemed', 'epoch'),
        Index('idx_token_credential', 'credential_hash'),
    )
    
    def __repr__(self):
        return f"<Token(id='{self.token_id[:16]}...', epoch={self.epoch}, redeemed={self.redeemed})>"


# ============================================================================
# Table 6: Escalations
# ============================================================================

class Escalation(Base):
    """
    Flagged submissions requiring human review
    
    Evidence blob contains:
    - Content hash/snapshot
    - Vote distribution
    - Submitter metadata (encrypted)
    - Classifier results
    """
    __tablename__ = "escalations"
    
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    submission_id = Column(
        Integer, 
        ForeignKey('submissions.id', ondelete='CASCADE'), 
        nullable=False, 
        index=True
    )
    reason = Column(String(200), nullable=False)
    evidence_blob = Column(JSON, nullable=False)  # Encrypted package
    status = Column(
        SQLEnum(EscalationStatus), 
        default=EscalationStatus.PENDING, 
        nullable=False,
        index=True
    )
    requested_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolver_notes = Column(Text, nullable=True)
    
    # Relationships
    submission = relationship("Submission", back_populates="escalations")
    
    # Indexes
    __table_args__ = (
        Index('idx_escalation_status', 'status'),
        Index('idx_escalation_requested', 'requested_at'),
    )
    
    def __repr__(self):
        return f"<Escalation(id={self.id}, submission_id={self.submission_id}, status='{self.status}')>"


# ============================================================================
# Table 7: Audit Logs
# ============================================================================

class AuditLog(Base):
    """
    Append-only audit trail
    
    Records all significant events for transparency and investigation.
    """
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    event_type = Column(String(50), nullable=False, index=True)
    entity_type = Column(String(50), nullable=False)
    entity_id = Column(String(100), nullable=False)
    details = Column(JSON, nullable=False)  # Event-specific data
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    
    # Indexes
    __table_args__ = (
        Index('idx_audit_event_timestamp', 'event_type', 'timestamp'),
        Index('idx_audit_entity', 'entity_type', 'entity_id'),
        Index('idx_audit_timestamp', 'timestamp'),
    )
    
    def __repr__(self):
        return f"<AuditLog(id={self.id}, event='{self.event_type}', entity='{self.entity_type}:{self.entity_id}')>"


# ============================================================================
# Table 8: Tallies
# ============================================================================

class Tally(Base):
    """
    Computed vote tallies and decisions
    
    Stores aggregated vote counts and final decision per submission.
    """
    __tablename__ = "tallies"
    
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    submission_id = Column(
        Integer, 
        ForeignKey('submissions.id', ondelete='CASCADE'), 
        unique=True, 
        nullable=False
    )
    count_approve = Column(Integer, default=0, nullable=False)
    count_escalate = Column(Integer, default=0, nullable=False)
    count_reject = Column(Integer, default=0, nullable=False)
    count_flag = Column(Integer, default=0, nullable=False)
    final_decision = Column(String(20), nullable=True, index=True)
    computed_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    submission = relationship("Submission", back_populates="tally")
    
    # Indexes
    __table_args__ = (
        Index('idx_tally_decision', 'final_decision'),
        Index('idx_tally_computed', 'computed_at'),
    )
    
    def __repr__(self):
        return f"<Tally(id={self.id}, submission_id={self.submission_id}, decision='{self.final_decision}')>"


# ============================================================================
# Table 9: Revocations
# ============================================================================

class Revocation(Base):
    """
    Revoked credentials
    
    When a reviewer is found to be malicious, their credential is revoked.
    All existing tokens become invalid.
    """
    __tablename__ = "revocations"
    
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    credential_hash = Column(
        String(64), 
        ForeignKey('reviewers.credential_hash', ondelete='CASCADE'), 
        nullable=False, 
        index=True
    )
    reason = Column(String(200), nullable=False)
    evidence = Column(Text, nullable=True)
    revoked_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    revoked_by = Column(String(100), nullable=True)  # Admin identifier
    
    # Relationships
    reviewer = relationship("Reviewer", back_populates="revocations")
    
    # Indexes
    __table_args__ = (
        Index('idx_revocation_credential', 'credential_hash'),
        Index('idx_revocation_date', 'revoked_at'),
    )
    
    def __repr__(self):
        return f"<Revocation(id={self.id}, credential_hash='{self.credential_hash[:16]}...', reason='{self.reason}')>"

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
    role = Column(String(20), nullable=False, index=True)
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
    """
    __tablename__ = "api_keys"
    
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    key_hash = Column(String(64), unique=True, nullable=False, index=True)
    scopes = Column(JSON, nullable=True)
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
# Utility Functions
# ============================================================================

def get_all_models():
    """Get list of all model classes"""
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
        User,        
        ApiKey       
    ]


def print_schema_info():
    """Print information about all tables"""
    models = get_all_models()
    print(f"\n{'='*80}")
    print(f"ProofPals Database Schema - {len(models)} Tables")
    print(f"{'='*80}\n")
    
    for model in models:
        table = model.__table__
        print(f"Table: {table.name}")
        print(f"  Columns: {len(table.columns)}")
        for col in table.columns:
            nullable = "NULL" if col.nullable else "NOT NULL"
            pk = " [PK]" if col.primary_key else ""
            fk = " [FK]" if col.foreign_keys else ""
            unique = " [UNIQUE]" if col.unique else ""
            print(f"    - {col.name}: {col.type} {nullable}{pk}{fk}{unique}")
        
        if table.indexes:
            print(f"  Indexes: {len(table.indexes)}")
            for idx in table.indexes:
                cols = ", ".join([c.name for c in idx.columns])
                print(f"    - {idx.name}: ({cols})")
        print()


# For testing
if __name__ == "__main__":
    print_schema_info()