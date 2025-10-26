"""
Pydantic schemas for API requests and responses
"""

from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

# Enums
class VoteType(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"
    FLAG = "flag"
    ESCALATE = "escalate"

class SubmissionStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    FLAGGED = "flagged"

class EscalationStatus(str, Enum):
    PENDING = "pending"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"

# Base schemas
class BaseSchema(BaseModel):
    class Config:
        from_attributes = True

# Ring schemas
class RingCreate(BaseModel):
    genre: str = Field(..., min_length=1, max_length=50)
    pubkeys: List[str] = Field(..., min_items=2, max_items=1000)
    epoch: int = Field(..., ge=1)

class RingResponse(BaseSchema):
    id: int
    genre: str
    pubkeys: List[str]
    epoch: int
    created_at: datetime
    active: bool

# Vote schemas
class VoteSubmission(BaseModel):
    submission_id: int = Field(..., ge=1)
    ring_id: int = Field(..., ge=1)
    signature_blob: str = Field(..., min_length=1)
    vote_type: VoteType
    token_id: str = Field(..., min_length=1)
    message: str = Field(..., min_length=1)  # Canonical message

class VoteResponse(BaseSchema):
    vote_id: int
    submission_id: int
    vote_type: str
    verified: bool
    created_at: datetime

# Token schemas
class CredentialPresentation(BaseModel):
    message: str = Field(..., min_length=1)
    signature: str = Field(..., min_length=1)
    public_key: str = Field(..., min_length=1)
    credential_hash: str = Field(..., min_length=1)
    epoch: int = Field(..., ge=1)
    token_count: int = Field(..., ge=1, le=10)

class TokenResponse(BaseSchema):
    tokens: List[Dict[str, Any]]
    issued_at: datetime

class CredentialRevocation(BaseModel):
    credential_hash: str = Field(..., min_length=1)
    reason: str = Field(..., min_length=1, max_length=100)

# Blind signature schemas
class BlindSignatureRequest(BaseModel):
    blinded_message: str = Field(..., min_length=1)

class BlindSignatureResponse(BaseSchema):
    signature: str
    created_at: datetime

# Tally schemas
class TallyResponse(BaseSchema):
    id: int
    submission_id: int
    count_approve: int
    count_reject: int
    count_flag: int
    count_escalate: int
    total_votes: int
    decision: str
    created_at: datetime
    updated_at: datetime

# Submission schemas
class SubmissionCreate(BaseModel):
    genre: str = Field(..., min_length=1, max_length=50)
    content_ref: str = Field(..., min_length=1)
    submitter_ip_hash: str = Field(..., min_length=1)
    submitter_mac_hash: Optional[str] = None

class SubmissionResponse(BaseSchema):
    id: int
    genre: str
    content_ref: str
    status: str
    created_at: datetime
    last_tallied_at: Optional[datetime]

# Escalation schemas
class EscalationCreate(BaseModel):
    submission_id: int = Field(..., ge=1)
    reason: str = Field(..., min_length=1, max_length=100)
    evidence_blob: str = Field(..., min_length=1)

class EscalationResponse(BaseSchema):
    id: int
    submission_id: int
    reason: str
    status: str
    requested_at: datetime
    resolved_at: Optional[datetime]
    resolved_by: Optional[str]

# Monitoring schemas
class EventResponse(BaseSchema):
    id: int
    event_type: str
    user_id: Optional[str]
    data: Optional[Dict[str, Any]]
    created_at: datetime

class MetricsResponse(BaseSchema):
    total_submissions: int
    total_votes: int
    total_rings: int
    active_tokens: int
    pending_escalations: int
    system_uptime: float
    last_updated: datetime

# Health check schema
class HealthResponse(BaseSchema):
    status: str
    timestamp: datetime
    version: str
    crypto_library: str
    services: Dict[str, Any]

# Error schemas
class ErrorResponse(BaseModel):
    detail: str
    error_code: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

# Rate limiting schemas
class RateLimitResponse(BaseModel):
    message: str
    retry_after: int
    limit: int
    remaining: int
    reset_time: datetime
