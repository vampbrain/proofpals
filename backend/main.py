

from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
import logging
import sys


# Import configuration and database
from config import settings
from database import get_db, init_db, close_db

# Import services
from crypto_service import get_crypto_service
from token_service import get_token_service
from vote_service import get_vote_service
from tally_service import get_tally_service

# Import models
from models import VoteType

# Add these imports at the top of main.py after existing imports

from sqlalchemy import update, select

# Import new services
from auth_service import get_auth_service
from vetter_service import get_vetter_service
from escalation_service import get_escalation_service
from monitoring_service import get_monitoring_service

# Import auth middleware
from middleware.auth_middleware import (
    get_current_user,
    get_optional_user,
    require_admin,
    require_vetter,
    require_reviewer,
    get_current_user_or_api_key
)

# Import auth schemas
from schemas.auth_schemas import (
    RegisterRequest,
    LoginRequest,
    RefreshTokenRequest,
    PasswordChangeRequest,
    TokenResponse,
    UserResponse,
    ErrorResponse,
    CurrentUser
)

# Configure logging
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Anonymous ring-based journalist review system with sybil-resistant credentials",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Pydantic Models for API
# ============================================================================

class HealthResponse(BaseModel):
    status: str
    timestamp: str
    version: str
    crypto_library: str
    database: str


class VoteRequest(BaseModel):
    submission_id: int = Field(..., gt=0)
    ring_id: int = Field(..., gt=0)
    signature_blob: str = Field(..., min_length=1)
    vote_type: str = Field(..., pattern="^(approve|reject|escalate|flag)$")
    token_id: str = Field(..., min_length=1)
    message: str = Field(..., min_length=1)  # hex-encoded bytes


class VoteResponse(BaseModel):
    success: bool
    vote_id: Optional[int] = None
    key_image: Optional[str] = None
    message: Optional[str] = None
    error: Optional[str] = None


class TallyResponse(BaseModel):
    success: bool
    tally_id: Optional[int] = None
    counts: Optional[dict] = None
    total_votes: Optional[int] = None
    decision: Optional[str] = None
    computed_at: Optional[str] = None
    error: Optional[str] = None


class CredentialRequest(BaseModel):
    credential_hash: str = Field(..., min_length=1)
    epoch: int = Field(..., gt=0)
    token_count: int = Field(default=5, gt=0, le=100)


class CredentialResponse(BaseModel):
    success: bool
    tokens: Optional[List[str]] = None
    credential_hash: Optional[str] = None
    epoch: Optional[int] = None
    error: Optional[str] = None


class SubmissionRequest(BaseModel):
    genre: str = Field(..., min_length=1, max_length=100)
    content_ref: str = Field(..., min_length=1)
    submitter_ip: Optional[str] = None
    submitter_mac: Optional[str] = None


class SubmissionResponse(BaseModel):
    success: bool
    submission_id: Optional[int] = None
    status: Optional[str] = None
    error: Optional[str] = None


# ============================================================================
# Startup and Shutdown Events
# ============================================================================

# Replace the startup_event function in main.py

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    logger.info("Starting ProofPals Backend...")
    
    try:
        # Initialize database
        await init_db()
        logger.info("✓ Database initialized")
        
        # Initialize Redis for token service
        token_service = get_token_service()
        await token_service.init_redis()
        logger.info("✓ Redis connection established")
        
        # Initialize vetter service with RSA keypair
        vetter_service = get_vetter_service()
        # Keypair already initialized in get_vetter_service()
        logger.info("✓ Vetter service initialized")
        
        # Initialize monitoring service
        monitoring_service = get_monitoring_service()
        logger.info("✓ Monitoring service initialized")
        
        # Check crypto library
        crypto_service = get_crypto_service()
        health = crypto_service.health_check()
        if health["status"] == "healthy":
            logger.info("✓ Crypto library loaded")
        else:
            logger.error(f"✗ Crypto library unhealthy: {health.get('error')}")
        
        logger.info(f"🚀 {settings.APP_NAME} v{settings.APP_VERSION} started successfully")
        
    except Exception as e:
        logger.error(f"Failed to start application: {e}", exc_info=True)
        raise


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("Shutting down ProofPals Backend...")
    
    try:
        # Close Redis
        token_service = get_token_service()
        await token_service.close_redis()
        logger.info("✓ Redis connection closed")
        
        # Close database
        await close_db()
        logger.info("✓ Database connections closed")
        
        logger.info("👋 Shutdown complete")
        
    except Exception as e:
        logger.error(f"Error during shutdown: {e}", exc_info=True)


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    try:
        crypto_service = get_crypto_service()
        crypto_health = crypto_service.health_check()
        
        return HealthResponse(
            status="healthy",
            timestamp=datetime.utcnow().isoformat(),
            version=settings.APP_VERSION,
            crypto_library=crypto_health.get("library", "unknown"),
            database="postgresql"
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        return HealthResponse(
            status="unhealthy",
            timestamp=datetime.utcnow().isoformat(),
            version=settings.APP_VERSION,
            crypto_library="error",
            database="error"
        )
# ============================================================================
# Authentication Endpoints
# ============================================================================

@app.post("/api/v1/auth/register", response_model=TokenResponse, tags=["Authentication"])
async def register(
    request: RegisterRequest,
    db: AsyncSession = Depends(get_db)
):
    """Register a new user and return tokens"""
    auth_service = get_auth_service()
    
    success, user_id, error = await auth_service.create_user(request, db)
    
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)
    
    # Get user data
    user_data = await auth_service.get_user_by_id(user_id, db)
    
    # Generate tokens
    access_token = auth_service.create_access_token(
        user_id=user_data["id"],
        username=user_data["username"],
        role=user_data["role"]
    )
    
    refresh_token = auth_service.create_refresh_token(
        user_id=user_data["id"],
        username=user_data["username"]
    )
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse(**user_data)
    )


@app.post("/api/v1/auth/login", response_model=TokenResponse, tags=["Authentication"])
async def login(
    request: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    """Login with username and password"""
    auth_service = get_auth_service()
    
    user_data = await auth_service.authenticate_user(
        username=request.username,
        password=request.password,
        db=db
    )
    
    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Update last login
    from models import User as UserModel
    await db.execute(
        update(UserModel)
        .where(UserModel.id == user_data["id"])
        .values(last_login_at=datetime.utcnow())
    )
    await db.commit()
    
    # Generate tokens
    access_token = auth_service.create_access_token(
        user_id=user_data["id"],
        username=user_data["username"],
        role=user_data["role"]
    )
    
    refresh_token = auth_service.create_refresh_token(
        user_id=user_data["id"],
        username=user_data["username"]
    )
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse(**user_data)
    )


@app.post("/api/v1/auth/refresh", response_model=TokenResponse, tags=["Authentication"])
async def refresh_token(
    request: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db)
):
    """Refresh access token"""
    auth_service = get_auth_service()
    
    payload = auth_service.verify_token(request.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    user_id = int(payload.get("sub"))
    user_data = await auth_service.get_user_by_id(user_id, db)
    
    if not user_data or not user_data.get("is_active"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    access_token = auth_service.create_access_token(
        user_id=user_data["id"],
        username=user_data["username"],
        role=user_data["role"]
    )
    
    refresh_token = auth_service.create_refresh_token(
        user_id=user_data["id"],
        username=user_data["username"]
    )
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse(**user_data)
    )


@app.get("/api/v1/auth/me", response_model=UserResponse, tags=["Authentication"])
async def get_current_user_info(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get current user information"""
    auth_service = get_auth_service()
    user_data = await auth_service.get_user_by_id(current_user.id, db)
    
    if not user_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    return UserResponse(**user_data)


@app.post("/api/v1/auth/change-password", tags=["Authentication"])
async def change_password(
    request: PasswordChangeRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Change user password"""
    auth_service = get_auth_service()
    
    from models import User as UserModel
    result = await db.execute(select(UserModel).where(UserModel.id == current_user.id))
    user = result.scalar_one_or_none()
    
    if not user or not auth_service.verify_password(request.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    new_password_hash = auth_service.hash_password(request.new_password)
    await db.execute(
        update(UserModel)
        .where(UserModel.id == current_user.id)
        .values(password_hash=new_password_hash)
    )
    await db.commit()
    
    return {"message": "Password changed successfully"}

# ============================================================================
# Vetter Endpoints (Blind Credential Issuance)
# ============================================================================

@app.get("/api/v1/vetter/public-key", tags=["Vetter"])
async def get_vetter_public_key():
    """Get vetter's public key for blind signing"""
    vetter_service = get_vetter_service()
    public_key = vetter_service.get_public_key()
    
    return {
        "public_key": public_key.hex(),
        "algorithm": "RSA-2048",
        "purpose": "blind_signature"
    }


@app.post("/api/v1/vetter/blind-sign", tags=["Vetter"])
async def blind_sign(
    blinded_data: dict,
    current_user: CurrentUser = Depends(require_vetter),
    db: AsyncSession = Depends(get_db)
):
    """
    Issue a blind signature (vetter only)
    
    Request body:
    {
        "blinded_message": "hex-encoded blinded message",
        "metadata": {"optional": "metadata"}
    }
    """
    try:
        blinded_message = bytes.fromhex(blinded_data["blinded_message"])
        metadata = blinded_data.get("metadata", {})
        
        vetter_service = get_vetter_service()
        success, signature_bytes, error = await vetter_service.issue_blind_signature(
            blinded_message,
            current_user.id,
            db,
            metadata
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error
            )
        
        return {
            "success": True,
            "blind_signature": signature_bytes.hex(),
            "issued_by": current_user.username,
            "issued_at": datetime.utcnow().isoformat()
        }
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid hex encoding: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Error in blind_sign: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Blind signing failed: {str(e)}"
        )


@app.post("/api/v1/vetter/register-credential", tags=["Vetter"])
async def register_credential(
    credential_data: dict,
    current_user: CurrentUser = Depends(require_reviewer),
    db: AsyncSession = Depends(get_db)
):
    """
    Register a credential after unblinding
    
    Request body:
    {
        "credential_hash": "sha256 hash of credential",
        "profile_hash": "optional profile identifier",
        "credential_meta": {"optional": "encrypted metadata"}
    }
    """
    vetter_service = get_vetter_service()
    
    success, reviewer_id, error = await vetter_service.register_credential(
        credential_hash=credential_data["credential_hash"],
        profile_hash=credential_data.get("profile_hash"),
        credential_meta=credential_data.get("credential_meta"),
        db=db
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    return {
        "success": True,
        "reviewer_id": reviewer_id,
        "credential_hash": credential_data["credential_hash"][:16] + "...",
        "registered_at": datetime.utcnow().isoformat()
    }


@app.post("/api/v1/vetter/revoke-credential", tags=["Vetter"])
async def revoke_credential(
    revocation_data: dict,
    current_user: CurrentUser = Depends(require_vetter),
    db: AsyncSession = Depends(get_db)
):
    """
    Revoke a credential (vetter/admin only)
    
    Request body:
    {
        "credential_hash": "credential to revoke",
        "reason": "reason for revocation",
        "evidence": "optional evidence"
    }
    """
    vetter_service = get_vetter_service()
    
    success, error = await vetter_service.revoke_credential(
        credential_hash=revocation_data["credential_hash"],
        reason=revocation_data["reason"],
        revoked_by=current_user.id,
        evidence=revocation_data.get("evidence"),
        db=db
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    return {
        "success": True,
        "message": "Credential revoked successfully",
        "revoked_by": current_user.username,
        "revoked_at": datetime.utcnow().isoformat()
    }


@app.get("/api/v1/vetter/statistics", tags=["Vetter"])
async def get_vetter_statistics(
    current_user: CurrentUser = Depends(require_vetter),
    db: AsyncSession = Depends(get_db)
):
    """Get vetter statistics (vetter/admin only)"""
    vetter_service = get_vetter_service()
    stats = await vetter_service.get_vetter_statistics(db)
    
    return {
        "success": True,
        "statistics": stats,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/v1/vote", response_model=VoteResponse)
async def submit_vote(
    vote_request: VoteRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Submit a vote on a submission
    
    This endpoint handles the complete vote verification pipeline:
    1. Atomically consumes the token (prevents double-voting)
    2. Verifies the CLSAG ring signature
    3. Checks for duplicate key images
    4. Stores the verified vote
    """
    try:
        # Get IP address for audit logging
        ip_address = request.client.host if request.client else None
        
        # Convert hex-encoded message to bytes
        try:
            message_bytes = bytes.fromhex(vote_request.message)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid message format: must be hex-encoded"
            )
        
        # Submit vote through service
        vote_service = get_vote_service()
        result = await vote_service.submit_vote(
            submission_id=vote_request.submission_id,
            ring_id=vote_request.ring_id,
            signature_blob=vote_request.signature_blob,
            vote_type=vote_request.vote_type,
            token_id=vote_request.token_id,
            message=message_bytes,
            db=db,
            ip_address=ip_address
        )
        
        if not result["success"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get("error", "Vote submission failed")
            )
        
        # Check if we should compute tally
        tally_service = get_tally_service()
        if await tally_service.should_compute_tally(vote_request.submission_id, db):
            await tally_service.compute_tally(vote_request.submission_id, db)
        
        return VoteResponse(
            success=True,
            vote_id=result["vote_id"],
            key_image=result["key_image"],
            message="Vote submitted successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in submit_vote endpoint: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/api/v1/tally/{submission_id}", response_model=TallyResponse)
async def get_tally(
    submission_id: int,
    db: AsyncSession = Depends(get_db)
):
    """
    Get or compute tally for a submission
    """
    try:
        tally_service = get_tally_service()
        
        # Try to get existing tally
        existing_tally = await tally_service.get_tally_by_submission(submission_id, db)
        
        if existing_tally:
            return TallyResponse(
                success=True,
                **existing_tally
            )
        
        # Compute new tally
        result = await tally_service.compute_tally(submission_id, db)
        
        if not result["success"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get("error", "Tally computation failed")
            )
        
        return TallyResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_tally endpoint: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.post("/api/v1/present-credential", response_model=CredentialResponse)
async def present_credential(
    credential_request: CredentialRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Present a blind credential and receive epoch tokens
    
    In production, this would verify the blind signature first.
    For now, it creates tokens for valid credentials.
    """
    try:
        token_service = get_token_service()
        
        success, token_ids, error = await token_service.create_epoch_tokens(
            credential_hash=credential_request.credential_hash,
            epoch=credential_request.epoch,
            token_count=credential_request.token_count,
            db=db
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error
            )
        
        return CredentialResponse(
            success=True,
            tokens=token_ids,
            credential_hash=credential_request.credential_hash,
            epoch=credential_request.epoch
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in present_credential endpoint: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.post("/api/v1/submissions", response_model=SubmissionResponse)
async def create_submission(
    submission_request: SubmissionRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new submission
    """
    try:
        import hashlib
        from models import Submission
        
        # Hash submitter identifiers
        ip_hash = None
        if submission_request.submitter_ip:
            ip_hash = hashlib.sha256(
                submission_request.submitter_ip.encode()
            ).hexdigest()
        
        mac_hash = None
        if submission_request.submitter_mac:
            mac_hash = hashlib.sha256(
                submission_request.submitter_mac.encode()
            ).hexdigest()
        
        # Create submission
        submission = Submission(
            genre=submission_request.genre,
            content_ref=submission_request.content_ref,
            submitter_ip_hash=ip_hash or "unknown",
            submitter_mac_hash=mac_hash,
            status="pending",
            created_at=datetime.utcnow()
        )
        
        db.add(submission)
        await db.commit()
        await db.refresh(submission)
        
        logger.info(f"Created submission {submission.id} in genre {submission.genre}")
        
        return SubmissionResponse(
            success=True,
            submission_id=submission.id,
            status=submission.status
        )
        
    except Exception as e:
        logger.error(f"Error creating submission: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create submission: {str(e)}"
        )


@app.get("/api/v1/submissions/{submission_id}")
async def get_submission(
    submission_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Get submission details"""
    try:
        from sqlalchemy import select
        from models import Submission
        
        result = await db.execute(
            select(Submission).where(Submission.id == submission_id)
        )
        submission = result.scalar_one_or_none()
        
        if not submission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Submission not found"
            )
        
        return {
            "submission_id": submission.id,
            "genre": submission.genre,
            "content_ref": submission.content_ref,
            "status": submission.status,
            "created_at": submission.created_at.isoformat(),
            "last_tallied_at": submission.last_tallied_at.isoformat() if submission.last_tallied_at else None
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting submission: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.post("/api/v1/rings")
async def create_ring(
    ring_data: dict,
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new ring (admin endpoint)
    
    In production, this would require authentication.
    """
    try:
        from models import Ring
        
        ring = Ring(
            genre=ring_data["genre"],
            pubkeys=ring_data["pubkeys"],
            epoch=ring_data["epoch"],
            active=True,
            created_at=datetime.utcnow()
        )
        
        db.add(ring)
        await db.commit()
        await db.refresh(ring)
        
        logger.info(f"Created ring {ring.id} with {len(ring.pubkeys)} members")
        
        return {
            "success": True,
            "ring_id": ring.id,
            "genre": ring.genre,
            "epoch": ring.epoch,
            "member_count": len(ring.pubkeys)
        }
        
    except Exception as e:
        logger.error(f"Error creating ring: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create ring: {str(e)}"
        )


@app.get("/api/v1/rings/{ring_id}")
async def get_ring(
    ring_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Get ring details"""
    try:
        from sqlalchemy import select
        from models import Ring
        
        result = await db.execute(
            select(Ring).where(Ring.id == ring_id)
        )
        ring = result.scalar_one_or_none()
        
        if not ring:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Ring not found"
            )
        
        return {
            "ring_id": ring.id,
            "genre": ring.genre,
            "epoch": ring.epoch,
            "member_count": len(ring.pubkeys),
            "active": ring.active,
            "created_at": ring.created_at.isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting ring: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/api/v1/statistics")
async def get_statistics(db: AsyncSession = Depends(get_db)):
    """Get system statistics"""
    try:
        # Get vote service stats
        vote_service = get_vote_service()
        
        # Get tally service stats
        tally_service = get_tally_service()
        tally_stats = await tally_service.get_statistics(db)
        
        # Get token stats
        token_service = get_token_service()
        token_stats = await token_service.get_token_stats(db)
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "tallies": tally_stats,
            "tokens": token_stats
        }
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


# ============================================================================
# Error Handlers
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.utcnow().isoformat()
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """General exception handler"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal server error",
            "detail": str(exc) if settings.DEBUG else "An error occurred",
            "status_code": 500,
            "timestamp": datetime.utcnow().isoformat()
        }
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level="info"
    )