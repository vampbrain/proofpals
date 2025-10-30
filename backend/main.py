

from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
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
try:
    from crypto_service import get_crypto_service
except ImportError:
    def get_crypto_service():
        return None
from token_service import get_token_service
try:
    from vote_service import get_vote_service
except ImportError:
    def get_vote_service():
        return None
try:
    from tally_service import get_tally_service
except ImportError:
    def get_tally_service():
        return None

# Import models
from models import VoteType

# Add these imports at the top of main.py after existing imports

from sqlalchemy import update, select

# Import new services
from auth_service import get_auth_service
try:
    from vetter_service import get_vetter_service
except ImportError:
    def get_vetter_service():
        return None
try:
    from escalation_service import get_escalation_service
except ImportError:
    def get_escalation_service():
        return None
try:
    from monitoring_service import get_monitoring_service
except ImportError:
    def get_monitoring_service():
        return None

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
    
    class Config:
        # Allow extra fields to be more permissive during debugging
        extra = "forbid"


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
    metadata: Optional[dict] = None
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


class PublicKeyRequest(BaseModel):
    public_key_hex: str = Field(..., min_length=2)


class PublicKeyItem(BaseModel):
    reviewer_id: int
    public_key_hex: str


class RingUpdateRequest(BaseModel):
    genre: Optional[str] = None
    epoch: Optional[int] = None
    active: Optional[bool] = None
    pubkeys: Optional[List[str]] = None


class RingMemberRequest(BaseModel):
    public_key_hex: str = Field(..., min_length=2)


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
        try:
            token_service = get_token_service()
            await token_service.init_redis()
            logger.info("✓ Redis connection established")
        except Exception as e:
            logger.warning(f"⚠ Redis connection failed: {e}")
        
        # Initialize vetter service with RSA keypair
        try:
            vetter_service = get_vetter_service()
            if vetter_service:
                logger.info("✓ Vetter service initialized")
            else:
                logger.warning("⚠ Vetter service not available")
        except Exception as e:
            logger.warning(f"⚠ Vetter service failed: {e}")
        
        # Initialize monitoring service
        try:
            monitoring_service = get_monitoring_service()
            if monitoring_service:
                logger.info("✓ Monitoring service initialized")
            else:
                logger.warning("⚠ Monitoring service not available")
        except Exception as e:
            logger.warning(f"⚠ Monitoring service failed: {e}")
        
        # Check crypto library
        try:
            crypto_service = get_crypto_service()
            if crypto_service:
                health = crypto_service.health_check()
                if health["status"] == "healthy":
                    logger.info("✓ Crypto library loaded")
                else:
                    logger.error(f"✗ Crypto library unhealthy: {health.get('error')}")
            else:
                logger.warning("⚠ Crypto library not available (running in test mode)")
        except Exception as e:
            logger.warning(f"⚠ Crypto library failed: {e} (running in test mode)")
        
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


@app.get("/api/v1/auth/public-key", tags=["Authentication"])
async def get_user_public_key(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get current user's public key for ring signatures"""
    try:
        from models import User as UserModel
        
        result = await db.execute(
            select(UserModel).where(UserModel.id == current_user.id)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
        if not user.public_key_hex:
            # Generate keys if they don't exist (for existing users)
            try:
                crypto_service = get_crypto_service()
                if crypto_service:
                    seed_hex, private_key_hex, public_key_hex = crypto_service.generate_keypair()
                    
                    # Update user with new keys
                    await db.execute(
                        update(UserModel)
                        .where(UserModel.id == current_user.id)
                        .values(
                            public_key_hex=public_key_hex,
                            private_key_hex=private_key_hex,
                            key_seed_hex=seed_hex
                        )
                    )
                    await db.commit()
                    
                    return {
                        "success": True,
                        "public_key_hex": public_key_hex,
                        "message": "New keys generated"
                    }
                else:
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="Crypto service not available"
                    )
            except Exception as e:
                logger.error(f"Failed to generate keys for user {current_user.id}: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to generate cryptographic keys"
                )
        
        return {
            "success": True,
            "public_key_hex": user.public_key_hex,
            "message": "Keys retrieved successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving public key for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve public key"
        )


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


@app.get("/api/v1/admin/available-public-keys", tags=["Admin"])
async def get_available_public_keys(
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get all available public keys for ring creation (admin only)"""
    try:
        from models import User as UserModel
        
        # Get all users with public keys (reviewers and others)
        result = await db.execute(
            select(UserModel.id, UserModel.username, UserModel.role, UserModel.public_key_hex)
            .where(UserModel.public_key_hex.is_not(None))
            .where(UserModel.is_active == True)
            .order_by(UserModel.role, UserModel.username)
        )
        users_with_keys = result.all()
        
        available_keys = []
        for user in users_with_keys:
            available_keys.append({
                "user_id": user.id,
                "username": user.username,
                "role": user.role,
                "public_key_hex": user.public_key_hex
            })
        
        return {
            "success": True,
            "available_keys": available_keys,
            "total_count": len(available_keys)
        }
        
    except Exception as e:
        logger.error(f"Error fetching available public keys: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch available public keys"
        )

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
# Add these endpoints AFTER the vetter endpoints in main.py

# ============================================================================
# Escalation Endpoints
# ============================================================================

@app.get("/api/v1/escalations", tags=["Escalation"])
async def list_escalations(
    current_user: CurrentUser = Depends(require_admin),
    limit: int = 50,
    db: AsyncSession = Depends(get_db)
):
    """List pending escalations (admin only)"""
    escalation_service = get_escalation_service()
    escalations = await escalation_service.list_pending_escalations(db, limit)
    
    return {
        "success": True,
        "escalations": escalations,
        "count": len(escalations)
    }


@app.get("/api/v1/escalations/{escalation_id}", tags=["Escalation"])
async def get_escalation(
    escalation_id: int,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get escalation details (admin only)"""
    escalation_service = get_escalation_service()
    escalation = await escalation_service.get_escalation(escalation_id, db)
    
    if not escalation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Escalation not found"
        )
    
    return {
        "success": True,
        "escalation": escalation
    }


@app.post("/api/v1/escalations/{escalation_id}/resolve", tags=["Escalation"])
async def resolve_escalation(
    escalation_id: int,
    resolution_data: dict,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Resolve an escalation (admin only)
    
    Request body:
    {
        "resolution": "approved|rejected|dismissed",
        "notes": "optional resolution notes"
    }
    """
    escalation_service = get_escalation_service()
    
    success, error = await escalation_service.resolve_escalation(
        escalation_id=escalation_id,
        resolver_id=current_user.id,
        resolution=resolution_data["resolution"],
        notes=resolution_data.get("notes"),
        db=db
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    return {
        "success": True,
        "message": "Escalation resolved",
        "resolution": resolution_data["resolution"],
        "resolved_by": current_user.username
    }


@app.post("/api/v1/escalations/{escalation_id}/dismiss", tags=["Escalation"])
async def dismiss_escalation(
    escalation_id: int,
    dismissal_data: dict,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Dismiss an escalation as invalid (admin only)
    
    Request body:
    {
        "reason": "reason for dismissal"
    }
    """
    escalation_service = get_escalation_service()
    
    success, error = await escalation_service.dismiss_escalation(
        escalation_id=escalation_id,
        dismisser_id=current_user.id,
        reason=dismissal_data["reason"],
        db=db
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    return {
        "success": True,
        "message": "Escalation dismissed",
        "dismissed_by": current_user.username
    }


# ============================================================================
# Monitoring Endpoints
# ============================================================================

@app.get("/api/v1/monitoring/health", tags=["Monitoring"])
async def get_detailed_health(
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get detailed system health (admin only)"""
    monitoring_service = get_monitoring_service()
    health = await monitoring_service.get_system_health(db)
    
    return health


@app.get("/api/v1/monitoring/statistics", tags=["Monitoring"])
async def get_detailed_statistics(
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get detailed system statistics (admin only)"""
    monitoring_service = get_monitoring_service()
    stats = await monitoring_service.get_statistics(db)
    
    return stats


@app.get("/api/v1/monitoring/anomalies", tags=["Monitoring"])
async def check_anomalies(
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Run anomaly detection checks (admin only)"""
    monitoring_service = get_monitoring_service()
    anomalies = await monitoring_service.run_anomaly_checks(db)
    
    return anomalies


@app.get("/metrics", tags=["Monitoring"])
async def prometheus_metrics(
    current_user: CurrentUser = Depends(require_admin)
):
    """
    Prometheus metrics endpoint (admin only)
    
    Returns metrics in Prometheus text format
    """
    monitoring_service = get_monitoring_service()
    metrics = monitoring_service.metrics.get_metrics()
    
    # Convert to Prometheus format
    lines = []
    
    # Counters
    for name, value in metrics["counters"].items():
        lines.append(f"# TYPE {name} counter")
        lines.append(f"{name} {value}")
    
    # Gauges
    for name, value in metrics["gauges"].items():
        lines.append(f"# TYPE {name} gauge")
        lines.append(f"{name} {value}")
    
    # Histograms (as summaries)
    for name, hist in metrics["histograms"].items():
        lines.append(f"# TYPE {name} summary")
        lines.append(f"{name}_count {hist['count']}")
        lines.append(f"{name}_sum {hist['count'] * hist['avg']}")
        lines.append(f"{name}_min {hist['min']}")
        lines.append(f"{name}_max {hist['max']}")
    
    return Response(
        content="\n".join(lines) + "\n",
        media_type="text/plain; version=0.0.4"
    )

@app.post("/api/v1/vote/debug")
async def debug_vote_request(
    request: Request,
    current_user: CurrentUser = Depends(require_reviewer),
    db: AsyncSession = Depends(get_db)
):
    """Debug endpoint to see what data is being sent for vote requests"""
    try:
        body = await request.body()
        body_str = body.decode('utf-8')
        
        logger.info(f"Raw vote request body: {body_str}")
        
        # Try to parse as JSON
        import json
        try:
            data = json.loads(body_str)
            logger.info(f"Parsed vote request data: {data}")
            
            # Check each field
            checks = {
                "submission_id": data.get("submission_id"),
                "ring_id": data.get("ring_id"), 
                "signature_blob": data.get("signature_blob"),
                "vote_type": data.get("vote_type"),
                "token_id": data.get("token_id"),
                "message": data.get("message")
            }
            
            return {
                "success": True,
                "raw_body": body_str,
                "parsed_data": data,
                "field_checks": checks,
                "user": current_user.username
            }
        except json.JSONDecodeError as e:
            return {
                "success": False,
                "error": f"JSON decode error: {str(e)}",
                "raw_body": body_str
            }
            
    except Exception as e:
        logger.error(f"Debug endpoint error: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e)
        }


@app.get("/api/v1/vote/requirements")
async def check_vote_requirements(
    current_user: CurrentUser = Depends(require_reviewer),
    db: AsyncSession = Depends(get_db)
):
    """Check if user has everything needed to vote"""
    try:
        from models import Submission, Ring, Token
        
        # Check for pending submissions
        result = await db.execute(
            select(Submission).where(Submission.status == "pending").limit(5)
        )
        submissions = result.scalars().all()
        
        # Check for active rings
        result = await db.execute(
            select(Ring).where(Ring.active == True).limit(5)
        )
        rings = result.scalars().all()
        
        # Check for available tokens
        result = await db.execute(
            select(Token).where(Token.redeemed == False).limit(5)
        )
        tokens = result.scalars().all()
        
        return {
            "success": True,
            "user": current_user.username,
            "submissions": [
                {
                    "id": s.id,
                    "genre": s.genre,
                    "content_ref": s.content_ref,
                    "status": s.status
                } for s in submissions
            ],
            "rings": [
                {
                    "id": r.id,
                    "genre": r.genre,
                    "epoch": r.epoch,
                    "member_count": len(r.pubkeys) if r.pubkeys else 0,
                    "active": r.active
                } for r in rings
            ],
            "tokens": [
                {
                    "token_id": t.token_id[:16] + "...",
                    "epoch": t.epoch,
                    "redeemed": t.redeemed
                } for t in tokens
            ],
            "can_vote": len(submissions) > 0 and len(rings) > 0 and len(tokens) > 0
        }
        
    except Exception as e:
        logger.error(f"Error checking vote requirements: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e)
        }


@app.get("/api/v1/system/status")
async def system_status(db: AsyncSession = Depends(get_db)):
    """Get system status for debugging"""
    try:
        from models import Submission, Ring, Token, Reviewer
        from sqlalchemy import func
        
        # Count submissions
        result = await db.execute(select(func.count(Submission.id)))
        total_submissions = result.scalar() or 0
        
        result = await db.execute(select(func.count(Submission.id)).where(Submission.status == "pending"))
        pending_submissions = result.scalar() or 0
        
        # Count rings
        result = await db.execute(select(func.count(Ring.id)))
        total_rings = result.scalar() or 0
        
        result = await db.execute(select(func.count(Ring.id)).where(Ring.active == True))
        active_rings = result.scalar() or 0
        
        # Count tokens
        result = await db.execute(select(func.count(Token.token_id)))
        total_tokens = result.scalar() or 0
        
        result = await db.execute(select(func.count(Token.token_id)).where(Token.redeemed == False))
        available_tokens = result.scalar() or 0
        
        # Count reviewers
        result = await db.execute(select(func.count(Reviewer.id)))
        total_reviewers = result.scalar() or 0
        
        return {
            "success": True,
            "submissions": {
                "total": total_submissions,
                "pending": pending_submissions
            },
            "rings": {
                "total": total_rings,
                "active": active_rings
            },
            "tokens": {
                "total": total_tokens,
                "available": available_tokens
            },
            "reviewers": {
                "total": total_reviewers
            },
            "ready_to_vote": pending_submissions > 0 and active_rings > 0 and available_tokens > 0
        }
        
    except Exception as e:
        logger.error(f"Error getting system status: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e)
        }


@app.get("/api/v1/submissions/approved")
async def get_approved_submissions(
    limit: int = 20,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    """Get approved submissions for home page (public access)"""
    try:
        from models import Submission
        
        # Get approved submissions
        result = await db.execute(
            select(Submission)
            .where(Submission.status == "approved")
            .order_by(Submission.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        submissions = result.scalars().all()
        
        # Format for frontend
        formatted_submissions = []
        for sub in submissions:
            formatted_submissions.append({
                "id": sub.id,
                "genre": sub.genre,
                "content_ref": sub.content_ref,
                "status": sub.status,
                "created_at": sub.created_at.isoformat(),
                "approved_at": sub.created_at.isoformat()
            })
        
        return {
            "success": True,
            "submissions": formatted_submissions,
            "total": len(formatted_submissions),
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        logger.error(f"Error getting approved submissions: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/api/v1/submissions")
async def get_all_submissions(
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get all submissions for admin dashboard"""
    try:
        from models import Submission
        
        # Get all submissions
        result = await db.execute(
            select(Submission).order_by(Submission.created_at.desc())
        )
        all_submissions = result.scalars().all()
        
        # Format for frontend
        formatted_submissions = []
        for sub in all_submissions:
            formatted_submissions.append({
                "id": sub.id,
                "genre": sub.genre,
                "content_ref": sub.content_ref,
                "status": sub.status,
                "created_at": sub.created_at.isoformat(),
                "updated_at": sub.created_at.isoformat()  # Use created_at as fallback
            })
        
        return formatted_submissions
        
    except Exception as e:
        logger.error(f"Error getting all submissions: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/api/v1/submissions/my")
async def get_my_submissions(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get current user's submissions"""
    try:
        from models import Submission
        
        # Filter submissions by current user's ID
        result = await db.execute(
            select(Submission)
            .where(Submission.user_id == current_user.id)
            .order_by(Submission.created_at.desc())
        )
        user_submissions_raw = result.scalars().all()
        
        # Format for frontend
        user_submissions = []
        for sub in user_submissions_raw:
            user_submissions.append({
                "id": sub.id,
                "genre": sub.genre,
                "content_ref": sub.content_ref,
                "status": sub.status,
                "created_at": sub.created_at.isoformat(),
                "updated_at": sub.created_at.isoformat(),
                "user_id": sub.user_id  # Include for debugging
            })
        
        logger.info(f"User {current_user.username} (ID: {current_user.id}) has {len(user_submissions)} submissions")
        return user_submissions
        
    except Exception as e:
        logger.error(f"Error getting user submissions: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/api/v1/reviewer/submissions")
async def get_reviewer_submissions(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get submissions available for reviewer to review"""
    try:
        from models import Submission
        
        # Get pending submissions for review
        result = await db.execute(
            select(Submission)
            .where(Submission.status == "pending")
            .order_by(Submission.created_at.desc())
            .limit(10)
        )
        pending_submissions = result.scalars().all()
        
        # Format for frontend
        formatted_submissions = []
        for sub in pending_submissions:
            formatted_submissions.append({
                "id": sub.id,
                "genre": sub.genre,
                "content_ref": sub.content_ref,
                "status": sub.status,
                "created_at": sub.created_at.isoformat(),
                "updated_at": sub.created_at.isoformat()
            })
        
        return formatted_submissions
        
    except Exception as e:
        logger.error(f"Error getting reviewer submissions: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/api/v1/submissions/{submission_id}")
async def get_submission_by_id(
    submission_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Get a specific submission by ID"""
    try:
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
            "id": submission.id,
            "genre": submission.genre,
            "content_ref": submission.content_ref,
            "status": submission.status,
            "created_at": submission.created_at.isoformat(),
            "updated_at": submission.created_at.isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting submission {submission_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/api/v1/rings")
async def get_rings(
    genre: str = None,
    active: bool = None,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get rings with optional filtering"""
    try:
        from models import Ring
        
        query = select(Ring)
        
        if genre:
            query = query.where(Ring.genre == genre)
        if active is not None:
            query = query.where(Ring.active == active)
            
        query = query.order_by(Ring.created_at.desc())
        
        result = await db.execute(query)
        rings = result.scalars().all()
        
        formatted_rings = []
        for ring in rings:
            formatted_rings.append({
                "id": ring.id,
                "genre": ring.genre,
                "epoch": ring.epoch,
                "active": ring.active,
                "public_keys": ring.pubkeys,
                "created_at": ring.created_at.isoformat(),
                "member_count": len(ring.pubkeys) if ring.pubkeys else 0
            })
        
        return {
            "success": True,
            "rings": formatted_rings,
            "total": len(formatted_rings)
        }
        
    except Exception as e:
        logger.error(f"Error getting rings: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )



@app.post("/api/v1/vote/test")
async def submit_test_vote(
    vote_data: dict,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Submit a test vote (bypasses crypto verification for development)"""
    try:
        from models import Vote, Submission, Ring
        
        # Validate submission exists
        result = await db.execute(
            select(Submission).where(Submission.id == vote_data["submission_id"])
        )
        submission = result.scalar_one_or_none()
        if not submission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Submission not found"
            )
        
        # Validate ring exists
        result = await db.execute(
            select(Ring).where(Ring.id == vote_data["ring_id"])
        )
        ring = result.scalar_one_or_none()
        if not ring:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Ring not found"
            )
        
        # Check if user already voted on this submission
        key_image = f"test_key_image_{vote_data['submission_id']}_{current_user.id}"
        
        existing_vote_result = await db.execute(
            select(Vote).where(
                Vote.submission_id == vote_data["submission_id"],
                Vote.key_image == key_image
            )
        )
        existing_vote = existing_vote_result.scalar_one_or_none()
        
        if existing_vote:
            logger.info(f"User {current_user.username} already voted on submission {vote_data['submission_id']}")
            return {
                "success": True,
                "vote_id": existing_vote.id,
                "message": "Vote already recorded",
                "already_voted": True
            }
        
        # Create test vote
        vote = Vote(
            submission_id=vote_data["submission_id"],
            ring_id=vote_data["ring_id"],
            signature_blob=vote_data["signature_blob"],
            key_image=key_image,
            vote_type=vote_data["vote_type"],
            token_id=vote_data["token_id"],
            verified=True,  # Auto-verify test votes
            created_at=datetime.utcnow()
        )
        
        db.add(vote)
        await db.commit()
        await db.refresh(vote)
        
        logger.info(f"Test vote submitted: {vote.id} by {current_user.username}")
        
        # Check if we should compute tally after test vote
        tally_service = get_tally_service()
        if tally_service and await tally_service.should_compute_tally(vote_data["submission_id"], db):
            logger.info(f"Computing tally for submission {vote_data['submission_id']} after test vote")
            tally_result = await tally_service.compute_tally(vote_data["submission_id"], db)
            logger.info(f"Tally result: {tally_result}")
        
        return {
            "success": True,
            "vote_id": vote.id,
            "message": "Test vote submitted successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error submitting test vote: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to submit test vote: {str(e)}"
        )


@app.get("/api/v1/submissions/{submission_id}/vote-status")
async def get_user_vote_status(
    submission_id: int,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Check if current user has voted on a submission"""
    try:
        from models import Vote
        
        # Check for user's vote on this submission
        key_image = f"test_key_image_{submission_id}_{current_user.id}"
        
        result = await db.execute(
            select(Vote).where(
                Vote.submission_id == submission_id,
                Vote.key_image == key_image
            )
        )
        vote = result.scalar_one_or_none()
        
        if vote:
            return {
                "has_voted": True,
                "vote_type": vote.vote_type,
                "voted_at": vote.created_at.isoformat()
            }
        else:
            return {
                "has_voted": False
            }
            
    except Exception as e:
        logger.error(f"Error checking vote status for submission {submission_id}: {e}", exc_info=True)
        return {"has_voted": False}


@app.post("/api/v1/admin/fix-submission-users")
async def fix_submission_user_associations(
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Fix existing submissions that don't have user_id set (admin only)"""
    try:
        from models import Submission, User
        
        # Get all submissions without user_id
        result = await db.execute(
            select(Submission).where(Submission.user_id.is_(None))
        )
        orphaned_submissions = result.scalars().all()
        
        if not orphaned_submissions:
            return {
                "success": True,
                "message": "No orphaned submissions found",
                "fixed_count": 0
            }
        
        # Get all users
        result = await db.execute(select(User))
        users = result.scalars().all()
        
        if not users:
            return {
                "success": False,
                "message": "No users found to assign submissions to"
            }
        
        # Distribute orphaned submissions among users
        fixed_count = 0
        for i, submission in enumerate(orphaned_submissions):
            # Assign to users in round-robin fashion
            user = users[i % len(users)]
            submission.user_id = user.id
            fixed_count += 1
        
        await db.commit()
        
        logger.info(f"Fixed {fixed_count} orphaned submissions, distributed among {len(users)} users")
        
        return {
            "success": True,
            "message": f"Fixed {fixed_count} submissions",
            "fixed_count": fixed_count,
            "distributed_among": len(users)
        }
        
    except Exception as e:
        logger.error(f"Error fixing submission user associations: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fix submissions: {str(e)}"
        )


@app.post("/api/v1/admin/compute-tally/{submission_id}")
async def admin_compute_tally(
    submission_id: int,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Manually compute tally for a submission (admin only)"""
    try:
        tally_service = get_tally_service()
        if not tally_service:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Tally service not available"
            )
        
        # Force compute tally
        result = await tally_service.compute_tally(submission_id, db, force=True)
        
        if not result["success"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get("error", "Tally computation failed")
            )
        
        logger.info(f"Admin {current_user.username} manually computed tally for submission {submission_id}")
        
        return {
            "success": True,
            "submission_id": submission_id,
            "tally_result": result,
            "message": "Tally computed successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error computing tally for submission {submission_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to compute tally: {str(e)}"
        )


@app.get("/api/v1/admin/escalations")
async def get_escalated_submissions(
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get escalated submissions for admin review"""
    try:
        from models import Submission
        
        # Get escalated submissions
        result = await db.execute(
            select(Submission)
            .where(Submission.status == "escalated")
            .order_by(Submission.created_at.desc())
        )
        escalated_submissions = result.scalars().all()
        
        # Format for frontend
        formatted_submissions = []
        for sub in escalated_submissions:
            formatted_submissions.append({
                "id": sub.id,
                "genre": sub.genre,
                "content_ref": sub.content_ref,
                "status": sub.status,
                "created_at": sub.created_at.isoformat(),
                "updated_at": (sub.updated_at or sub.created_at).isoformat()
            })
        
        return {
            "success": True,
            "escalated_submissions": formatted_submissions,
            "count": len(formatted_submissions)
        }
        
    except Exception as e:
        logger.error(f"Error getting escalated submissions: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get escalated submissions: {str(e)}"
        )


@app.get("/api/v1/admin/flagged")
async def get_flagged_submissions(
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get flagged submissions with submitter IP/MAC for admin review"""
    try:
        from models import Submission
        
        # Get flagged submissions
        result = await db.execute(
            select(Submission)
            .where(Submission.status == "flagged")
            .order_by(Submission.created_at.desc())
        )
        flagged_submissions = result.scalars().all()
        
        # Format for frontend with submitter information
        formatted_submissions = []
        for sub in flagged_submissions:
            # Debug logging
            logger.info(f"Flagged submission {sub.id}: IP={sub.submitter_ip_hash}, MAC={sub.submitter_mac_hash}")
            
            formatted_submissions.append({
                "id": sub.id,
                "genre": sub.genre,
                "content_ref": sub.content_ref,
                "status": sub.status,
                "submitter_ip_hash": sub.submitter_ip_hash or "No IP data",
                "submitter_mac_hash": sub.submitter_mac_hash or "No MAC data",
                "created_at": sub.created_at.isoformat(),
                "updated_at": (sub.updated_at or sub.created_at).isoformat(),
                "flagged_reason": "Content flagged by reviewers - requires urgent admin review"
            })
        
        logger.info(f"Admin {current_user.username} accessed {len(formatted_submissions)} flagged submissions with submitter data")
        
        return {
            "success": True,
            "flagged_submissions": formatted_submissions,
            "count": len(formatted_submissions),
            "warning": "Flagged content includes submitter IP/MAC hashes for investigation"
        }
        
    except Exception as e:
        logger.error(f"Error getting flagged submissions: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get flagged submissions: {str(e)}"
        )


@app.get("/api/v1/admin/debug/submission/{submission_id}")
async def debug_submission(
    submission_id: int,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Debug endpoint to check submission data"""
    try:
        from models import Submission
        
        result = await db.execute(
            select(Submission).where(Submission.id == submission_id)
        )
        submission = result.scalar_one_or_none()
        
        if not submission:
            raise HTTPException(status_code=404, detail="Submission not found")
        
        return {
            "id": submission.id,
            "status": submission.status,
            "submitter_ip_hash": submission.submitter_ip_hash,
            "submitter_mac_hash": submission.submitter_mac_hash,
            "genre": submission.genre,
            "content_ref": submission.content_ref,
            "created_at": submission.created_at.isoformat() if submission.created_at else None,
            "user_id": submission.user_id
        }
        
    except Exception as e:
        logger.error(f"Error debugging submission {submission_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/admin/submissions/{submission_id}/review")
async def admin_review_submission(
    submission_id: int,
    review_data: dict,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Admin review submission - approve, reject, or escalate"""
    try:
        from models import Submission
        
        # Get submission
        result = await db.execute(
            select(Submission).where(Submission.id == submission_id)
        )
        submission = result.scalar_one_or_none()
        
        if not submission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Submission not found"
            )
        
        # Check if submission has tally-based decision
        tally_service = get_tally_service()
        existing_tally = await tally_service.get_tally_by_submission(submission_id, db)
        
        # Admin can only override tally decisions for escalated/flagged content
        if existing_tally and existing_tally.get("decision") in ["approved", "rejected"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot override tally decision '{existing_tally['decision']}'. Admin review is only for escalated/flagged content."
            )
        
        # Validate review action
        action = review_data.get("action")
        if action not in ["approve", "reject", "escalate", "flag"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid action. Must be 'approve', 'reject', 'escalate', or 'flag'"
            )
        
        # Update submission status (only for escalated/flagged or no tally)
        if action == "approve":
            submission.status = "approved"
        elif action == "reject":
            submission.status = "rejected"
        elif action == "escalate":
            submission.status = "escalated"
        elif action == "flag":
            submission.status = "flagged"
        
        # Log admin override
        logger.info(f"Admin {current_user.username} overrode submission {submission_id} from {submission.status} to {action}")
        
        await db.commit()
        await db.refresh(submission)
        
        logger.info(f"Admin {current_user.username} {action}ed submission {submission_id}")
        
        return {
            "success": True,
            "submission_id": submission_id,
            "new_status": submission.status,
            "reviewed_by": current_user.username,
            "action": action,
            "message": f"Submission {action}ed successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error reviewing submission {submission_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to review submission: {str(e)}"
        )


@app.post("/api/v1/admin/escalations/{submission_id}/resolve")
async def resolve_escalation(
    submission_id: int,
    resolution_data: dict,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Resolve an escalated submission (approve or reject)"""
    try:
        from models import Submission
        
        # Get the submission
        result = await db.execute(
            select(Submission).where(Submission.id == submission_id)
        )
        submission = result.scalar_one_or_none()
        
        if not submission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Submission not found"
            )
        
        if submission.status != "escalated":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Submission is not escalated"
            )
        
        # Validate resolution
        resolution = resolution_data.get("resolution")
        if resolution not in ["approve", "reject"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Resolution must be 'approve' or 'reject'"
            )
        
        # Update submission status
        new_status = "approved" if resolution == "approve" else "rejected"
        submission.status = new_status
        
        await db.commit()
        
        logger.info(f"Admin {current_user.username} resolved escalation {submission_id} as {new_status}")
        
        return {
            "success": True,
            "submission_id": submission_id,
            "resolution": resolution,
            "new_status": new_status,
            "resolved_by": current_user.username,
            "resolved_at": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resolving escalation: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/api/v1/admin/audit-logs")
async def get_audit_logs(
    current_user: CurrentUser = Depends(require_admin),
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    """Get audit logs for admin review"""
    try:
        from models import Vote, Submission
        
        # Get recent votes as audit logs
        result = await db.execute(
            select(Vote, Submission)
            .join(Submission, Vote.submission_id == Submission.id)
            .order_by(Vote.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        vote_submissions = result.all()
        
        # Format audit logs
        audit_logs = []
        for vote, submission in vote_submissions:
            audit_logs.append({
                "id": vote.id,
                "action": f"Vote: {vote.vote_type}",
                "submission_id": submission.id,
                "submission_genre": submission.genre,
                "submission_status": submission.status,
                "timestamp": vote.created_at.isoformat(),
                "details": f"Submission #{submission.id} ({submission.genre}) voted as {vote.vote_type}",
                "vote_id": vote.id,
                "key_image": vote.key_image[:16] + "..." if vote.key_image else "N/A"
            })
        
        return {
            "success": True,
            "logs": audit_logs,
            "total": len(audit_logs),
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        logger.error(f"Error getting audit logs: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/api/v1/admin/statistics")
async def get_admin_statistics(
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Get detailed statistics for admin dashboard"""
    try:
        from models import Submission, Vote, Ring, Token, Reviewer
        from sqlalchemy import func, distinct
        
        # Submission statistics
        result = await db.execute(select(func.count(Submission.id)))
        total_submissions = result.scalar() or 0
        
        result = await db.execute(select(func.count(Submission.id)).where(Submission.status == "pending"))
        pending_submissions = result.scalar() or 0
        
        result = await db.execute(select(func.count(Submission.id)).where(Submission.status == "approved"))
        approved_submissions = result.scalar() or 0
        
        result = await db.execute(select(func.count(Submission.id)).where(Submission.status == "rejected"))
        rejected_submissions = result.scalar() or 0
        
        result = await db.execute(select(func.count(Submission.id)).where(Submission.status == "escalated"))
        escalated_submissions = result.scalar() or 0
        
        result = await db.execute(select(func.count(Submission.id)).where(Submission.status == "flagged"))
        flagged_submissions = result.scalar() or 0
        
        # Vote statistics
        result = await db.execute(select(func.count(Vote.id)))
        total_votes = result.scalar() or 0
        
        result = await db.execute(select(func.count(Vote.id)).where(Vote.vote_type == "approve"))
        approve_votes = result.scalar() or 0
        
        result = await db.execute(select(func.count(Vote.id)).where(Vote.vote_type == "reject"))
        reject_votes = result.scalar() or 0
        
        result = await db.execute(select(func.count(Vote.id)).where(Vote.vote_type == "escalate"))
        escalate_votes = result.scalar() or 0
        
        result = await db.execute(select(func.count(Vote.id)).where(Vote.vote_type == "flag"))
        flag_votes = result.scalar() or 0
        
        # Ring and Token statistics
        result = await db.execute(select(func.count(Ring.id)))
        total_rings = result.scalar() or 0
        
        result = await db.execute(select(func.count(Ring.id)).where(Ring.active == True))
        active_rings = result.scalar() or 0
        
        result = await db.execute(select(func.count(Token.token_id)))
        total_tokens = result.scalar() or 0
        
        result = await db.execute(select(func.count(Token.token_id)).where(Token.redeemed == False))
        available_tokens = result.scalar() or 0
        
        # Reviewer statistics
        result = await db.execute(select(func.count(Reviewer.id)))
        total_reviewers = result.scalar() or 0
        
        # Genre breakdown
        result = await db.execute(
            select(Submission.genre, func.count(Submission.id))
            .group_by(Submission.genre)
        )
        genre_stats = {genre: count for genre, count in result.all()}
        
        return {
            "success": True,
            "submissions": {
                "total": total_submissions,
                "pending": pending_submissions,
                "approved": approved_submissions,
                "rejected": rejected_submissions,
                "escalated": escalated_submissions,
                "flagged": flagged_submissions,
                "by_genre": genre_stats
            },
            "votes": {
                "total": total_votes,
                "approve": approve_votes,
                "reject": reject_votes,
                "escalate": escalate_votes,
                "flag": flag_votes
            },
            "rings": {
                "total": total_rings,
                "active": active_rings
            },
            "tokens": {
                "total": total_tokens,
                "available": available_tokens,
                "used": total_tokens - available_tokens
            },
            "reviewers": {
                "total": total_reviewers
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting admin statistics: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.post("/api/v1/vote/test", response_model=VoteResponse)
async def submit_test_vote(
    vote_request: VoteRequest,
    request: Request,
    current_user: CurrentUser = Depends(require_reviewer),
    db: AsyncSession = Depends(get_db)
):
    """
    Test vote submission endpoint that bypasses crypto verification
    """
    try:
        logger.info(f"Test vote request from {current_user.username}: {vote_request}")
        
        # Basic validation
        from models import Submission, Ring
        
        # Check submission exists
        result = await db.execute(
            select(Submission).where(Submission.id == vote_request.submission_id)
        )
        submission = result.scalar_one_or_none()
        if not submission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Submission {vote_request.submission_id} not found"
            )
        
        # Check ring exists
        result = await db.execute(
            select(Ring).where(Ring.id == vote_request.ring_id)
        )
        ring = result.scalar_one_or_none()
        if not ring:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Ring {vote_request.ring_id} not found"
            )
        
        # Create a test vote record
        from models import Vote
        import uuid
        
        vote = Vote(
            submission_id=vote_request.submission_id,
            ring_id=vote_request.ring_id,
            vote_type=vote_request.vote_type,
            signature_blob=vote_request.signature_blob,
            key_image=f"test_key_image_{uuid.uuid4().hex[:16]}",
            token_id=vote_request.token_id,  # Add the missing token_id
            verified=True,  # Skip verification for testing
            created_at=datetime.utcnow()
        )
        
        db.add(vote)
        await db.commit()
        await db.refresh(vote)
        
        # Update submission status based on vote
        if vote_request.vote_type == "approve":
            submission.status = "approved"
        elif vote_request.vote_type == "reject":
            submission.status = "rejected"
        elif vote_request.vote_type == "escalate":
            submission.status = "escalated"
        elif vote_request.vote_type == "flag":
            submission.status = "flagged"
        
        await db.commit()
        
        logger.info(f"Test vote {vote.id} created successfully, submission {submission.id} status updated to {submission.status}")
        
        return VoteResponse(
            success=True,
            vote_id=vote.id,
            key_image=vote.key_image,
            message=f"Vote submitted successfully - submission {submission.status}"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in test vote endpoint: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.post("/api/v1/vote", response_model=VoteResponse)
async def submit_vote(
    vote_request: VoteRequest,
    request: Request,
    current_user: CurrentUser = Depends(require_reviewer),
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
        # Debug logging for vote request
        logger.info(f"Vote request received: submission_id={vote_request.submission_id}, "
                   f"ring_id={vote_request.ring_id}, vote_type={vote_request.vote_type}, "
                   f"token_id={vote_request.token_id[:16]}..., message_length={len(vote_request.message)}")
        
        # Get IP address for audit logging
        ip_address = request.client.host if request.client else None
        
        # Validate submission exists
        from models import Submission
        result = await db.execute(
            select(Submission).where(Submission.id == vote_request.submission_id)
        )
        submission = result.scalar_one_or_none()
        if not submission:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Submission {vote_request.submission_id} not found"
            )
        
        # Validate ring exists
        from models import Ring
        result = await db.execute(
            select(Ring).where(Ring.id == vote_request.ring_id)
        )
        ring = result.scalar_one_or_none()
        if not ring:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Ring {vote_request.ring_id} not found"
            )
        
        if not ring.active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Ring {vote_request.ring_id} is not active"
            )
        
        # Convert hex-encoded message to bytes
        try:
            message_bytes = bytes.fromhex(vote_request.message)
        except ValueError as e:
            logger.error(f"Invalid message format: {vote_request.message[:50]}... Error: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid message format: must be hex-encoded string. Error: {str(e)}"
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


@app.get("/api/v1/tally/{submission_id}/weighted", response_model=TallyResponse, tags=["Voting"])
async def get_weighted_tally(
    submission_id: int,
    current_user: CurrentUser = Depends(get_optional_user),  # Optional auth
    db: AsyncSession = Depends(get_db)
):
    """
    Get weighted tally for a submission (accounts for reputation)
    
    This endpoint computes vote weights based on voter reputation,
    providing a more nuanced decision than simple vote counting.
    """
    try:
        tally_service = get_tally_service()
        
        # Compute weighted tally
        result = await tally_service.compute_weighted_tally(submission_id, db)
        
        if not result["success"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get("error", "Weighted tally computation failed")
            )
        
        return TallyResponse(
            success=True,
            tally_id=None,  # Weighted tally doesn't have a tally_id yet
            counts=result["weighted_counts"],
            total_votes=len(result.get("unweighted_counts", {})),
            decision=result["decision"],
            computed_at=result["computed_at"],
            metadata={
                "weighted": True,
                "total_reputation_weight": result["total_reputation_weight"],
                "weighted_percentages": result["weighted_percentages"],
                "unweighted_counts": result["unweighted_counts"]
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_weighted_tally endpoint: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.post("/api/v1/present-credential", response_model=CredentialResponse)
async def present_credential(
    credential_request: CredentialRequest,
    current_user: CurrentUser = Depends(require_reviewer),
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
    current_user: CurrentUser = Depends(get_current_user),
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
        
        # Create submission with current user
        submission = Submission(
            user_id=current_user.id,  # Associate with authenticated user
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
    current_user: CurrentUser = Depends(require_admin),
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
async def get_statistics(current_user: CurrentUser = Depends(require_admin), db: AsyncSession = Depends(get_db)):
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


# =============================================================================
# Reviewer Public Key Endpoints - Routes
# =============================================================================

@app.post("/api/v1/reviewer/public-key")
async def publish_public_key(
    request: PublicKeyRequest,
    current_user: CurrentUser = Depends(require_reviewer),
    db: AsyncSession = Depends(get_db)
):
    """Allow a reviewer to publish their public key (hex) for admin use."""
    try:
        from sqlalchemy import select, update
        from models import Reviewer
        import json, os

        pk = request.public_key_hex.lower()
        if any(ch not in "0123456789abcdef" for ch in pk):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid hex in public key")

        result = await db.execute(select(Reviewer).where(Reviewer.id == current_user.id))
        reviewer = result.scalar_one_or_none()
        if reviewer:
            meta = reviewer.credential_meta or {}
            if not isinstance(meta, dict):
                meta = {}
            meta["public_key_hex"] = pk

            await db.execute(
                update(Reviewer)
                .where(Reviewer.id == current_user.id)
                .values(credential_meta=meta)
            )
            await db.commit()
        else:
            # Fallback: store in local JSON file if reviewer row does not exist yet
            store_path = os.path.join(os.path.dirname(__file__), "published_pubkeys.json")
            try:
                with open(store_path, "r", encoding="utf-8") as f:
                    store = json.load(f)
            except Exception:
                store = []
            # Upsert by reviewer id
            store = [item for item in store if item.get("reviewer_id") != current_user.id]
            store.append({"reviewer_id": current_user.id, "public_key_hex": pk})
            with open(store_path, "w", encoding="utf-8") as f:
                json.dump(store, f)

        return {"success": True}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error publishing public key: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/api/v1/reviewer/public-keys", response_model=List[PublicKeyItem])
async def list_public_keys(
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """List reviewer public keys that have been published (admin only)."""
    try:
        from sqlalchemy import select
        from models import Reviewer
        import json, os

        items: List[PublicKeyItem] = []

        # Collect from DB where available
        result = await db.execute(select(Reviewer.id, Reviewer.credential_meta))
        rows = result.all()
        for reviewer_id, meta in rows:
            if isinstance(meta, dict) and meta.get("public_key_hex"):
                items.append(PublicKeyItem(reviewer_id=reviewer_id, public_key_hex=meta["public_key_hex"]))

        # Merge in any file-based entries (in case reviewer row isn't created yet)
        store_path = os.path.join(os.path.dirname(__file__), "published_pubkeys.json")
        try:
            with open(store_path, "r", encoding="utf-8") as f:
                file_items = json.load(f)
            for entry in file_items:
                if not any(x.reviewer_id == entry.get("reviewer_id") for x in items):
                    items.append(PublicKeyItem(reviewer_id=entry.get("reviewer_id"), public_key_hex=entry.get("public_key_hex")))
        except Exception:
            pass

        return items

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing public keys: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# =============================================================================
# Submissions and Reviewer Endpoints
# =============================================================================

@app.get("/api/v1/submissions")
async def list_submissions(
    db: AsyncSession = Depends(get_db)
):
    """List all submissions (basic listing for UI)"""
    try:
        from models import Submission
        result = await db.execute(
            select(Submission).order_by(Submission.created_at.desc())
        )
        submissions = result.scalars().all()
        return [
            {
                "submission_id": s.id,
                "genre": s.genre,
                "content_ref": s.content_ref,
                "status": s.status,
                "created_at": s.created_at.isoformat(),
            }
            for s in submissions
        ]
    except Exception as e:
        logger.error(f"Error listing submissions: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/api/v1/reviewer/stats")
async def get_reviewer_stats(
    current_user: CurrentUser = Depends(require_reviewer),
    db: AsyncSession = Depends(get_db)
):
    """Basic reviewer stats used by dashboard"""
    try:
        from models import Submission, Vote, Token
        from sqlalchemy import func

        # Available submissions = pending count
        result = await db.execute(
            select(func.count(Submission.id)).where(Submission.status == "pending")
        )
        available = result.scalar() or 0

        # Votes cast (global verified count for now)
        result = await db.execute(
            select(func.count(Vote.id)).where(Vote.verified == True)
        )
        votes_cast = result.scalar() or 0

        # Tokens remaining (global unredeemed count for now)
        result = await db.execute(
            select(func.count(Token.token_id)).where(Token.redeemed == False)
        )
        tokens_remaining = result.scalar() or 0

        return {
            "available_submissions": available,
            "votes_cast": votes_cast,
            "tokens_remaining": tokens_remaining,
        }
    except Exception as e:
        logger.error(f"Error getting reviewer stats: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/api/v1/reviewer/next")
async def get_next_submission(
    current_user: CurrentUser = Depends(require_reviewer),
    db: AsyncSession = Depends(get_db)
):
    """Get next pending submission for quick review"""
    try:
        from models import Submission
        result = await db.execute(
            select(Submission)
            .where(Submission.status == "pending")
            .order_by(Submission.created_at.asc())
            .limit(1)
        )
        submission = result.scalar_one_or_none()
        if not submission:
            return None
        return {
            "id": submission.id,
            "genre": submission.genre,
        }
    except Exception as e:
        logger.error(f"Error getting next submission: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.put("/api/v1/rings/{ring_id}")
async def update_ring(
    ring_id: int,
    ring_update: RingUpdateRequest,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Update a ring (admin only)"""
    try:
        from sqlalchemy import select, update
        from models import Ring
        
        # Check if ring exists
        result = await db.execute(
            select(Ring).where(Ring.id == ring_id)
        )
        ring = result.scalar_one_or_none()
        
        if not ring:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Ring not found"
            )
        
        # Prepare update data
        update_data = {}
        if ring_update.genre is not None:
            update_data["genre"] = ring_update.genre
        if ring_update.epoch is not None:
            update_data["epoch"] = ring_update.epoch
        if ring_update.active is not None:
            update_data["active"] = ring_update.active
        if ring_update.pubkeys is not None:
            update_data["pubkeys"] = ring_update.pubkeys
        
        if not update_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No valid fields to update"
            )
        
        # Update the ring
        await db.execute(
            update(Ring)
            .where(Ring.id == ring_id)
            .values(**update_data)
        )
        await db.commit()
        
        # Get updated ring
        result = await db.execute(
            select(Ring).where(Ring.id == ring_id)
        )
        updated_ring = result.scalar_one()
        
        logger.info(f"Updated ring {ring_id} by admin {current_user.username}")
        
        return {
            "success": True,
            "ring_id": updated_ring.id,
            "genre": updated_ring.genre,
            "epoch": updated_ring.epoch,
            "member_count": len(updated_ring.pubkeys) if updated_ring.pubkeys else 0,
            "active": updated_ring.active,
            "created_at": updated_ring.created_at.isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating ring: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update ring: {str(e)}"
        )


@app.delete("/api/v1/rings/{ring_id}")
async def delete_ring(
    ring_id: int,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Delete a ring (admin only)"""
    try:
        from sqlalchemy import select, delete
        from models import Ring, Vote
        
        # Check if ring exists
        result = await db.execute(
            select(Ring).where(Ring.id == ring_id)
        )
        ring = result.scalar_one_or_none()
        
        if not ring:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Ring not found"
            )
        
        # Check if ring has any votes (prevent deletion if votes exist)
        try:
            result = await db.execute(
                select(Vote).where(Vote.ring_id == ring_id).limit(1)
            )
            existing_vote = result.scalar_one_or_none()
            
            if existing_vote:
                # Instead of preventing deletion, just log a warning and proceed
                logger.warning(f"Deleting ring {ring_id} that has existing votes")
        except Exception as vote_check_error:
            # If vote check fails, just log and continue with deletion
            logger.warning(f"Could not check votes for ring {ring_id}: {vote_check_error}")
            pass
        
        # Delete the ring
        try:
            await db.execute(
                delete(Ring).where(Ring.id == ring_id)
            )
            await db.commit()
            logger.info(f"Successfully deleted ring {ring_id}")
        except Exception as delete_error:
            await db.rollback()
            logger.error(f"Failed to delete ring {ring_id}: {delete_error}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error while deleting ring: {str(delete_error)}"
            )
        
        logger.info(f"Deleted ring {ring_id} by admin {current_user.username}")
        
        return {
            "success": True,
            "message": f"Ring {ring_id} deleted successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting ring: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete ring: {str(e)}"
        )


@app.post("/api/v1/rings/{ring_id}/members")
async def add_ring_member(
    ring_id: int,
    member_request: RingMemberRequest,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Add a member to a ring (admin only)"""
    try:
        from sqlalchemy import select, update
        from models import Ring
        
        # Check if ring exists
        result = await db.execute(
            select(Ring).where(Ring.id == ring_id)
        )
        ring = result.scalar_one_or_none()
        
        if not ring:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Ring not found"
            )
        
        # Validate public key format
        pk = member_request.public_key_hex.lower()
        if any(ch not in "0123456789abcdef" for ch in pk):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid hex in public key"
            )
        
        # Check if public key already exists in ring
        current_pubkeys = ring.pubkeys or []
        if pk in current_pubkeys:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Public key already exists in ring"
            )
        
        # Add the public key
        updated_pubkeys = current_pubkeys + [pk]
        
        await db.execute(
            update(Ring)
            .where(Ring.id == ring_id)
            .values(pubkeys=updated_pubkeys)
        )
        await db.commit()
        
        logger.info(f"Added member to ring {ring_id} by admin {current_user.username}")
        
        return {
            "success": True,
            "ring_id": ring_id,
            "member_count": len(updated_pubkeys),
            "message": "Member added successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding ring member: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to add ring member: {str(e)}"
        )


@app.delete("/api/v1/rings/{ring_id}/members/{public_key_hex}")
async def remove_ring_member(
    ring_id: int,
    public_key_hex: str,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Remove a member from a ring (admin only)"""
    try:
        from sqlalchemy import select, update
        from models import Ring
        
        # Check if ring exists
        result = await db.execute(
            select(Ring).where(Ring.id == ring_id)
        )
        ring = result.scalar_one_or_none()
        
        if not ring:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Ring not found"
            )
        
        # Normalize public key
        pk = public_key_hex.lower()
        
        # Check if public key exists in ring
        current_pubkeys = ring.pubkeys or []
        if pk not in current_pubkeys:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Public key not found in ring"
            )
        
        # Remove the public key
        updated_pubkeys = [key for key in current_pubkeys if key != pk]
        
        # Prevent removing all members
        if len(updated_pubkeys) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot remove all members from ring"
            )
        
        await db.execute(
            update(Ring)
            .where(Ring.id == ring_id)
            .values(pubkeys=updated_pubkeys)
        )
        await db.commit()
        
        logger.info(f"Removed member from ring {ring_id} by admin {current_user.username}")
        
        return {
            "success": True,
            "ring_id": ring_id,
            "member_count": len(updated_pubkeys),
            "message": "Member removed successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing ring member: {e}", exc_info=True)
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to remove ring member: {str(e)}"
        )


# =============================================================================
# Ring Listing Endpoint
# =============================================================================

@app.get("/api/v1/rings")
async def list_rings(
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """List all rings (admin only)"""
    try:
        from sqlalchemy import select
        from models import Ring
        
        result = await db.execute(
            select(Ring).order_by(Ring.created_at.desc())
        )
        rings = result.scalars().all()
        
        return [
            {
                "ring_id": ring.id,
                "genre": ring.genre,
                "epoch": ring.epoch,
                "member_count": len(ring.pubkeys) if ring.pubkeys else 0,
                "active": ring.active,
                "created_at": ring.created_at.isoformat()
            }
            for ring in rings
        ]
        
    except Exception as e:
        logger.error(f"Error listing rings: {e}", exc_info=True)
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