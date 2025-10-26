# """
# ProofPals Backend - FastAPI Application
# Crypto-enabled anonymous voting and review system
# """

# from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
# from fastapi.middleware.cors import CORSMiddleware
# from fastapi.middleware.trustedhost import TrustedHostMiddleware
# from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
# from contextlib import asynccontextmanager
# import asyncio
# import logging
# from typing import List, Optional, Dict, Any
# import redis
# import json
# from datetime import datetime, timedelta
# import uuid

# # Import our crypto library
# import sys
# import os
# sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'pp_clsag_core'))
# import pp_clsag_core

# # Import our modules
# from app.database import get_db, engine, Base
# from app.models import *
# from app.schemas import *
# from app.services.crypto_service import CryptoService
# from app.services.token_service import TokenService
# from app.services.vote_service import VoteService
# from app.services.ring_service import RingService
# from app.services.monitoring_service import MonitoringService
# from app.middleware.rate_limiter import RateLimiter
# from app.middleware.concurrency_protection import ConcurrencyProtection
# from app.utils.security import verify_api_key, get_current_user
# from app.config import settings

# # Configure logging
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)

# # Initialize services
# crypto_service = CryptoService()
# token_service = TokenService()
# vote_service = VoteService()
# ring_service = RingService()
# monitoring_service = MonitoringService()

# # Security
# security = HTTPBearer()

# @asynccontextmanager
# async def lifespan(app: FastAPI):
#     """Application lifespan manager"""
#     # Startup
#     logger.info("Starting ProofPals Backend...")
    
#     # Create database tables
#     Base.metadata.create_all(bind=engine)
    
#     # Initialize Redis connection
#     redis_client = redis.Redis(
#         host=settings.REDIS_HOST,
#         port=settings.REDIS_PORT,
#         db=settings.REDIS_DB,
#         decode_responses=True
#     )
    
#     # Test Redis connection
#     try:
#         redis_client.ping()
#         logger.info("Redis connection established")
#     except Exception as e:
#         logger.error(f"Redis connection failed: {e}")
#         raise
    
#     # Initialize services
#     await crypto_service.initialize()
#     await token_service.initialize(redis_client)
#     await vote_service.initialize(redis_client)
#     await ring_service.initialize()
#     await monitoring_service.initialize()
    
#     logger.info("ProofPals Backend started successfully")
    
#     yield
    
#     # Shutdown
#     logger.info("Shutting down ProofPals Backend...")
#     await crypto_service.cleanup()
#     await token_service.cleanup()
#     await vote_service.cleanup()
#     await ring_service.cleanup()
#     await monitoring_service.cleanup()
#     logger.info("ProofPals Backend shutdown complete")

# # Create FastAPI app
# app = FastAPI(
#     title="ProofPals Backend",
#     description="Anonymous ring-based journalist review system with crypto primitives",
#     version="1.0.0",
#     lifespan=lifespan
# )

# # Add middleware
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=settings.ALLOWED_ORIGINS,
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# app.add_middleware(
#     TrustedHostMiddleware,
#     allowed_hosts=settings.ALLOWED_HOSTS
# )

# # Add custom middleware
# app.add_middleware(RateLimiter)
# app.add_middleware(ConcurrencyProtection)

# # Health check endpoint
# @app.get("/health")
# async def health_check():
#     """Health check endpoint"""
#     return {
#         "status": "healthy",
#         "timestamp": datetime.utcnow().isoformat(),
#         "version": "1.0.0",
#         "crypto_library": "pp_clsag_core",
#         "services": {
#             "crypto": await crypto_service.health_check(),
#             "token": await token_service.health_check(),
#             "vote": await vote_service.health_check(),
#             "ring": await ring_service.health_check(),
#             "monitoring": await monitoring_service.health_check()
#         }
#     }

# # Crypto operations endpoints
# @app.post("/rings", response_model=RingResponse)
# async def create_ring(
#     ring_data: RingCreate,
#     background_tasks: BackgroundTasks,
#     current_user: dict = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     """Create a new ring for anonymous voting"""
#     try:
#         # Verify admin permissions
#         if not current_user.get("is_admin", False):
#             raise HTTPException(status_code=403, detail="Admin access required")
        
#         # Create ring using ring service
#         ring = await ring_service.create_ring(
#             genre=ring_data.genre,
#             pubkeys=ring_data.pubkeys,
#             epoch=ring_data.epoch,
#             db=db
#         )
        
#         # Log ring creation
#         await monitoring_service.log_event(
#             event_type="ring_created",
#             user_id=current_user.get("user_id"),
#             data={"ring_id": ring.id, "genre": ring.genre, "size": len(ring.pubkeys)}
#         )
        
#         return RingResponse.from_orm(ring)
        
#     except Exception as e:
#         logger.error(f"Error creating ring: {e}")
#         raise HTTPException(status_code=500, detail="Failed to create ring")

# @app.get("/rings/{ring_id}/pubkeys")
# async def get_ring_pubkeys(
#     ring_id: int,
#     current_user: dict = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     """Get public keys for a ring (server internal use)"""
#     try:
#         # Verify server internal access
#         if not current_user.get("is_server_internal", False):
#             raise HTTPException(status_code=403, detail="Server internal access required")
        
#         ring = await ring_service.get_ring(ring_id, db)
#         if not ring:
#             raise HTTPException(status_code=404, detail="Ring not found")
        
#         return {
#             "ring_id": ring.id,
#             "pubkeys": ring.pubkeys,
#             "epoch": ring.epoch,
#             "active": ring.active
#         }
        
#     except Exception as e:
#         logger.error(f"Error getting ring pubkeys: {e}")
#         raise HTTPException(status_code=500, detail="Failed to get ring pubkeys")

# @app.post("/vetter/blind-sign", response_model=BlindSignatureResponse)
# async def blind_sign_token(
#     blind_request: BlindSignatureRequest,
#     current_user: dict = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     """Blind sign a token for credential issuance (vetter only)"""
#     try:
#         # Verify vetter permissions
#         if not current_user.get("is_vetter", False):
#             raise HTTPException(status_code=403, detail="Vetter access required")
        
#         # Create blind signature using crypto service
#         blind_signature = await crypto_service.create_blind_signature(
#             blinded_message=blind_request.blinded_message,
#             vetter_id=current_user.get("user_id")
#         )
        
#         # Log blind signature creation
#         await monitoring_service.log_event(
#             event_type="blind_signature_created",
#             user_id=current_user.get("user_id"),
#             data={"vetter_id": current_user.get("user_id")}
#         )
        
#         return BlindSignatureResponse(
#             signature=blind_signature.signature,
#             created_at=datetime.utcnow()
#         )
        
#     except Exception as e:
#         logger.error(f"Error creating blind signature: {e}")
#         raise HTTPException(status_code=500, detail="Failed to create blind signature")

# @app.post("/present-credential", response_model=TokenResponse)
# async def present_credential(
#     credential_data: CredentialPresentation,
#     background_tasks: BackgroundTasks,
#     current_user: dict = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     """Present blind-signed credential and receive epoch tokens"""
#     try:
#         # Verify the blind signature
#         is_valid = await crypto_service.verify_blind_signature(
#             message=credential_data.message,
#             signature=credential_data.signature,
#             public_key=credential_data.public_key
#         )
        
#         if not is_valid:
#             raise HTTPException(status_code=400, detail="Invalid credential signature")
        
#         # Check if credential is revoked
#         if await token_service.is_credential_revoked(credential_data.credential_hash):
#             raise HTTPException(status_code=400, detail="Credential has been revoked")
        
#         # Issue epoch tokens
#         tokens = await token_service.issue_epoch_tokens(
#             credential_hash=credential_data.credential_hash,
#             epoch=credential_data.epoch,
#             count=credential_data.token_count,
#             db=db
#         )
        
#         # Log credential presentation
#         await monitoring_service.log_event(
#             event_type="credential_presented",
#             user_id=current_user.get("user_id"),
#             data={"credential_hash": credential_data.credential_hash, "token_count": len(tokens)}
#         )
        
#         return TokenResponse(
#             tokens=[{"token_id": token.token_id, "epoch": token.epoch} for token in tokens],
#             issued_at=datetime.utcnow()
#         )
        
#     except Exception as e:
#         logger.error(f"Error presenting credential: {e}")
#         raise HTTPException(status_code=500, detail="Failed to present credential")

# @app.post("/vote", response_model=VoteResponse)
# async def submit_vote(
#     vote_data: VoteSubmission,
#     background_tasks: BackgroundTasks,
#     current_user: dict = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     """Submit a vote with ring signature"""
#     try:
#         # Verify and consume token atomically
#         token_valid = await token_service.verify_and_consume_token(
#             token_id=vote_data.token_id,
#             db=db
#         )
        
#         if not token_valid:
#             raise HTTPException(status_code=400, detail="Invalid or already consumed token")
        
#         # Get ring for verification
#         ring = await ring_service.get_ring(vote_data.ring_id, db)
#         if not ring:
#             raise HTTPException(status_code=404, detail="Ring not found")
        
#         # Verify ring signature using crypto service
#         verification_result = await crypto_service.verify_ring_signature(
#             message=vote_data.message,
#             ring_pubkeys=ring.pubkeys,
#             signature_blob=vote_data.signature_blob
#         )
        
#         if not verification_result["valid"]:
#             raise HTTPException(status_code=400, detail="Invalid ring signature")
        
#         key_image = verification_result["key_image"]
        
#         # Check for duplicate vote using key image
#         existing_vote = await vote_service.check_duplicate_vote(
#             submission_id=vote_data.submission_id,
#             key_image=key_image,
#             db=db
#         )
        
#         if existing_vote:
#             raise HTTPException(status_code=409, detail="Duplicate vote detected")
        
#         # Create vote record
#         vote = await vote_service.create_vote(
#             submission_id=vote_data.submission_id,
#             ring_id=vote_data.ring_id,
#             signature_blob=vote_data.signature_blob,
#             key_image=key_image,
#             vote_type=vote_data.vote_type,
#             token_id=vote_data.token_id,
#             db=db
#         )
        
#         # Trigger tally if threshold reached
#         background_tasks.add_task(
#             vote_service.check_and_trigger_tally,
#             vote_data.submission_id,
#             db
#         )
        
#         # Log vote submission
#         await monitoring_service.log_event(
#             event_type="vote_submitted",
#             user_id=current_user.get("user_id"),
#             data={
#                 "submission_id": vote_data.submission_id,
#                 "vote_type": vote_data.vote_type,
#                 "ring_id": vote_data.ring_id
#             }
#         )
        
#         return VoteResponse(
#             vote_id=vote.id,
#             submission_id=vote.submission_id,
#             vote_type=vote.vote_type,
#             verified=True,
#             created_at=vote.created_at
#         )
        
#     except Exception as e:
#         logger.error(f"Error submitting vote: {e}")
#         raise HTTPException(status_code=500, detail="Failed to submit vote")

# @app.get("/tally/{submission_id}", response_model=TallyResponse)
# async def get_tally_result(
#     submission_id: int,
#     current_user: dict = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     """Get tally result for a submission (admin only)"""
#     try:
#         # Verify admin permissions
#         if not current_user.get("is_admin", False):
#             raise HTTPException(status_code=403, detail="Admin access required")
        
#         tally = await vote_service.get_tally_result(submission_id, db)
#         if not tally:
#             raise HTTPException(status_code=404, detail="Tally not found")
        
#         return TallyResponse.from_orm(tally)
        
#     except Exception as e:
#         logger.error(f"Error getting tally result: {e}")
#         raise HTTPException(status_code=500, detail="Failed to get tally result")

# @app.post("/revoke-credential")
# async def revoke_credential(
#     revocation_data: CredentialRevocation,
#     current_user: dict = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     """Revoke a credential (vetter only)"""
#     try:
#         # Verify vetter permissions
#         if not current_user.get("is_vetter", False):
#             raise HTTPException(status_code=403, detail="Vetter access required")
        
#         # Revoke credential
#         await token_service.revoke_credential(
#             credential_hash=revocation_data.credential_hash,
#             reason=revocation_data.reason,
#             revoked_by=current_user.get("user_id"),
#             db=db
#         )
        
#         # Log revocation
#         await monitoring_service.log_event(
#             event_type="credential_revoked",
#             user_id=current_user.get("user_id"),
#             data={
#                 "credential_hash": revocation_data.credential_hash,
#                 "reason": revocation_data.reason
#             }
#         )
        
#         return {"message": "Credential revoked successfully"}
        
#     except Exception as e:
#         logger.error(f"Error revoking credential: {e}")
#         raise HTTPException(status_code=500, detail="Failed to revoke credential")

# # Monitoring and metrics endpoints
# @app.get("/metrics")
# async def get_metrics(
#     current_user: dict = Depends(get_current_user)
# ):
#     """Get system metrics (admin only)"""
#     try:
#         if not current_user.get("is_admin", False):
#             raise HTTPException(status_code=403, detail="Admin access required")
        
#         metrics = await monitoring_service.get_metrics()
#         return metrics
        
#     except Exception as e:
#         logger.error(f"Error getting metrics: {e}")
#         raise HTTPException(status_code=500, detail="Failed to get metrics")

# @app.get("/events")
# async def get_events(
#     event_type: Optional[str] = None,
#     limit: int = 100,
#     current_user: dict = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     """Get audit events (admin only)"""
#     try:
#         if not current_user.get("is_admin", False):
#             raise HTTPException(status_code=403, detail="Admin access required")
        
#         events = await monitoring_service.get_events(
#             event_type=event_type,
#             limit=limit,
#             db=db
#         )
        
#         return events
        
#     except Exception as e:
#         logger.error(f"Error getting events: {e}")
#         raise HTTPException(status_code=500, detail="Failed to get events")

# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(
#         "main:app",
#         host="0.0.0.0",
#         port=8000,
#         reload=True,
#         log_level="info"
#     )

"""
ProofPals Backend - Main FastAPI Application
"""

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