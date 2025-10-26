"""
ProofPals Backend - FastAPI Application
Crypto-enabled anonymous voting and review system
"""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from contextlib import asynccontextmanager
import asyncio
import logging
from typing import List, Optional, Dict, Any
import redis
import json
from datetime import datetime, timedelta
import uuid

# Import our crypto library
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'pp_clsag_core'))
import pp_clsag_core

# Import our modules
from app.database import get_db, engine, Base
from app.models import *
from app.schemas import *
from app.services.crypto_service import CryptoService
from app.services.token_service import TokenService
from app.services.vote_service import VoteService
from app.services.ring_service import RingService
from app.services.monitoring_service import MonitoringService
from app.middleware.rate_limiter import RateLimiter
from app.middleware.concurrency_protection import ConcurrencyProtection
from app.utils.security import verify_api_key, get_current_user
from app.config import settings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize services
crypto_service = CryptoService()
token_service = TokenService()
vote_service = VoteService()
ring_service = RingService()
monitoring_service = MonitoringService()

# Security
security = HTTPBearer()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    logger.info("Starting ProofPals Backend...")
    
    # Create database tables
    Base.metadata.create_all(bind=engine)
    
    # Initialize Redis connection
    redis_client = redis.Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        db=settings.REDIS_DB,
        decode_responses=True
    )
    
    # Test Redis connection
    try:
        redis_client.ping()
        logger.info("Redis connection established")
    except Exception as e:
        logger.error(f"Redis connection failed: {e}")
        raise
    
    # Initialize services
    await crypto_service.initialize()
    await token_service.initialize(redis_client)
    await vote_service.initialize(redis_client)
    await ring_service.initialize()
    await monitoring_service.initialize()
    
    logger.info("ProofPals Backend started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down ProofPals Backend...")
    await crypto_service.cleanup()
    await token_service.cleanup()
    await vote_service.cleanup()
    await ring_service.cleanup()
    await monitoring_service.cleanup()
    logger.info("ProofPals Backend shutdown complete")

# Create FastAPI app
app = FastAPI(
    title="ProofPals Backend",
    description="Anonymous ring-based journalist review system with crypto primitives",
    version="1.0.0",
    lifespan=lifespan
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS
)

# Add custom middleware
app.add_middleware(RateLimiter)
app.add_middleware(ConcurrencyProtection)

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "crypto_library": "pp_clsag_core",
        "services": {
            "crypto": await crypto_service.health_check(),
            "token": await token_service.health_check(),
            "vote": await vote_service.health_check(),
            "ring": await ring_service.health_check(),
            "monitoring": await monitoring_service.health_check()
        }
    }

# Crypto operations endpoints
@app.post("/rings", response_model=RingResponse)
async def create_ring(
    ring_data: RingCreate,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new ring for anonymous voting"""
    try:
        # Verify admin permissions
        if not current_user.get("is_admin", False):
            raise HTTPException(status_code=403, detail="Admin access required")
        
        # Create ring using ring service
        ring = await ring_service.create_ring(
            genre=ring_data.genre,
            pubkeys=ring_data.pubkeys,
            epoch=ring_data.epoch,
            db=db
        )
        
        # Log ring creation
        await monitoring_service.log_event(
            event_type="ring_created",
            user_id=current_user.get("user_id"),
            data={"ring_id": ring.id, "genre": ring.genre, "size": len(ring.pubkeys)}
        )
        
        return RingResponse.from_orm(ring)
        
    except Exception as e:
        logger.error(f"Error creating ring: {e}")
        raise HTTPException(status_code=500, detail="Failed to create ring")

@app.get("/rings/{ring_id}/pubkeys")
async def get_ring_pubkeys(
    ring_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get public keys for a ring (server internal use)"""
    try:
        # Verify server internal access
        if not current_user.get("is_server_internal", False):
            raise HTTPException(status_code=403, detail="Server internal access required")
        
        ring = await ring_service.get_ring(ring_id, db)
        if not ring:
            raise HTTPException(status_code=404, detail="Ring not found")
        
        return {
            "ring_id": ring.id,
            "pubkeys": ring.pubkeys,
            "epoch": ring.epoch,
            "active": ring.active
        }
        
    except Exception as e:
        logger.error(f"Error getting ring pubkeys: {e}")
        raise HTTPException(status_code=500, detail="Failed to get ring pubkeys")

@app.post("/vetter/blind-sign", response_model=BlindSignatureResponse)
async def blind_sign_token(
    blind_request: BlindSignatureRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Blind sign a token for credential issuance (vetter only)"""
    try:
        # Verify vetter permissions
        if not current_user.get("is_vetter", False):
            raise HTTPException(status_code=403, detail="Vetter access required")
        
        # Create blind signature using crypto service
        blind_signature = await crypto_service.create_blind_signature(
            blinded_message=blind_request.blinded_message,
            vetter_id=current_user.get("user_id")
        )
        
        # Log blind signature creation
        await monitoring_service.log_event(
            event_type="blind_signature_created",
            user_id=current_user.get("user_id"),
            data={"vetter_id": current_user.get("user_id")}
        )
        
        return BlindSignatureResponse(
            signature=blind_signature.signature,
            created_at=datetime.utcnow()
        )
        
    except Exception as e:
        logger.error(f"Error creating blind signature: {e}")
        raise HTTPException(status_code=500, detail="Failed to create blind signature")

@app.post("/present-credential", response_model=TokenResponse)
async def present_credential(
    credential_data: CredentialPresentation,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Present blind-signed credential and receive epoch tokens"""
    try:
        # Verify the blind signature
        is_valid = await crypto_service.verify_blind_signature(
            message=credential_data.message,
            signature=credential_data.signature,
            public_key=credential_data.public_key
        )
        
        if not is_valid:
            raise HTTPException(status_code=400, detail="Invalid credential signature")
        
        # Check if credential is revoked
        if await token_service.is_credential_revoked(credential_data.credential_hash):
            raise HTTPException(status_code=400, detail="Credential has been revoked")
        
        # Issue epoch tokens
        tokens = await token_service.issue_epoch_tokens(
            credential_hash=credential_data.credential_hash,
            epoch=credential_data.epoch,
            count=credential_data.token_count,
            db=db
        )
        
        # Log credential presentation
        await monitoring_service.log_event(
            event_type="credential_presented",
            user_id=current_user.get("user_id"),
            data={"credential_hash": credential_data.credential_hash, "token_count": len(tokens)}
        )
        
        return TokenResponse(
            tokens=[{"token_id": token.token_id, "epoch": token.epoch} for token in tokens],
            issued_at=datetime.utcnow()
        )
        
    except Exception as e:
        logger.error(f"Error presenting credential: {e}")
        raise HTTPException(status_code=500, detail="Failed to present credential")

@app.post("/vote", response_model=VoteResponse)
async def submit_vote(
    vote_data: VoteSubmission,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Submit a vote with ring signature"""
    try:
        # Verify and consume token atomically
        token_valid = await token_service.verify_and_consume_token(
            token_id=vote_data.token_id,
            db=db
        )
        
        if not token_valid:
            raise HTTPException(status_code=400, detail="Invalid or already consumed token")
        
        # Get ring for verification
        ring = await ring_service.get_ring(vote_data.ring_id, db)
        if not ring:
            raise HTTPException(status_code=404, detail="Ring not found")
        
        # Verify ring signature using crypto service
        verification_result = await crypto_service.verify_ring_signature(
            message=vote_data.message,
            ring_pubkeys=ring.pubkeys,
            signature_blob=vote_data.signature_blob
        )
        
        if not verification_result["valid"]:
            raise HTTPException(status_code=400, detail="Invalid ring signature")
        
        key_image = verification_result["key_image"]
        
        # Check for duplicate vote using key image
        existing_vote = await vote_service.check_duplicate_vote(
            submission_id=vote_data.submission_id,
            key_image=key_image,
            db=db
        )
        
        if existing_vote:
            raise HTTPException(status_code=409, detail="Duplicate vote detected")
        
        # Create vote record
        vote = await vote_service.create_vote(
            submission_id=vote_data.submission_id,
            ring_id=vote_data.ring_id,
            signature_blob=vote_data.signature_blob,
            key_image=key_image,
            vote_type=vote_data.vote_type,
            token_id=vote_data.token_id,
            db=db
        )
        
        # Trigger tally if threshold reached
        background_tasks.add_task(
            vote_service.check_and_trigger_tally,
            vote_data.submission_id,
            db
        )
        
        # Log vote submission
        await monitoring_service.log_event(
            event_type="vote_submitted",
            user_id=current_user.get("user_id"),
            data={
                "submission_id": vote_data.submission_id,
                "vote_type": vote_data.vote_type,
                "ring_id": vote_data.ring_id
            }
        )
        
        return VoteResponse(
            vote_id=vote.id,
            submission_id=vote.submission_id,
            vote_type=vote.vote_type,
            verified=True,
            created_at=vote.created_at
        )
        
    except Exception as e:
        logger.error(f"Error submitting vote: {e}")
        raise HTTPException(status_code=500, detail="Failed to submit vote")

@app.get("/tally/{submission_id}", response_model=TallyResponse)
async def get_tally_result(
    submission_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get tally result for a submission (admin only)"""
    try:
        # Verify admin permissions
        if not current_user.get("is_admin", False):
            raise HTTPException(status_code=403, detail="Admin access required")
        
        tally = await vote_service.get_tally_result(submission_id, db)
        if not tally:
            raise HTTPException(status_code=404, detail="Tally not found")
        
        return TallyResponse.from_orm(tally)
        
    except Exception as e:
        logger.error(f"Error getting tally result: {e}")
        raise HTTPException(status_code=500, detail="Failed to get tally result")

@app.post("/revoke-credential")
async def revoke_credential(
    revocation_data: CredentialRevocation,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Revoke a credential (vetter only)"""
    try:
        # Verify vetter permissions
        if not current_user.get("is_vetter", False):
            raise HTTPException(status_code=403, detail="Vetter access required")
        
        # Revoke credential
        await token_service.revoke_credential(
            credential_hash=revocation_data.credential_hash,
            reason=revocation_data.reason,
            revoked_by=current_user.get("user_id"),
            db=db
        )
        
        # Log revocation
        await monitoring_service.log_event(
            event_type="credential_revoked",
            user_id=current_user.get("user_id"),
            data={
                "credential_hash": revocation_data.credential_hash,
                "reason": revocation_data.reason
            }
        )
        
        return {"message": "Credential revoked successfully"}
        
    except Exception as e:
        logger.error(f"Error revoking credential: {e}")
        raise HTTPException(status_code=500, detail="Failed to revoke credential")

# Monitoring and metrics endpoints
@app.get("/metrics")
async def get_metrics(
    current_user: dict = Depends(get_current_user)
):
    """Get system metrics (admin only)"""
    try:
        if not current_user.get("is_admin", False):
            raise HTTPException(status_code=403, detail="Admin access required")
        
        metrics = await monitoring_service.get_metrics()
        return metrics
        
    except Exception as e:
        logger.error(f"Error getting metrics: {e}")
        raise HTTPException(status_code=500, detail="Failed to get metrics")

@app.get("/events")
async def get_events(
    event_type: Optional[str] = None,
    limit: int = 100,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get audit events (admin only)"""
    try:
        if not current_user.get("is_admin", False):
            raise HTTPException(status_code=403, detail="Admin access required")
        
        events = await monitoring_service.get_events(
            event_type=event_type,
            limit=limit,
            db=db
        )
        
        return events
        
    except Exception as e:
        logger.error(f"Error getting events: {e}")
        raise HTTPException(status_code=500, detail="Failed to get events")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
