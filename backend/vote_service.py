"""
ProofPals Vote Service
Handles vote submission, verification, and duplicate detection
"""

import logging
from typing import Optional, Dict, Any
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models import Vote, Ring, Submission, VoteType, AuditLog
from crypto_service import get_crypto_service
from token_service import get_token_service

logger = logging.getLogger(__name__)


class VoteService:
    """Service for managing votes"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.crypto_service = get_crypto_service()
        self.token_service = get_token_service()
    
    async def submit_vote(
        self,
        submission_id: int,
        ring_id: int,
        signature_blob: str,
        vote_type: str,
        token_id: str,
        message: bytes,
        db: AsyncSession,
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Submit and verify a vote
        
        This is the CRITICAL vote processing pipeline:
        1. Consume token atomically (prevents double-voting)
        2. Verify ring signature (proves anonymity + authenticity)
        3. Check for duplicate key image (prevents same credential voting twice)
        4. Store vote
        
        Args:
            submission_id: ID of submission being voted on
            ring_id: ID of ring used for signature
            signature_blob: JSON string of CLSAG signature
            vote_type: Type of vote (approve/reject/escalate/flag)
            token_id: Token to consume
            message: The canonical message that was signed
            db: Database session
            ip_address: Optional IP for audit logging
            
        Returns:
            Dictionary with success status, vote_id, and error if any
        """
        try:
            # Validate vote type
            if vote_type not in [vt.value for vt in VoteType]:
                return {
                    "success": False,
                    "error": f"Invalid vote type: {vote_type}"
                }
            
            # STEP 1: Atomically consume token
            token_valid, token_error = await self.token_service.verify_and_consume_token(
                token_id, db
            )
            
            if not token_valid:
                self.logger.warning(f"Token verification failed: {token_error}")
                await self._log_audit(
                    db, "vote_failed", "vote", str(submission_id),
                    {"reason": "invalid_token", "error": token_error},
                    ip_address
                )
                return {
                    "success": False,
                    "error": token_error
                }
            
            # STEP 2: Fetch ring from database
            result = await db.execute(
                select(Ring).where(
                    Ring.id == ring_id,
                    Ring.active == True
                )
            )
            ring = result.scalar_one_or_none()
            
            if not ring:
                self.logger.warning(f"Ring {ring_id} not found or inactive")
                return {
                    "success": False,
                    "error": "Ring not found or inactive"
                }
            
            # Extract public keys from ring
            ring_pubkeys = ring.pubkeys  # This is a list of hex strings
            
            # STEP 3: Verify CLSAG signature
            verification_result = self.crypto_service.verify_clsag_signature(
                message, ring_pubkeys, signature_blob
            )
            
            if not verification_result.is_valid:
                self.logger.warning(f"Signature verification failed: {verification_result.error}")
                await self._log_audit(
                    db, "vote_failed", "vote", str(submission_id),
                    {"reason": "invalid_signature", "error": verification_result.error},
                    ip_address
                )
                return {
                    "success": False,
                    "error": verification_result.error or "Invalid signature"
                }
            
            key_image = verification_result.key_image
            
            # STEP 4: Check for duplicate vote (same key_image + submission)
            result = await db.execute(
                select(Vote).where(
                    Vote.submission_id == submission_id,
                    Vote.key_image == key_image
                )
            )
            existing_vote = result.scalar_one_or_none()
            
            if existing_vote:
                self.logger.warning(
                    f"Duplicate vote detected: submission={submission_id}, "
                    f"key_image={key_image[:16]}..."
                )
                await self._log_audit(
                    db, "vote_failed", "vote", str(submission_id),
                    {"reason": "duplicate_vote", "key_image": key_image[:16]},
                    ip_address
                )
                return {
                    "success": False,
                    "error": "Duplicate vote: This credential has already voted on this submission"
                }
            
            # STEP 5: Verify submission exists
            result = await db.execute(
                select(Submission).where(Submission.id == submission_id)
            )
            submission = result.scalar_one_or_none()
            
            if not submission:
                self.logger.warning(f"Submission {submission_id} not found")
                return {
                    "success": False,
                    "error": "Submission not found"
                }
            
            # STEP 6: Create vote record
            vote = Vote(
                submission_id=submission_id,
                ring_id=ring_id,
                signature_blob=signature_blob,
                key_image=key_image,
                vote_type=vote_type,
                token_id=token_id,
                verified=True,
                created_at=datetime.utcnow()
            )
            
            db.add(vote)
            await db.commit()
            await db.refresh(vote)
            
            # STEP 7: Log successful vote
            await self._log_audit(
                db, "vote_submitted", "vote", str(vote.id),
                {
                    "submission_id": submission_id,
                    "vote_type": vote_type,
                    "key_image": key_image[:16],
                    "ring_id": ring_id
                },
                ip_address
            )
            
            self.logger.info(
                f"Vote {vote.id} successfully submitted: "
                f"submission={submission_id}, type={vote_type}, "
                f"key_image={key_image[:16]}..."
            )
            
            return {
                "success": True,
                "vote_id": vote.id,
                "key_image": key_image,
                "message": "Vote submitted successfully"
            }
            
        except Exception as e:
            self.logger.error(f"Error submitting vote: {e}", exc_info=True)
            await db.rollback()
            return {
                "success": False,
                "error": f"Vote submission failed: {str(e)}"
            }
    
    async def get_vote_count(
        self,
        submission_id: int,
        db: AsyncSession
    ) -> Dict[str, int]:
        """
        Get vote counts for a submission
        
        Args:
            submission_id: Submission ID
            db: Database session
            
        Returns:
            Dictionary with vote counts by type
        """
        try:
            from sqlalchemy import func
            
            result = await db.execute(
                select(
                    Vote.vote_type,
                    func.count(Vote.id)
                ).where(
                    Vote.submission_id == submission_id,
                    Vote.verified == True
                ).group_by(Vote.vote_type)
            )
            
            counts = {vt.value: 0 for vt in VoteType}
            for vote_type, count in result:
                counts[vote_type] = count
            
            counts["total"] = sum(counts.values())
            
            return counts
            
        except Exception as e:
            self.logger.error(f"Error getting vote count: {e}", exc_info=True)
            return {"total": 0}
    
    async def get_unique_voters(
        self,
        submission_id: int,
        db: AsyncSession
    ) -> int:
        """
        Get number of unique voters (unique key images)
        
        Args:
            submission_id: Submission ID
            db: Database session
            
        Returns:
            Number of unique voters
        """
        try:
            from sqlalchemy import func, distinct
            
            result = await db.execute(
                select(func.count(distinct(Vote.key_image)))
                .where(
                    Vote.submission_id == submission_id,
                    Vote.verified == True
                )
            )
            
            count = result.scalar()
            return count or 0
            
        except Exception as e:
            self.logger.error(f"Error getting unique voters: {e}", exc_info=True)
            return 0
    
    async def check_has_voted(
        self,
        submission_id: int,
        key_image: str,
        db: AsyncSession
    ) -> bool:
        """
        Check if a key image has already voted on a submission
        
        Args:
            submission_id: Submission ID
            key_image: Key image hex string
            db: Database session
            
        Returns:
            True if already voted, False otherwise
        """
        try:
            result = await db.execute(
                select(Vote).where(
                    Vote.submission_id == submission_id,
                    Vote.key_image == key_image,
                    Vote.verified == True
                )
            )
            
            vote = result.scalar_one_or_none()
            return vote is not None
            
        except Exception as e:
            self.logger.error(f"Error checking vote status: {e}", exc_info=True)
            return False
    
    async def _log_audit(
        self,
        db: AsyncSession,
        event_type: str,
        entity_type: str,
        entity_id: str,
        details: Dict[str, Any],
        ip_address: Optional[str] = None
    ):
        """Log an audit event"""
        try:
            audit_log = AuditLog(
                event_type=event_type,
                entity_type=entity_type,
                entity_id=entity_id,
                details=details,
                ip_address=ip_address,
                timestamp=datetime.utcnow()
            )
            db.add(audit_log)
            await db.commit()
        except Exception as e:
            self.logger.error(f"Error logging audit: {e}", exc_info=True)


# Global vote service instance
_vote_service: Optional[VoteService] = None


def get_vote_service() -> VoteService:
    """Get global vote service instance"""
    global _vote_service
    if _vote_service is None:
        _vote_service = VoteService()
    return _vote_service