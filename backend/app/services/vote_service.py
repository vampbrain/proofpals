"""
Vote service for handling vote ingestion and tallying
"""

import asyncio
import logging
import redis
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models import Vote, Submission, Tally, Ring
from app.config import settings

logger = logging.getLogger(__name__)

class VoteService:
    """Service for handling votes and tallying"""
    
    def __init__(self):
        self.redis_client = None
        self.initialized = False
        
    async def initialize(self, redis_client: redis.Redis):
        """Initialize the vote service"""
        try:
            self.redis_client = redis_client
            self.initialized = True
            logger.info("Vote service initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize vote service: {e}")
            raise
    
    async def cleanup(self):
        """Cleanup vote service resources"""
        self.initialized = False
        self.redis_client = None
        logger.info("Vote service cleaned up")
    
    async def health_check(self) -> Dict[str, Any]:
        """Check vote service health"""
        try:
            if self.redis_client:
                await self.redis_client.ping()
                redis_healthy = True
            else:
                redis_healthy = False
        except:
            redis_healthy = False
            
        return {
            "initialized": self.initialized,
            "redis_connected": redis_healthy,
            "vote_threshold": settings.VOTE_THRESHOLD
        }
    
    async def create_vote(
        self,
        submission_id: int,
        ring_id: int,
        signature_blob: str,
        key_image: bytes,
        vote_type: str,
        token_id: str,
        db: Session
    ) -> Vote:
        """Create a new vote record"""
        try:
            vote = Vote(
                submission_id=submission_id,
                ring_id=ring_id,
                signature_blob=signature_blob,
                key_image=key_image.hex(),
                vote_type=vote_type,
                token_id=token_id,
                verified_bool=True
            )
            
            db.add(vote)
            db.commit()
            db.refresh(vote)
            
            # Store vote in Redis for fast duplicate checking
            await self._store_vote_in_redis(vote)
            
            logger.info(f"Created vote {vote.id} for submission {submission_id}")
            return vote
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error creating vote: {e}")
            raise
    
    async def check_duplicate_vote(
        self,
        submission_id: int,
        key_image: bytes,
        db: Session
    ) -> Optional[Vote]:
        """Check for duplicate vote using key image"""
        try:
            # Check Redis cache first
            cache_key = f"vote:{submission_id}:{key_image.hex()}"
            cached = await self.redis_client.get(cache_key)
            if cached:
                return Vote  # Vote exists
            
            # Check database
            vote = db.query(Vote).filter(
                Vote.submission_id == submission_id,
                Vote.key_image == key_image.hex()
            ).first()
            
            if vote:
                # Cache in Redis
                await self.redis_client.setex(cache_key, 3600, "1")
            
            return vote
            
        except Exception as e:
            logger.error(f"Error checking duplicate vote: {e}")
            return None
    
    async def check_and_trigger_tally(self, submission_id: int, db: Session):
        """Check if tally threshold is reached and trigger tallying"""
        try:
            # Get vote count for submission
            vote_count = db.query(Vote).filter(
                Vote.submission_id == submission_id,
                Vote.verified_bool == True
            ).count()
            
            if vote_count >= settings.VOTE_THRESHOLD:
                await self.perform_tally(submission_id, db)
                
        except Exception as e:
            logger.error(f"Error checking tally threshold: {e}")
    
    async def perform_tally(self, submission_id: int, db: Session) -> Optional[Tally]:
        """Perform tally for a submission"""
        try:
            # Get all verified votes for submission
            votes = db.query(Vote).filter(
                Vote.submission_id == submission_id,
                Vote.verified_bool == True
            ).all()
            
            if not votes:
                logger.warning(f"No votes found for submission {submission_id}")
                return None
            
            # Count votes by type
            count_approve = sum(1 for v in votes if v.vote_type == "approve")
            count_reject = sum(1 for v in votes if v.vote_type == "reject")
            count_flag = sum(1 for v in votes if v.vote_type == "flag")
            count_escalate = sum(1 for v in votes if v.vote_type == "escalate")
            total_votes = len(votes)
            
            # Apply decision logic
            decision = self._determine_decision(
                count_approve, count_reject, count_flag, count_escalate
            )
            
            # Create or update tally
            tally = db.query(Tally).filter(Tally.submission_id == submission_id).first()
            
            if tally:
                # Update existing tally
                tally.count_approve = count_approve
                tally.count_reject = count_reject
                tally.count_flag = count_flag
                tally.count_escalate = count_escalate
                tally.total_votes = total_votes
                tally.decision = decision
                tally.updated_at = datetime.utcnow()
            else:
                # Create new tally
                tally = Tally(
                    submission_id=submission_id,
                    count_approve=count_approve,
                    count_reject=count_reject,
                    count_flag=count_flag,
                    count_escalate=count_escalate,
                    total_votes=total_votes,
                    decision=decision
                )
                db.add(tally)
            
            # Update submission status
            submission = db.query(Submission).filter(Submission.id == submission_id).first()
            if submission:
                submission.status = decision
                submission.last_tallied_at = datetime.utcnow()
            
            db.commit()
            db.refresh(tally)
            
            # Store tally in Redis
            await self._store_tally_in_redis(tally)
            
            logger.info(f"Tally completed for submission {submission_id}: {decision}")
            return tally
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error performing tally: {e}")
            raise
    
    async def get_tally_result(self, submission_id: int, db: Session) -> Optional[Tally]:
        """Get tally result for a submission"""
        try:
            # Check Redis cache first
            cache_key = f"tally:{submission_id}"
            cached = await self.redis_client.get(cache_key)
            if cached:
                tally_data = json.loads(cached)
                return Tally(**tally_data)
            
            # Get from database
            tally = db.query(Tally).filter(Tally.submission_id == submission_id).first()
            
            if tally:
                # Cache in Redis
                await self._store_tally_in_redis(tally)
            
            return tally
            
        except Exception as e:
            logger.error(f"Error getting tally result: {e}")
            return None
    
    async def get_vote_statistics(self, submission_id: int, db: Session) -> Dict[str, Any]:
        """Get vote statistics for a submission"""
        try:
            votes = db.query(Vote).filter(
                Vote.submission_id == submission_id,
                Vote.verified_bool == True
            ).all()
            
            stats = {
                "total_votes": len(votes),
                "by_type": {
                    "approve": sum(1 for v in votes if v.vote_type == "approve"),
                    "reject": sum(1 for v in votes if v.vote_type == "reject"),
                    "flag": sum(1 for v in votes if v.vote_type == "flag"),
                    "escalate": sum(1 for v in votes if v.vote_type == "escalate")
                },
                "by_ring": {}
            }
            
            # Group by ring
            for vote in votes:
                ring_id = vote.ring_id
                if ring_id not in stats["by_ring"]:
                    stats["by_ring"][ring_id] = {
                        "total": 0,
                        "by_type": {"approve": 0, "reject": 0, "flag": 0, "escalate": 0}
                    }
                
                stats["by_ring"][ring_id]["total"] += 1
                stats["by_ring"][ring_id]["by_type"][vote.vote_type] += 1
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting vote statistics: {e}")
            return {}
    
    def _determine_decision(
        self,
        count_approve: int,
        count_reject: int,
        count_flag: int,
        count_escalate: int
    ) -> str:
        """Determine decision based on vote counts"""
        # Check for urgent escalation
        if count_flag >= settings.URGENT_FLAG_LIMIT:
            return "escalated"
        
        # Check flag fraction
        total_votes = count_approve + count_reject + count_flag + count_escalate
        if total_votes > 0 and count_flag / total_votes >= settings.FLAG_FRACTION:
            return "escalated"
        
        # Check escalation threshold
        if count_escalate > 0:
            return "escalated"
        
        # Determine approval/rejection
        if count_approve > count_reject:
            return "approved"
        elif count_reject > count_approve:
            return "rejected"
        else:
            # Tie - escalate for human review
            return "escalated"
    
    async def _store_vote_in_redis(self, vote: Vote):
        """Store vote data in Redis"""
        try:
            cache_key = f"vote:{vote.submission_id}:{vote.key_image}"
            await self.redis_client.setex(cache_key, 3600, "1")
            
        except Exception as e:
            logger.error(f"Error storing vote in Redis: {e}")
    
    async def _store_tally_in_redis(self, tally: Tally):
        """Store tally data in Redis"""
        try:
            tally_data = {
                "id": tally.id,
                "submission_id": tally.submission_id,
                "count_approve": tally.count_approve,
                "count_reject": tally.count_reject,
                "count_flag": tally.count_flag,
                "count_escalate": tally.count_escalate,
                "total_votes": tally.total_votes,
                "decision": tally.decision,
                "created_at": tally.created_at.isoformat(),
                "updated_at": tally.updated_at.isoformat()
            }
            
            cache_key = f"tally:{tally.submission_id}"
            await self.redis_client.setex(cache_key, 3600, json.dumps(tally_data))
            
        except Exception as e:
            logger.error(f"Error storing tally in Redis: {e}")
    
    async def get_system_vote_stats(self, db: Session) -> Dict[str, Any]:
        """Get system-wide vote statistics"""
        try:
            total_votes = db.query(Vote).count()
            verified_votes = db.query(Vote).filter(Vote.verified_bool == True).count()
            
            # Votes by type
            votes_by_type = db.query(
                Vote.vote_type,
                func.count(Vote.id)
            ).filter(Vote.verified_bool == True).group_by(Vote.vote_type).all()
            
            # Votes by genre (through submissions)
            votes_by_genre = db.query(
                Submission.genre,
                func.count(Vote.id)
            ).join(Vote).filter(Vote.verified_bool == True).group_by(Submission.genre).all()
            
            return {
                "total_votes": total_votes,
                "verified_votes": verified_votes,
                "by_type": dict(votes_by_type),
                "by_genre": dict(votes_by_genre)
            }
            
        except Exception as e:
            logger.error(f"Error getting system vote stats: {e}")
            return {}
