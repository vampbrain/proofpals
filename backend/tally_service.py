"""
ProofPals Tally Service
Computes vote tallies and makes decisions
"""

import logging
from typing import Optional, Dict, Any
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, func

from models import Vote, Submission, Tally, SubmissionStatus, VoteType, AuditLog
from config import settings

logger = logging.getLogger(__name__)


class TallyService:
    """Service for computing vote tallies"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    async def compute_tally(
        self,
        submission_id: int,
        db: AsyncSession,
        force: bool = False
    ) -> Dict[str, Any]:
        """
        Compute vote tally and make decision
        
        Decision Rules:
        1. If count_flag >= URGENT_FLAG_LIMIT → ESCALATED
        2. Else if count_approve > count_reject → APPROVED
        3. Else if count_reject > count_approve → REJECTED
        4. Else (tie) → ESCALATED
        
        Args:
            submission_id: Submission ID
            db: Database session
            force: Force recomputation even if already computed
            
        Returns:
            Dictionary with tally results and decision
        """
        try:
            # Verify submission exists
            result = await db.execute(
                select(Submission).where(Submission.id == submission_id)
            )
            submission = result.scalar_one_or_none()
            
            if not submission:
                return {
                    "success": False,
                    "error": "Submission not found"
                }
            
            # Check if tally already exists
            result = await db.execute(
                select(Tally).where(Tally.submission_id == submission_id)
            )
            existing_tally = result.scalar_one_or_none()
            
            if existing_tally and not force:
                self.logger.info(f"Tally for submission {submission_id} already exists")
                return {
                    "success": True,
                    "tally_id": existing_tally.id,
                    "counts": {
                        "approve": existing_tally.count_approve,
                        "escalate": existing_tally.count_escalate,
                        "reject": existing_tally.count_reject,
                        "flag": existing_tally.count_flag
                    },
                    "decision": existing_tally.final_decision,
                    "computed_at": existing_tally.computed_at.isoformat()
                }
            
            # Count votes by type
            result = await db.execute(
                select(
                    Vote.vote_type,
                    func.count(Vote.id)
                ).where(
                    Vote.submission_id == submission_id,
                    Vote.verified == True
                ).group_by(Vote.vote_type)
            )
            
            # Initialize counts
            counts = {
                "approve": 0,
                "escalate": 0,
                "reject": 0,
                "flag": 0
            }
            
            # Populate counts from query results
            for vote_type, count in result:
                if vote_type in counts:
                    counts[vote_type] = count
            
            total_votes = sum(counts.values())
            
            # Apply decision rules
            decision = self._make_decision(counts)
            
            self.logger.info(
                f"Tally for submission {submission_id}: "
                f"approve={counts['approve']}, "
                f"reject={counts['reject']}, "
                f"escalate={counts['escalate']}, "
                f"flag={counts['flag']}, "
                f"decision={decision}"
            )
            
            # Create or update tally record
            if existing_tally:
                await db.execute(
                    update(Tally)
                    .where(Tally.submission_id == submission_id)
                    .values(
                        count_approve=counts["approve"],
                        count_escalate=counts["escalate"],
                        count_reject=counts["reject"],
                        count_flag=counts["flag"],
                        final_decision=decision,
                        computed_at=datetime.utcnow()
                    )
                )
                tally_id = existing_tally.id
            else:
                tally = Tally(
                    submission_id=submission_id,
                    count_approve=counts["approve"],
                    count_escalate=counts["escalate"],
                    count_reject=counts["reject"],
                    count_flag=counts["flag"],
                    final_decision=decision,
                    computed_at=datetime.utcnow()
                )
                db.add(tally)
                await db.flush()
                tally_id = tally.id
            
            # Update submission status
            await db.execute(
                update(Submission)
                .where(Submission.id == submission_id)
                .values(
                    status=decision,
                    last_tallied_at=datetime.utcnow()
                )
            )
            
            await db.commit()
            
            # Log audit event
            await self._log_audit(
                db, "tally_computed", "tally", str(tally_id),
                {
                    "submission_id": submission_id,
                    "decision": decision,
                    "counts": counts,
                    "total_votes": total_votes
                }
            )
            
            return {
                "success": True,
                "tally_id": tally_id,
                "counts": counts,
                "total_votes": total_votes,
                "decision": decision,
                "computed_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error computing tally: {e}", exc_info=True)
            await db.rollback()
            return {
                "success": False,
                "error": f"Tally computation failed: {str(e)}"
            }
    
    def _make_decision(self, counts: Dict[str, int]) -> str:
        """
        Apply decision rules to vote counts
        
        Args:
            counts: Dictionary with vote counts
            
        Returns:
            Decision string (approved/rejected/escalated/flagged)
        """
        # Rule 1: Urgent flag threshold
        if counts["flag"] >= settings.URGENT_FLAG_LIMIT:
            self.logger.info(
                f"Decision: FLAGGED (flags={counts['flag']} >= {settings.URGENT_FLAG_LIMIT})"
            )
            return SubmissionStatus.FLAGGED.value
        
        # Rule 2: Approve if more approvals than rejections
        if counts["approve"] > counts["reject"]:
            self.logger.info(
                f"Decision: APPROVED (approve={counts['approve']} > reject={counts['reject']})"
            )
            return SubmissionStatus.APPROVED.value
        
        # Rule 3: Reject if more rejections than approvals
        if counts["reject"] > counts["approve"]:
            self.logger.info(
                f"Decision: REJECTED (reject={counts['reject']} > approve={counts['approve']})"
            )
            return SubmissionStatus.REJECTED.value
        
        # Rule 4: Tie or edge cases → escalate
        self.logger.info(
            f"Decision: ESCALATED (tie or edge case: "
            f"approve={counts['approve']}, reject={counts['reject']})"
        )
        return SubmissionStatus.ESCALATED.value
    
    async def get_tally_by_submission(
        self,
        submission_id: int,
        db: AsyncSession
    ) -> Optional[Dict[str, Any]]:
        """
        Get existing tally for a submission
        
        Args:
            submission_id: Submission ID
            db: Database session
            
        Returns:
            Tally dictionary or None
        """
        try:
            result = await db.execute(
                select(Tally).where(Tally.submission_id == submission_id)
            )
            tally = result.scalar_one_or_none()
            
            if not tally:
                return None
            
            return {
                "tally_id": tally.id,
                "submission_id": tally.submission_id,
                "counts": {
                    "approve": tally.count_approve,
                    "escalate": tally.count_escalate,
                    "reject": tally.count_reject,
                    "flag": tally.count_flag
                },
                "total_votes": (
                    tally.count_approve + 
                    tally.count_escalate + 
                    tally.count_reject + 
                    tally.count_flag
                ),
                "decision": tally.final_decision,
                "computed_at": tally.computed_at.isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error getting tally: {e}", exc_info=True)
            return None
    
    async def should_compute_tally(
        self,
        submission_id: int,
        db: AsyncSession
    ) -> bool:
        """
        Check if submission has enough votes for tally
        
        Args:
            submission_id: Submission ID
            db: Database session
            
        Returns:
            True if should compute tally
        """
        try:
            # Count verified votes
            result = await db.execute(
                select(func.count(Vote.id))
                .where(
                    Vote.submission_id == submission_id,
                    Vote.verified == True
                )
            )
            vote_count = result.scalar()
            
            return vote_count >= settings.MIN_VOTES_FOR_TALLY
            
        except Exception as e:
            self.logger.error(f"Error checking tally threshold: {e}", exc_info=True)
            return False
    
    async def get_statistics(self, db: AsyncSession) -> Dict[str, Any]:
        """
        Get overall tally statistics
        
        Returns:
            Dictionary with statistics
        """
        try:
            # Count by decision
            result = await db.execute(
                select(
                    Tally.final_decision,
                    func.count(Tally.id)
                ).group_by(Tally.final_decision)
            )
            
            decision_counts = {}
            for decision, count in result:
                decision_counts[decision] = count
            
            # Total tallies
            total = sum(decision_counts.values())
            
            # Average votes per submission
            result = await db.execute(
                select(func.avg(
                    Tally.count_approve + 
                    Tally.count_escalate + 
                    Tally.count_reject + 
                    Tally.count_flag
                ))
            )
            avg_votes = result.scalar() or 0
            
            return {
                "total_tallies": total,
                "decision_counts": decision_counts,
                "average_votes_per_submission": float(avg_votes),
                "approval_rate": (
                    decision_counts.get(SubmissionStatus.APPROVED.value, 0) / total * 100
                    if total > 0 else 0
                )
            }
            
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}", exc_info=True)
            return {
                "total_tallies": 0,
                "decision_counts": {},
                "average_votes_per_submission": 0,
                "approval_rate": 0,
                "error": str(e)
            }
    
    async def _log_audit(
        self,
        db: AsyncSession,
        event_type: str,
        entity_type: str,
        entity_id: str,
        details: Dict[str, Any]
    ):
        """Log an audit event"""
        try:
            audit_log = AuditLog(
                event_type=event_type,
                entity_type=entity_type,
                entity_id=entity_id,
                details=details,
                timestamp=datetime.utcnow()
            )
            db.add(audit_log)
            await db.commit()
        except Exception as e:
            self.logger.error(f"Error logging audit: {e}", exc_info=True)


# Global tally service instance
_tally_service: Optional[TallyService] = None


def get_tally_service() -> TallyService:
    """Get global tally service instance"""
    global _tally_service
    if _tally_service is None:
        _tally_service = TallyService()
    return _tally_service