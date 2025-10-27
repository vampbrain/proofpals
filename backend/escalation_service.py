
"""
ProofPals Escalation Service
Handles content escalation, evidence packaging, and trustee notifications
"""

import logging
import json
import hashlib
from typing import Optional, Dict, Any, List
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models import Escalation, Submission, Vote, AuditLog, EscalationStatus
from config import settings

logger = logging.getLogger(__name__)


class EscalationService:
    """Service for handling escalated content"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    async def create_escalation(
        self,
        submission_id: int,
        reason: str,
        db: AsyncSession,
        triggered_by: Optional[str] = None
    ) -> tuple[bool, Optional[int], Optional[str]]:
        """
        Create an escalation for a submission
        
        Args:
            submission_id: Submission to escalate
            reason: Reason for escalation
            db: Database session
            triggered_by: What triggered escalation (flags/admin/algorithm)
            
        Returns:
            Tuple of (success, escalation_id, error)
        """
        try:
            # Check if submission exists
            result = await db.execute(
                select(Submission).where(Submission.id == submission_id)
            )
            submission = result.scalar_one_or_none()
            
            if not submission:
                return False, None, "Submission not found"
            
            # Check if already escalated
            result = await db.execute(
                select(Escalation).where(
                    Escalation.submission_id == submission_id,
                    Escalation.status == EscalationStatus.PENDING
                )
            )
            existing = result.scalar_one_or_none()
            
            if existing:
                return False, existing.id, "Already escalated"
            
            # Package evidence
            evidence = await self._package_evidence(submission_id, db)
            
            # Create escalation
            escalation = Escalation(
                submission_id=submission_id,
                reason=reason,
                evidence_blob=evidence,
                status=EscalationStatus.PENDING,
                requested_at=datetime.utcnow()
            )
            
            db.add(escalation)
            
            # Update submission status
            submission.status = "escalated"
            
            await db.commit()
            await db.refresh(escalation)
            
            # Log escalation
            await self._log_audit(
                db,
                "escalation_created",
                "escalation",
                str(escalation.id),
                {
                    "submission_id": submission_id,
                    "reason": reason,
                    "triggered_by": triggered_by
                }
            )
            
            self.logger.warning(
                f"Escalation created: ID={escalation.id}, "
                f"submission={submission_id}, reason={reason}"
            )
            
            # TODO: Notify trustees
            # await self._notify_trustees(escalation.id, evidence)
            
            return True, escalation.id, None
            
        except Exception as e:
            self.logger.error(f"Error creating escalation: {e}", exc_info=True)
            await db.rollback()
            return False, None, f"Failed to create escalation: {str(e)}"
    
    async def _package_evidence(
        self,
        submission_id: int,
        db: AsyncSession
    ) -> Dict[str, Any]:
        """
        Package evidence for escalation
        
        Includes:
        - Content snapshot/hash
        - Vote distribution
        - Submitter metadata (hashed)
        - Timestamp information
        - Vote key images (for potential deanonymization by trustees)
        """
        try:
            # Get submission
            result = await db.execute(
                select(Submission).where(Submission.id == submission_id)
            )
            submission = result.scalar_one()
            
            # Get all votes
            result = await db.execute(
                select(Vote).where(Vote.submission_id == submission_id)
            )
            votes = result.scalars().all()
            
            # Count votes by type
            vote_counts = {
                "approve": 0,
                "reject": 0,
                "escalate": 0,
                "flag": 0
            }
            
            key_images = []
            for vote in votes:
                vote_counts[vote.vote_type] = vote_counts.get(vote.vote_type, 0) + 1
                key_images.append({
                    "key_image": vote.key_image,
                    "vote_type": vote.vote_type,
                    "timestamp": vote.created_at.isoformat()
                })
            
            # Package evidence
            evidence = {
                "submission": {
                    "id": submission.id,
                    "genre": submission.genre,
                    "content_ref": submission.content_ref,
                    "content_hash": hashlib.sha256(
                        submission.content_ref.encode()
                    ).hexdigest(),
                    "created_at": submission.created_at.isoformat()
                },
                "submitter": {
                    "ip_hash": submission.submitter_ip_hash,
                    "mac_hash": submission.submitter_mac_hash
                },
                "votes": {
                    "counts": vote_counts,
                    "total": len(votes),
                    "key_images": key_images
                },
                "timestamp": datetime.utcnow().isoformat(),
                "version": "1.0"
            }
            
            return evidence
            
        except Exception as e:
            self.logger.error(f"Error packaging evidence: {e}", exc_info=True)
            return {"error": str(e)}
    
    async def resolve_escalation(
        self,
        escalation_id: int,
        resolver_id: int,
        resolution: str,
        notes: Optional[str],
        db: AsyncSession
    ) -> tuple[bool, Optional[str]]:
        """
        Resolve an escalation
        
        Args:
            escalation_id: Escalation ID
            resolver_id: Admin/trustee resolving
            resolution: Resolution (approved/rejected/dismissed)
            notes: Resolution notes
            db: Database session
            
        Returns:
            Tuple of (success, error)
        """
        try:
            # Get escalation
            result = await db.execute(
                select(Escalation).where(Escalation.id == escalation_id)
            )
            escalation = result.scalar_one_or_none()
            
            if not escalation:
                return False, "Escalation not found"
            
            if escalation.status != EscalationStatus.PENDING:
                return False, f"Escalation already {escalation.status}"
            
            # Update escalation
            escalation.status = EscalationStatus.RESOLVED
            escalation.resolved_at = datetime.utcnow()
            escalation.resolver_notes = notes
            
            # Update submission status based on resolution
            result = await db.execute(
                select(Submission).where(Submission.id == escalation.submission_id)
            )
            submission = result.scalar_one()
            
            if resolution == "approved":
                submission.status = "approved"
            elif resolution == "rejected":
                submission.status = "rejected"
            elif resolution == "dismissed":
                submission.status = "pending"
            
            await db.commit()
            
            # Log resolution
            await self._log_audit(
                db,
                "escalation_resolved",
                "escalation",
                str(escalation_id),
                {
                    "escalation_id": escalation_id,
                    "resolver_id": resolver_id,
                    "resolution": resolution,
                    "has_notes": notes is not None
                }
            )
            
            self.logger.info(
                f"Escalation {escalation_id} resolved: {resolution}"
            )
            
            return True, None
            
        except Exception as e:
            self.logger.error(f"Error resolving escalation: {e}", exc_info=True)
            await db.rollback()
            return False, f"Failed to resolve: {str(e)}"
    
    async def dismiss_escalation(
        self,
        escalation_id: int,
        dismisser_id: int,
        reason: str,
        db: AsyncSession
    ) -> tuple[bool, Optional[str]]:
        """
        Dismiss an escalation as invalid
        
        Args:
            escalation_id: Escalation ID
            dismisser_id: Admin dismissing
            reason: Dismissal reason
            db: Database session
            
        Returns:
            Tuple of (success, error)
        """
        try:
            result = await db.execute(
                select(Escalation).where(Escalation.id == escalation_id)
            )
            escalation = result.scalar_one_or_none()
            
            if not escalation:
                return False, "Escalation not found"
            
            escalation.status = EscalationStatus.DISMISSED
            escalation.resolved_at = datetime.utcnow()
            escalation.resolver_notes = f"Dismissed: {reason}"
            
            # Reset submission status
            result = await db.execute(
                select(Submission).where(Submission.id == escalation.submission_id)
            )
            submission = result.scalar_one()
            submission.status = "pending"
            
            await db.commit()
            
            await self._log_audit(
                db,
                "escalation_dismissed",
                "escalation",
                str(escalation_id),
                {
                    "escalation_id": escalation_id,
                    "dismisser_id": dismisser_id,
                    "reason": reason
                }
            )
            
            return True, None
            
        except Exception as e:
            self.logger.error(f"Error dismissing escalation: {e}", exc_info=True)
            await db.rollback()
            return False, f"Failed to dismiss: {str(e)}"
    
    async def get_escalation(
        self,
        escalation_id: int,
        db: AsyncSession
    ) -> Optional[Dict[str, Any]]:
        """Get escalation details"""
        try:
            result = await db.execute(
                select(Escalation).where(Escalation.id == escalation_id)
            )
            escalation = result.scalar_one_or_none()
            
            if not escalation:
                return None
            
            return {
                "escalation_id": escalation.id,
                "submission_id": escalation.submission_id,
                "reason": escalation.reason,
                "status": escalation.status,
                "evidence": escalation.evidence_blob,
                "requested_at": escalation.requested_at.isoformat(),
                "resolved_at": (
                    escalation.resolved_at.isoformat()
                    if escalation.resolved_at else None
                ),
                "resolver_notes": escalation.resolver_notes
            }
            
        except Exception as e:
            self.logger.error(f"Error getting escalation: {e}", exc_info=True)
            return None
    
    async def list_pending_escalations(
        self,
        db: AsyncSession,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """List pending escalations"""
        try:
            result = await db.execute(
                select(Escalation)
                .where(Escalation.status == EscalationStatus.PENDING)
                .order_by(Escalation.requested_at.desc())
                .limit(limit)
            )
            escalations = result.scalars().all()
            
            return [
                {
                    "escalation_id": e.id,
                    "submission_id": e.submission_id,
                    "reason": e.reason,
                    "requested_at": e.requested_at.isoformat()
                }
                for e in escalations
            ]
            
        except Exception as e:
            self.logger.error(f"Error listing escalations: {e}", exc_info=True)
            return []
    
    async def check_auto_escalation_triggers(
        self,
        submission_id: int,
        db: AsyncSession
    ) -> tuple[bool, Optional[str]]:
        """
        Check if submission should be auto-escalated
        
        Triggers:
        - Flag count >= URGENT_FLAG_LIMIT
        - High rejection rate
        - Suspicious voting patterns
        
        Returns:
            Tuple of (should_escalate, reason)
        """
        try:
            from sqlalchemy import func
            
            # Count flags
            result = await db.execute(
                select(func.count(Vote.id))
                .where(
                    Vote.submission_id == submission_id,
                    Vote.vote_type == "flag",
                    Vote.verified == True
                )
            )
            flag_count = result.scalar()
            
            if flag_count >= settings.URGENT_FLAG_LIMIT:
                return True, f"Urgent: {flag_count} flags received"
            
            # Check vote distribution
            result = await db.execute(
                select(Vote.vote_type, func.count(Vote.id))
                .where(
                    Vote.submission_id == submission_id,
                    Vote.verified == True
                )
                .group_by(Vote.vote_type)
            )
            
            vote_dist = {row[0]: row[1] for row in result}
            total_votes = sum(vote_dist.values())
            
            if total_votes >= settings.MIN_VOTES_FOR_TALLY:
                reject_rate = vote_dist.get("reject", 0) / total_votes
                if reject_rate >= 0.7:  # 70% rejection
                    return True, f"High rejection rate: {reject_rate:.0%}"
            
            return False, None
            
        except Exception as e:
            self.logger.error(f"Error checking triggers: {e}", exc_info=True)
            return False, None
    
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


# Global escalation service instance
_escalation_service: Optional[EscalationService] = None


def get_escalation_service() -> EscalationService:
    """Get global escalation service instance"""
    global _escalation_service
    if _escalation_service is None:
        _escalation_service = EscalationService()
    return _escalation_service