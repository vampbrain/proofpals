"""
Monitoring service for logging and metrics
"""

import asyncio
import logging
import json
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from app.models import AuditLog, Submission, Vote, Ring, Token, Escalation

logger = logging.getLogger(__name__)

class MonitoringService:
    """Service for monitoring and logging"""
    
    def __init__(self):
        self.initialized = False
        
    async def initialize(self):
        """Initialize the monitoring service"""
        try:
            self.initialized = True
            logger.info("Monitoring service initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize monitoring service: {e}")
            raise
    
    async def cleanup(self):
        """Cleanup monitoring service resources"""
        self.initialized = False
        logger.info("Monitoring service cleaned up")
    
    async def health_check(self) -> Dict[str, Any]:
        """Check monitoring service health"""
        return {
            "initialized": self.initialized,
            "log_level": logging.getLogger().level
        }
    
    async def log_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        db: Session = None
    ):
        """Log an audit event"""
        try:
            audit_log = AuditLog(
                event_type=event_type,
                user_id=user_id,
                data=data
            )
            
            if db:
                db.add(audit_log)
                db.commit()
            
            # Also log to application logger
            logger.info(f"Audit event: {event_type} by {user_id or 'system'}")
            
        except Exception as e:
            logger.error(f"Error logging event: {e}")
    
    async def get_events(
        self,
        event_type: Optional[str] = None,
        limit: int = 100,
        db: Session = None
    ) -> List[Dict[str, Any]]:
        """Get audit events"""
        try:
            query = db.query(AuditLog)
            
            if event_type:
                query = query.filter(AuditLog.event_type == event_type)
            
            events = query.order_by(desc(AuditLog.created_at)).limit(limit).all()
            
            return [
                {
                    "id": event.id,
                    "event_type": event.event_type,
                    "user_id": event.user_id,
                    "data": event.data,
                    "created_at": event.created_at
                }
                for event in events
            ]
            
        except Exception as e:
            logger.error(f"Error getting events: {e}")
            return []
    
    async def get_metrics(self, db: Session) -> Dict[str, Any]:
        """Get system metrics"""
        try:
            # Basic counts
            total_submissions = db.query(Submission).count()
            total_votes = db.query(Vote).count()
            total_rings = db.query(Ring).count()
            active_tokens = db.query(Token).filter(Token.redeemed_bool == False).count()
            pending_escalations = db.query(Escalation).filter(
                Escalation.status == "pending"
            ).count()
            
            # Votes by type
            votes_by_type = db.query(
                Vote.vote_type,
                func.count(Vote.id)
            ).filter(Vote.verified_bool == True).group_by(Vote.vote_type).all()
            
            # Submissions by status
            submissions_by_status = db.query(
                Submission.status,
                func.count(Submission.id)
            ).group_by(Submission.status).all()
            
            # Recent activity (last 24 hours)
            recent_time = datetime.utcnow() - timedelta(hours=24)
            recent_submissions = db.query(Submission).filter(
                Submission.created_at >= recent_time
            ).count()
            recent_votes = db.query(Vote).filter(
                Vote.created_at >= recent_time
            ).count()
            
            # System uptime (placeholder)
            system_uptime = 0.0  # Would be calculated from actual startup time
            
            return {
                "total_submissions": total_submissions,
                "total_votes": total_votes,
                "total_rings": total_rings,
                "active_tokens": active_tokens,
                "pending_escalations": pending_escalations,
                "votes_by_type": dict(votes_by_type),
                "submissions_by_status": dict(submissions_by_status),
                "recent_activity": {
                    "submissions_24h": recent_submissions,
                    "votes_24h": recent_votes
                },
                "system_uptime": system_uptime,
                "last_updated": datetime.utcnow()
            }
            
        except Exception as e:
            logger.error(f"Error getting metrics: {e}")
            return {}
    
    async def get_performance_metrics(self, db: Session) -> Dict[str, Any]:
        """Get performance metrics"""
        try:
            # Average votes per submission
            avg_votes_per_submission = db.query(
                func.avg(func.count(Vote.id))
            ).join(Submission).group_by(Vote.submission_id).scalar() or 0
            
            # Average ring size
            avg_ring_size = db.query(
                func.avg(func.json_array_length(Ring.pubkeys))
            ).scalar() or 0
            
            # Vote verification rate
            total_votes = db.query(Vote).count()
            verified_votes = db.query(Vote).filter(Vote.verified_bool == True).count()
            verification_rate = (verified_votes / total_votes * 100) if total_votes > 0 else 0
            
            # Token redemption rate
            total_tokens = db.query(Token).count()
            redeemed_tokens = db.query(Token).filter(Token.redeemed_bool == True).count()
            redemption_rate = (redeemed_tokens / total_tokens * 100) if total_tokens > 0 else 0
            
            return {
                "avg_votes_per_submission": float(avg_votes_per_submission),
                "avg_ring_size": float(avg_ring_size),
                "verification_rate": float(verification_rate),
                "redemption_rate": float(redemption_rate),
                "total_votes": total_votes,
                "verified_votes": verified_votes,
                "total_tokens": total_tokens,
                "redeemed_tokens": redeemed_tokens
            }
            
        except Exception as e:
            logger.error(f"Error getting performance metrics: {e}")
            return {}
    
    async def get_security_metrics(self, db: Session) -> Dict[str, Any]:
        """Get security-related metrics"""
        try:
            # Duplicate vote attempts
            duplicate_attempts = db.query(AuditLog).filter(
                AuditLog.event_type == "duplicate_vote_attempt"
            ).count()
            
            # Failed signature verifications
            failed_verifications = db.query(AuditLog).filter(
                AuditLog.event_type == "signature_verification_failed"
            ).count()
            
            # Revoked credentials
            revoked_credentials = db.query(AuditLog).filter(
                AuditLog.event_type == "credential_revoked"
            ).count()
            
            # Escalation events
            escalation_events = db.query(AuditLog).filter(
                AuditLog.event_type == "escalation_triggered"
            ).count()
            
            return {
                "duplicate_vote_attempts": duplicate_attempts,
                "failed_verifications": failed_verifications,
                "revoked_credentials": revoked_credentials,
                "escalation_events": escalation_events
            }
            
        except Exception as e:
            logger.error(f"Error getting security metrics: {e}")
            return {}
    
    async def log_security_event(
        self,
        event_type: str,
        details: Dict[str, Any],
        user_id: Optional[str] = None,
        db: Session = None
    ):
        """Log a security-related event"""
        try:
            await self.log_event(
                event_type=event_type,
                user_id=user_id,
                data={
                    "security_event": True,
                    "details": details,
                    "timestamp": datetime.utcnow().isoformat()
                },
                db=db
            )
            
            # Log to security logger
            logger.warning(f"Security event: {event_type} - {details}")
            
        except Exception as e:
            logger.error(f"Error logging security event: {e}")
    
    async def get_audit_trail(
        self,
        user_id: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 1000,
        db: Session = None
    ) -> List[Dict[str, Any]]:
        """Get comprehensive audit trail"""
        try:
            query = db.query(AuditLog)
            
            if user_id:
                query = query.filter(AuditLog.user_id == user_id)
            
            if start_date:
                query = query.filter(AuditLog.created_at >= start_date)
            
            if end_date:
                query = query.filter(AuditLog.created_at <= end_date)
            
            events = query.order_by(desc(AuditLog.created_at)).limit(limit).all()
            
            return [
                {
                    "id": event.id,
                    "event_type": event.event_type,
                    "user_id": event.user_id,
                    "data": event.data,
                    "created_at": event.created_at,
                    "is_security_event": event.data.get("security_event", False) if event.data else False
                }
                for event in events
            ]
            
        except Exception as e:
            logger.error(f"Error getting audit trail: {e}")
            return []
    
    async def cleanup_old_logs(self, days: int = 30, db: Session = None):
        """Clean up old audit logs"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            deleted_count = db.query(AuditLog).filter(
                AuditLog.created_at < cutoff_date
            ).delete()
            
            db.commit()
            
            logger.info(f"Cleaned up {deleted_count} old audit logs")
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error cleaning up old logs: {e}")
    
    async def export_audit_logs(
        self,
        start_date: datetime,
        end_date: datetime,
        db: Session
    ) -> List[Dict[str, Any]]:
        """Export audit logs for external analysis"""
        try:
            events = await self.get_audit_trail(
                start_date=start_date,
                end_date=end_date,
                limit=10000,  # Large limit for export
                db=db
            )
            
            return events
            
        except Exception as e:
            logger.error(f"Error exporting audit logs: {e}")
            return []
