
"""
ProofPals Monitoring Service
Real-time metrics, anomaly detection, and system health monitoring
"""

import logging
import time
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from collections import defaultdict, deque
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from models import Vote, Token, Submission, Escalation, AuditLog
from config import settings

logger = logging.getLogger(_name_)


class MetricsCollector:
    """Collects and stores application metrics"""
    
    def _init_(self):
        self.counters = defaultdict(int)
        self.gauges = defaultdict(float)
        self.histograms = defaultdict(list)
        self.timeseries = defaultdict(lambda: deque(maxlen=1000))
        
    def increment(self, metric: str, value: int = 1):
        """Increment a counter"""
        self.counters[metric] += value
        
    def set_gauge(self, metric: str, value: float):
        """Set a gauge value"""
        self.gauges[metric] = value
        
    def record_timing(self, metric: str, duration_ms: float):
        """Record a timing measurement"""
        self.histograms[metric].append(duration_ms)
        self.timeseries[metric].append({
            "timestamp": time.time(),
            "value": duration_ms
        })
        
    def get_metrics(self) -> Dict[str, Any]:
        """Get all metrics"""
        return {
            "counters": dict(self.counters),
            "gauges": dict(self.gauges),
            "histograms": {
                name: {
                    "count": len(values),
                    "min": min(values) if values else 0,
                    "max": max(values) if values else 0,
                    "avg": sum(values) / len(values) if values else 0
                }
                for name, values in self.histograms.items()
            }
        }


class AnomalyDetector:
    """Detects anomalous patterns in voting and submissions"""
    
    def _init_(self):
        self.logger = logging.getLogger(f"{_name}.{self.class.name_}")
        self.alert_history = deque(maxlen=100)
        
    async def detect_flag_burst(
        self,
        db: AsyncSession,
        window_minutes: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Detect sudden bursts of flag votes
        
        Args:
            db: Database session
            window_minutes: Time window to check
            
        Returns:
            List of anomalies detected
        """
        try:
            window_start = datetime.utcnow() - timedelta(minutes=window_minutes)
            
            # Count flags in time window
            result = await db.execute(
                select(Vote.submission_id, func.count(Vote.id).label('flag_count'))
                .where(
                    Vote.vote_type == "flag",
                    Vote.created_at >= window_start,
                    Vote.verified == True
                )
                .group_by(Vote.submission_id)
                .having(func.count(Vote.id) >= settings.URGENT_FLAG_LIMIT)
            )
            
            anomalies = []
            for row in result:
                submission_id, flag_count = row
                anomaly = {
                    "type": "flag_burst",
                    "submission_id": submission_id,
                    "flag_count": flag_count,
                    "window_minutes": window_minutes,
                    "severity": "high",
                    "detected_at": datetime.utcnow().isoformat()
                }
                anomalies.append(anomaly)
                self.alert_history.append(anomaly)
            
            if anomalies:
                self.logger.warning(f"Flag burst detected: {len(anomalies)} submissions")
            
            return anomalies
            
        except Exception as e:
            self.logger.error(f"Error detecting flag burst: {e}", exc_info=True)
            return []
    
    async def detect_token_abuse(
        self,
        db: AsyncSession,
        window_minutes: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Detect suspicious token consumption patterns
        
        Args:
            db: Database session
            window_minutes: Time window to check
            
        Returns:
            List of anomalies
        """
        try:
            window_start = datetime.utcnow() - timedelta(minutes=window_minutes)
            
            # Find credentials with high token consumption rate
            result = await db.execute(
                select(Token.credential_hash, func.count(Token.token_id).label('redeemed_count'))
                .where(
                    Token.redeemed == True,
                    Token.redeemed_at >= window_start
                )
                .group_by(Token.credential_hash)
                .having(func.count(Token.token_id) > 10)  # More than 10 in 5 minutes
            )
            
            anomalies = []
            for row in result:
                credential_hash, redeemed_count = row
                anomaly = {
                    "type": "token_abuse",
                    "credential_hash": credential_hash[:16],
                    "redeemed_count": redeemed_count,
                    "window_minutes": window_minutes,
                    "severity": "medium",
                    "detected_at": datetime.utcnow().isoformat()
                }
                anomalies.append(anomaly)
                self.alert_history.append(anomaly)
            
            if anomalies:
                self.logger.warning(f"Token abuse detected: {len(anomalies)} credentials")
            
            return anomalies
            
        except Exception as e:
            self.logger.error(f"Error detecting token abuse: {e}", exc_info=True)
            return []
    
    async def detect_key_image_collisions(
        self,
        db: AsyncSession
    ) -> List[Dict[str, Any]]:
        """
        Detect suspicious key image reuse across submissions
        
        Returns:
            List of anomalies
        """
        try:
            # Find key images used across multiple submissions
            result = await db.execute(
                select(Vote.key_image, func.count(func.distinct(Vote.submission_id)).label('submission_count'))
                .where(Vote.verified == True)
                .group_by(Vote.key_image)
                .having(func.count(func.distinct(Vote.submission_id)) > 1)
            )
            
            anomalies = []
            for row in result:
                key_image, submission_count = row
                # This is expected behavior (same credential voting on different submissions)
                # Only flag if count is suspiciously high
                if submission_count > 100:  # Threshold
                    anomaly = {
                        "type": "key_image_reuse",
                        "key_image": key_image[:16],
                        "submission_count": submission_count,
                        "severity": "low",
                        "detected_at": datetime.utcnow().isoformat()
                    }
                    anomalies.append(anomaly)
                    self.alert_history.append(anomaly)
            
            return anomalies
            
        except Exception as e:
            self.logger.error(f"Error detecting key image collisions: {e}", exc_info=True)
            return []
    
    async def detect_vote_patterns(
        self,
        submission_id: int,
        db: AsyncSession
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze voting patterns for a specific submission
        
        Args:
            submission_id: Submission to analyze
            db: Database session
            
        Returns:
            Pattern analysis or None
        """
        try:
            # Get all votes for submission
            result = await db.execute(
                select(Vote)
                .where(
                    Vote.submission_id == submission_id,
                    Vote.verified == True
                )
                .order_by(Vote.created_at)
            )
            votes = result.scalars().all()
            
            if len(votes) < 5:
                return None
            
            # Analyze timing
            timestamps = [v.created_at.timestamp() for v in votes]
            time_diffs = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            avg_time_diff = sum(time_diffs) / len(time_diffs) if time_diffs else 0
            
            # Analyze vote types
            vote_types = [v.vote_type for v in votes]
            type_counts = {vt: vote_types.count(vt) for vt in set(vote_types)}
            
            # Check for suspicious patterns
            suspicious = False
            reasons = []
            
            # All votes within very short time (< 1 second apart on average)
            if avg_time_diff < 1:
                suspicious = True
                reasons.append("Votes submitted too rapidly")
            
            # Extreme vote concentration (>90% same type)
            if max(type_counts.values()) / len(votes) > 0.9:
                suspicious = True
                reasons.append("Extreme vote concentration")
            
            if suspicious:
                return {
                    "submission_id": submission_id,
                    "vote_count": len(votes),
                    "avg_time_diff_seconds": avg_time_diff,
                    "vote_distribution": type_counts,
                    "suspicious": True,
                    "reasons": reasons
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error analyzing vote patterns: {e}", exc_info=True)
            return None


class MonitoringService:
    """Main monitoring service coordinating all monitoring activities"""
    
    def _init_(self):
        self.logger = logging.getLogger(f"{_name}.{self.class.name_}")
        self.metrics = MetricsCollector()
        self.anomaly_detector = AnomalyDetector()
        self.start_time = time.time()
        
    async def get_system_health(self, db: AsyncSession) -> Dict[str, Any]:
        """
        Get comprehensive system health status
        
        Returns:
            Health status dictionary
        """
        try:
            health = {
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "uptime_seconds": time.time() - self.start_time,
                "components": {}
            }
            
            # Database health
            try:
                result = await db.execute(select(func.count(Submission.id)))
                submission_count = result.scalar()
                health["components"]["database"] = {
                    "status": "healthy",
                    "submission_count": submission_count
                }
            except Exception as e:
                health["components"]["database"] = {
                    "status": "unhealthy",
                    "error": str(e)
                }
                health["status"] = "degraded"
            
            # Crypto library health
            try:
                import pp_clsag_core
                seed = pp_clsag_core.generate_seed()
                health["components"]["crypto"] = {
                    "status": "healthy",
                    "library": "pp_clsag_core"
                }
            except Exception as e:
                health["components"]["crypto"] = {
                    "status": "unhealthy",
                    "error": str(e)
                }
                health["status"] = "degraded"
            
            # Redis health (token service)
            try:
                from token_service import get_token_service
                token_service = get_token_service()
                if token_service.redis_client:
                    await token_service.redis_client.ping()
                    health["components"]["redis"] = {"status": "healthy"}
                else:
                    health["components"]["redis"] = {"status": "not_initialized"}
            except Exception as e:
                health["components"]["redis"] = {
                    "status": "unhealthy",
                    "error": str(e)
                }
                health["status"] = "degraded"
            
            return health
            
        except Exception as e:
            self.logger.error(f"Error getting system health: {e}", exc_info=True)
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def get_statistics(self, db: AsyncSession) -> Dict[str, Any]:
        """
        Get comprehensive system statistics
        
        Returns:
            Statistics dictionary
        """
        try:
            stats = {
                "timestamp": datetime.utcnow().isoformat(),
                "submissions": await self._get_submission_stats(db),
                "votes": await self._get_vote_stats(db),
                "tokens": await self._get_token_stats(db),
                "escalations": await self._get_escalation_stats(db),
                "performance": self.metrics.get_metrics()
            }
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}", exc_info=True)
            return {"error": str(e)}
    
    async def _get_submission_stats(self, db: AsyncSession) -> Dict[str, Any]:
        """Get submission statistics"""
        try:
            # Total submissions
            result = await db.execute(select(func.count(Submission.id)))
            total = result.scalar()
            
            # By status
            result = await db.execute(
                select(Submission.status, func.count(Submission.id))
                .group_by(Submission.status)
            )
            by_status = {row[0]: row[1] for row in result}
            
            # By genre
            result = await db.execute(
                select(Submission.genre, func.count(Submission.id))
                .group_by(Submission.genre)
            )
            by_genre = {row[0]: row[1] for row in result}
            
            return {
                "total": total,
                "by_status": by_status,
                "by_genre": by_genre
            }
        except Exception as e:
            self.logger.error(f"Error getting submission stats: {e}")
            return {}
    
    async def _get_vote_stats(self, db: AsyncSession) -> Dict[str, Any]:
        """Get vote statistics"""
        try:
            # Total votes
            result = await db.execute(select(func.count(Vote.id)))
            total = result.scalar()
            
            # By type
            result = await db.execute(
                select(Vote.vote_type, func.count(Vote.id))
                .where(Vote.verified == True)
                .group_by(Vote.vote_type)
            )
            by_type = {row[0]: row[1] for row in result}
            
            # Verified vs unverified
            result = await db.execute(
                select(Vote.verified, func.count(Vote.id))
                .group_by(Vote.verified)
            )
            by_verification = {
                ("verified" if row[0] else "unverified"): row[1]
                for row in result
            }
            
            return {
                "total": total,
                "by_type": by_type,
                "by_verification": by_verification
            }
        except Exception as e:
            self.logger.error(f"Error getting vote stats: {e}")
            return {}
    
    async def _get_token_stats(self, db: AsyncSession) -> Dict[str, Any]:
        """Get token statistics"""
        try:
            # Total tokens
            result = await db.execute(select(func.count(Token.token_id)))
            total = result.scalar()
            
            # Redeemed vs available
            result = await db.execute(
                select(Token.redeemed, func.count(Token.token_id))
                .group_by(Token.redeemed)
            )
            by_status = {
                ("redeemed" if row[0] else "available"): row[1]
                for row in result
            }
            
            # Redemption rate
            redeemed = by_status.get("redeemed", 0)
            redemption_rate = (redeemed / total * 100) if total > 0 else 0
            
            return {
                "total": total,
                "by_status": by_status,
                "redemption_rate": redemption_rate
            }
        except Exception as e:
            self.logger.error(f"Error getting token stats: {e}")
            return {}
    
    async def _get_escalation_stats(self, db: AsyncSession) -> Dict[str, Any]:
        """Get escalation statistics"""
        try:
            # Total escalations
            result = await db.execute(select(func.count(Escalation.id)))
            total = result.scalar()
            
            # By status
            result = await db.execute(
                select(Escalation.status, func.count(Escalation.id))
                .group_by(Escalation.status)
            )
            by_status = {row[0]: row[1] for row in result}
            
            return {
                "total": total,
                "by_status": by_status
            }
        except Exception as e:
            self.logger.error(f"Error getting escalation stats: {e}")
            return {}
    
    async def run_anomaly_checks(self, db: AsyncSession) -> Dict[str, Any]:
        """
        Run all anomaly detection checks
        
        Returns:
            Anomaly detection results
        """
        try:
            anomalies = {
                "timestamp": datetime.utcnow().isoformat(),
                "flag_bursts": await self.anomaly_detector.detect_flag_burst(db),
                "token_abuse": await self.anomaly_detector.detect_token_abuse(db),
                "key_image_issues": await self.anomaly_detector.detect_key_image_collisions(db)
            }
            
            total_anomalies = sum(
                len(v) for v in anomalies.values() if isinstance(v, list)
            )
            
            anomalies["summary"] = {
                "total_anomalies": total_anomalies,
                "requires_attention": total_anomalies > 0
            }
            
            return anomalies
            
        except Exception as e:
            self.logger.error(f"Error running anomaly checks: {e}", exc_info=True)
            return {"error": str(e)}
    
    def record_operation(self, operation: str, duration_ms: float):
        """Record an operation timing"""
        self.metrics.record_timing(operation, duration_ms)
        self.metrics.increment(f"{operation}_count")
    
    def increment_counter(self, counter: str, value: int = 1):
        """Increment a counter"""
        self.metrics.increment(counter, value)


# Global monitoring service instance
_monitoring_service: Optional[MonitoringService] = None


def get_monitoring_service() -> MonitoringService:
    """Get global monitoring service instance"""
    global _monitoring_service
    if _monitoring_service is None:
        _monitoring_service = MonitoringService()
    return _monitoring_service