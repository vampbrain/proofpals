"""
Ring service for managing voting rings
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from app.models import Ring, Submission
from app.services.crypto_service import CryptoService

logger = logging.getLogger(__name__)

class RingService:
    """Service for managing voting rings"""
    
    def __init__(self):
        self.crypto_service = None
        self.initialized = False
        
    async def initialize(self):
        """Initialize the ring service"""
        try:
            self.crypto_service = CryptoService()
            await self.crypto_service.initialize()
            self.initialized = True
            logger.info("Ring service initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize ring service: {e}")
            raise
    
    async def cleanup(self):
        """Cleanup ring service resources"""
        if self.crypto_service:
            await self.crypto_service.cleanup()
        self.initialized = False
        logger.info("Ring service cleaned up")
    
    async def health_check(self) -> Dict[str, Any]:
        """Check ring service health"""
        crypto_health = await self.crypto_service.health_check() if self.crypto_service else {}
        
        return {
            "initialized": self.initialized,
            "crypto_service": crypto_health
        }
    
    async def create_ring(
        self,
        genre: str,
        pubkeys: List[str],
        epoch: int,
        db: Session
    ) -> Ring:
        """Create a new voting ring"""
        try:
            # Validate ring size
            if len(pubkeys) < 2:
                raise ValueError("Ring must have at least 2 members")
            
            if len(pubkeys) > 1000:  # From settings.MAX_RING_SIZE
                raise ValueError("Ring size exceeds maximum limit")
            
            # Canonicalize the ring using crypto service
            canonical_pubkeys = await self.crypto_service.canonicalize_ring(
                [bytes.fromhex(pk) for pk in pubkeys]
            )
            
            # Convert back to hex strings
            canonical_pubkeys_hex = [pk.hex() for pk in canonical_pubkeys]
            
            # Create ring
            ring = Ring(
                genre=genre,
                pubkeys=canonical_pubkeys_hex,
                epoch=epoch,
                active=True
            )
            
            db.add(ring)
            db.commit()
            db.refresh(ring)
            
            logger.info(f"Created ring {ring.id} with {len(canonical_pubkeys_hex)} members")
            return ring
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error creating ring: {e}")
            raise
    
    async def get_ring(self, ring_id: int, db: Session) -> Optional[Ring]:
        """Get a ring by ID"""
        try:
            ring = db.query(Ring).filter(Ring.id == ring_id).first()
            return ring
        except Exception as e:
            logger.error(f"Error getting ring {ring_id}: {e}")
            return None
    
    async def get_active_rings(
        self,
        genre: Optional[str] = None,
        epoch: Optional[int] = None,
        db: Session = None
    ) -> List[Ring]:
        """Get active rings with optional filters"""
        try:
            query = db.query(Ring).filter(Ring.active == True)
            
            if genre:
                query = query.filter(Ring.genre == genre)
            
            if epoch:
                query = query.filter(Ring.epoch == epoch)
            
            rings = query.all()
            return rings
            
        except Exception as e:
            logger.error(f"Error getting active rings: {e}")
            return []
    
    async def get_ring_for_submission(
        self,
        submission_id: int,
        db: Session
    ) -> Optional[Ring]:
        """Get the appropriate ring for a submission"""
        try:
            # Get submission to determine genre
            submission = db.query(Submission).filter(Submission.id == submission_id).first()
            if not submission:
                return None
            
            # Get active ring for this genre
            rings = await self.get_active_rings(genre=submission.genre, db=db)
            
            if not rings:
                logger.warning(f"No active rings found for genre {submission.genre}")
                return None
            
            # Return the most recent ring
            return max(rings, key=lambda r: r.created_at)
            
        except Exception as e:
            logger.error(f"Error getting ring for submission {submission_id}: {e}")
            return None
    
    async def deactivate_ring(self, ring_id: int, db: Session) -> bool:
        """Deactivate a ring"""
        try:
            ring = db.query(Ring).filter(Ring.id == ring_id).first()
            if not ring:
                return False
            
            ring.active = False
            db.commit()
            
            logger.info(f"Deactivated ring {ring_id}")
            return True
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error deactivating ring {ring_id}: {e}")
            return False
    
    async def get_ring_statistics(self, db: Session) -> Dict[str, Any]:
        """Get ring statistics"""
        try:
            total_rings = db.query(Ring).count()
            active_rings = db.query(Ring).filter(Ring.active == True).count()
            
            # Rings by genre
            rings_by_genre = db.query(
                Ring.genre,
                db.func.count(Ring.id)
            ).group_by(Ring.genre).all()
            
            # Rings by epoch
            rings_by_epoch = db.query(
                Ring.epoch,
                db.func.count(Ring.id)
            ).group_by(Ring.epoch).all()
            
            # Average ring size
            avg_size = db.query(
                db.func.avg(db.func.json_array_length(Ring.pubkeys))
            ).scalar() or 0
            
            return {
                "total_rings": total_rings,
                "active_rings": active_rings,
                "by_genre": dict(rings_by_genre),
                "by_epoch": dict(rings_by_epoch),
                "average_size": float(avg_size)
            }
            
        except Exception as e:
            logger.error(f"Error getting ring statistics: {e}")
            return {}
    
    async def validate_ring_membership(
        self,
        ring_id: int,
        public_key: str,
        db: Session
    ) -> bool:
        """Validate if a public key is a member of a ring"""
        try:
            ring = await self.get_ring(ring_id, db)
            if not ring:
                return False
            
            return public_key in ring.pubkeys
            
        except Exception as e:
            logger.error(f"Error validating ring membership: {e}")
            return False
    
    async def get_ring_member_count(self, ring_id: int, db: Session) -> int:
        """Get the number of members in a ring"""
        try:
            ring = await self.get_ring(ring_id, db)
            if not ring:
                return 0
            
            return len(ring.pubkeys)
            
        except Exception as e:
            logger.error(f"Error getting ring member count: {e}")
            return 0
    
    async def rotate_ring(
        self,
        genre: str,
        new_pubkeys: List[str],
        epoch: int,
        db: Session
    ) -> Ring:
        """Create a new ring for the next epoch"""
        try:
            # Deactivate old rings for this genre
            old_rings = await self.get_active_rings(genre=genre, db=db)
            for ring in old_rings:
                await self.deactivate_ring(ring.id, db)
            
            # Create new ring
            new_ring = await self.create_ring(genre, new_pubkeys, epoch, db)
            
            logger.info(f"Rotated ring for genre {genre} to epoch {epoch}")
            return new_ring
            
        except Exception as e:
            logger.error(f"Error rotating ring: {e}")
            raise
    
    async def get_ring_performance_metrics(
        self,
        ring_id: int,
        db: Session
    ) -> Dict[str, Any]:
        """Get performance metrics for a ring"""
        try:
            ring = await self.get_ring(ring_id, db)
            if not ring:
                return {}
            
            # Get vote count for this ring
            from app.models import Vote
            vote_count = db.query(Vote).filter(Vote.ring_id == ring_id).count()
            
            # Get submissions that used this ring
            submission_count = db.query(Submission).join(Vote).filter(
                Vote.ring_id == ring_id
            ).distinct().count()
            
            return {
                "ring_id": ring_id,
                "genre": ring.genre,
                "epoch": ring.epoch,
                "member_count": len(ring.pubkeys),
                "vote_count": vote_count,
                "submission_count": submission_count,
                "created_at": ring.created_at,
                "active": ring.active
            }
            
        except Exception as e:
            logger.error(f"Error getting ring performance metrics: {e}")
            return {}
