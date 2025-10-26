"""
ProofPals Token Service
Atomic token verification and consumption using Redis
"""

import hashlib
import logging
from typing import Optional, List
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
import redis.asyncio as redis

from config import settings
from models import Token, Reviewer

logger = logging.getLogger(__name__)


class TokenService:
    """Service for managing epoch tokens"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.redis_client: Optional[redis.Redis] = None
    
    async def init_redis(self):
        """Initialize Redis connection"""
        if self.redis_client is None:
            self.redis_client = await redis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True
            )
            self.logger.info("Redis connection initialized")
    
    async def close_redis(self):
        """Close Redis connection"""
        if self.redis_client:
            await self.redis_client.close()
            self.logger.info("Redis connection closed")
    
    async def verify_and_consume_token(
        self, 
        token_id: str, 
        db: AsyncSession
    ) -> tuple[bool, Optional[str]]:
        """
        Atomically verify and consume a token
        
        This is the CRITICAL function that prevents double-spending.
        Uses Redis SETNX for atomic locking.
        
        Args:
            token_id: The token identifier to consume
            db: Database session
            
        Returns:
            Tuple of (success: bool, error_message: Optional[str])
        """
        if not self.redis_client:
            await self.init_redis()
        
        redis_key = f"token:{token_id}"
        
        try:
            # STEP 1: Atomic lock using Redis SETNX
            # This returns True only if key didn't exist (first request wins)
            lock_acquired = await self.redis_client.set(
                redis_key,
                "consumed",
                nx=True,  # Only set if not exists
                ex=settings.REDIS_TOKEN_EXPIRY  # Expire after 5 minutes
            )
            
            if not lock_acquired:
                self.logger.warning(f"Token {token_id} already consumed (Redis lock failed)")
                return False, "Token already consumed"
            
            # STEP 2: Verify token exists in database
            result = await db.execute(
                select(Token).where(
                    Token.token_id == token_id,
                    Token.redeemed == False
                )
            )
            token = result.scalar_one_or_none()
            
            if not token:
                # Token doesn't exist or already redeemed in DB
                self.logger.warning(f"Token {token_id} not found or already redeemed in DB")
                return False, "Invalid or already redeemed token"
            
            # STEP 3: Check if credential is revoked
            result = await db.execute(
                select(Reviewer).where(
                    Reviewer.credential_hash == token.credential_hash,
                    Reviewer.revoked == False
                )
            )
            reviewer = result.scalar_one_or_none()
            
            if not reviewer:
                self.logger.warning(f"Token {token_id} belongs to revoked credential")
                return False, "Credential has been revoked"
            
            # STEP 4: Mark token as redeemed in database
            await db.execute(
                update(Token)
                .where(Token.token_id == token_id)
                .values(
                    redeemed=True,
                    redeemed_at=datetime.utcnow()
                )
            )
            
            await db.commit()
            
            self.logger.info(f"Token {token_id} successfully consumed")
            return True, None
            
        except Exception as e:
            self.logger.error(f"Error consuming token {token_id}: {e}", exc_info=True)
            await db.rollback()
            
            # Release Redis lock on error
            await self.redis_client.delete(redis_key)
            
            return False, f"Token consumption failed: {str(e)}"
    
    async def create_epoch_tokens(
        self,
        credential_hash: str,
        epoch: int,
        token_count: int,
        db: AsyncSession
    ) -> tuple[bool, List[str], Optional[str]]:
        """
        Create multiple epoch tokens for a credential
        
        Args:
            credential_hash: Hash of the blind credential
            epoch: Current epoch number
            token_count: Number of tokens to create
            db: Database session
            
        Returns:
            Tuple of (success: bool, token_ids: List[str], error: Optional[str])
        """
        try:
            # Verify credential exists and is not revoked
            result = await db.execute(
                select(Reviewer).where(
                    Reviewer.credential_hash == credential_hash,
                    Reviewer.revoked == False
                )
            )
            reviewer = result.scalar_one_or_none()
            
            if not reviewer:
                self.logger.warning(f"Credential {credential_hash} not found or revoked")
                return False, [], "Invalid or revoked credential"
            
            # Generate unique token IDs
            token_ids = []
            tokens = []
            
            for i in range(token_count):
                # Create deterministic but unique token ID
                token_data = f"{credential_hash}:{epoch}:{i}:{datetime.utcnow().isoformat()}"
                token_id = hashlib.sha256(token_data.encode()).hexdigest()
                token_ids.append(token_id)
                
                # Create token object
                token = Token(
                    token_id=token_id,
                    credential_hash=credential_hash,
                    epoch=epoch,
                    redeemed=False
                )
                tokens.append(token)
            
            # Insert all tokens
            db.add_all(tokens)
            await db.commit()
            
            self.logger.info(
                f"Created {token_count} epoch tokens for credential {credential_hash[:16]}... "
                f"in epoch {epoch}"
            )
            
            return True, token_ids, None
            
        except Exception as e:
            self.logger.error(f"Error creating epoch tokens: {e}", exc_info=True)
            await db.rollback()
            return False, [], f"Token creation failed: {str(e)}"
    
    async def check_token_validity(
        self,
        token_id: str,
        db: AsyncSession
    ) -> tuple[bool, Optional[str]]:
        """
        Check if a token is valid (exists and not redeemed)
        
        Args:
            token_id: Token identifier
            db: Database session
            
        Returns:
            Tuple of (is_valid: bool, error: Optional[str])
        """
        try:
            result = await db.execute(
                select(Token).where(
                    Token.token_id == token_id,
                    Token.redeemed == False
                )
            )
            token = result.scalar_one_or_none()
            
            if not token:
                return False, "Token not found or already redeemed"
            
            # Check if credential is revoked
            result = await db.execute(
                select(Reviewer).where(
                    Reviewer.credential_hash == token.credential_hash,
                    Reviewer.revoked == False
                )
            )
            reviewer = result.scalar_one_or_none()
            
            if not reviewer:
                return False, "Credential has been revoked"
            
            return True, None
            
        except Exception as e:
            self.logger.error(f"Error checking token validity: {e}", exc_info=True)
            return False, f"Validation failed: {str(e)}"
    
    async def get_token_stats(self, db: AsyncSession) -> dict:
        """
        Get token statistics
        
        Returns:
            Dictionary with token statistics
        """
        try:
            from sqlalchemy import func
            
            # Total tokens
            result = await db.execute(select(func.count(Token.token_id)))
            total = result.scalar()
            
            # Redeemed tokens
            result = await db.execute(
                select(func.count(Token.token_id)).where(Token.redeemed == True)
            )
            redeemed = result.scalar()
            
            # Available tokens
            available = total - redeemed
            
            return {
                "total": total,
                "redeemed": redeemed,
                "available": available,
                "redemption_rate": (redeemed / total * 100) if total > 0 else 0
            }
            
        except Exception as e:
            self.logger.error(f"Error getting token stats: {e}", exc_info=True)
            return {
                "total": 0,
                "redeemed": 0,
                "available": 0,
                "redemption_rate": 0,
                "error": str(e)
            }


# Global token service instance
_token_service: Optional[TokenService] = None


def get_token_service() -> TokenService:
    """Get global token service instance"""
    global _token_service
    if _token_service is None:
        _token_service = TokenService()
    return _token_service