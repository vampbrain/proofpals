"""
Token service for managing epoch tokens and credential revocation
"""

import asyncio
import logging
import redis
import json
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.models import Token, Revocation, Reviewer
from app.config import settings

logger = logging.getLogger(__name__)

class TokenService:
    """Service for managing tokens and credential revocation"""
    
    def __init__(self):
        self.redis_client = None
        self.initialized = False
        
    async def initialize(self, redis_client: redis.Redis):
        """Initialize the token service"""
        try:
            self.redis_client = redis_client
            self.initialized = True
            logger.info("Token service initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize token service: {e}")
            raise
    
    async def cleanup(self):
        """Cleanup token service resources"""
        self.initialized = False
        self.redis_client = None
        logger.info("Token service cleaned up")
    
    async def health_check(self) -> Dict[str, Any]:
        """Check token service health"""
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
            "token_expiry_hours": settings.TOKEN_EXPIRY_HOURS
        }
    
    async def issue_epoch_tokens(
        self,
        credential_hash: str,
        epoch: int,
        count: int,
        db: Session
    ) -> List[Token]:
        """Issue epoch tokens for a credential"""
        try:
            tokens = []
            
            for _ in range(count):
                token_id = str(uuid.uuid4())
                
                token = Token(
                    token_id=token_id,
                    cred_id_hash=credential_hash,
                    epoch=epoch,
                    redeemed_bool=False
                )
                
                db.add(token)
                tokens.append(token)
                
                # Store token in Redis for fast lookup
                await self._store_token_in_redis(token)
            
            db.commit()
            logger.info(f"Issued {count} tokens for credential {credential_hash}")
            return tokens
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error issuing epoch tokens: {e}")
            raise
    
    async def verify_and_consume_token(self, token_id: str, db: Session) -> bool:
        """Atomically verify and consume a token"""
        try:
            # Use Redis Lua script for atomic operation
            lua_script = """
            local token_id = ARGV[1]
            local expiry = ARGV[2]
            
            -- Check if token exists and is not redeemed
            local token_data = redis.call('GET', 'token:' .. token_id)
            if not token_data then
                return 0
            end
            
            local token = cjson.decode(token_data)
            if token.redeemed then
                return 0
            end
            
            -- Mark as redeemed
            token.redeemed = true
            token.redeemed_at = redis.call('TIME')[1]
            
            -- Update Redis
            redis.call('SET', 'token:' .. token_id, cjson.encode(token))
            redis.call('EXPIRE', 'token:' .. token_id, expiry)
            
            return 1
            """
            
            # Execute Lua script
            result = await self.redis_client.eval(
                lua_script,
                0,  # No keys
                token_id,
                settings.TOKEN_EXPIRY_HOURS * 3600  # Expiry in seconds
            )
            
            if result == 1:
                # Update database
                token = db.query(Token).filter(Token.token_id == token_id).first()
                if token:
                    token.redeemed_bool = True
                    token.redeemed_at = datetime.utcnow()
                    db.commit()
                
                logger.info(f"Token {token_id} consumed successfully")
                return True
            else:
                logger.warning(f"Token {token_id} verification failed")
                return False
                
        except Exception as e:
            logger.error(f"Error verifying and consuming token: {e}")
            return False
    
    async def is_credential_revoked(self, credential_hash: str) -> bool:
        """Check if a credential is revoked"""
        try:
            # Check Redis cache first
            revoked = await self.redis_client.get(f"revoked:{credential_hash}")
            if revoked:
                return True
            
            # Check database
            revocation = await self._get_revocation_from_db(credential_hash)
            if revocation:
                # Cache in Redis
                await self.redis_client.setex(
                    f"revoked:{credential_hash}",
                    3600,  # 1 hour cache
                    "1"
                )
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking credential revocation: {e}")
            return False
    
    async def revoke_credential(
        self,
        credential_hash: str,
        reason: str,
        revoked_by: str,
        db: Session
    ):
        """Revoke a credential"""
        try:
            # Add to revocation list
            revocation = Revocation(
                credential_hash=credential_hash,
                reason=reason,
                revoked_by=revoked_by
            )
            
            db.add(revocation)
            db.commit()
            
            # Cache in Redis
            await self.redis_client.setex(
                f"revoked:{credential_hash}",
                3600,  # 1 hour cache
                "1"
            )
            
            # Invalidate all tokens for this credential
            await self._invalidate_credential_tokens(credential_hash)
            
            logger.info(f"Credential {credential_hash} revoked by {revoked_by}")
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error revoking credential: {e}")
            raise
    
    async def get_active_tokens_count(self, credential_hash: str) -> int:
        """Get count of active tokens for a credential"""
        try:
            # Use Redis for fast counting
            pattern = f"token:*"
            keys = await self.redis_client.keys(pattern)
            
            count = 0
            for key in keys:
                token_data = await self.redis_client.get(key)
                if token_data:
                    token = json.loads(token_data)
                    if (token.get("cred_id_hash") == credential_hash and 
                        not token.get("redeemed", False)):
                        count += 1
            
            return count
            
        except Exception as e:
            logger.error(f"Error getting active tokens count: {e}")
            return 0
    
    async def cleanup_expired_tokens(self, db: Session):
        """Clean up expired tokens"""
        try:
            expiry_time = datetime.utcnow() - timedelta(hours=settings.TOKEN_EXPIRY_HOURS)
            
            # Get expired tokens
            expired_tokens = db.query(Token).filter(
                Token.created_at < expiry_time,
                Token.redeemed_bool == False
            ).all()
            
            for token in expired_tokens:
                # Remove from Redis
                await self.redis_client.delete(f"token:{token.token_id}")
                
                # Mark as expired in database
                token.redeemed_bool = True
                token.redeemed_at = datetime.utcnow()
            
            db.commit()
            logger.info(f"Cleaned up {len(expired_tokens)} expired tokens")
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error cleaning up expired tokens: {e}")
    
    async def _store_token_in_redis(self, token: Token):
        """Store token data in Redis"""
        try:
            token_data = {
                "token_id": token.token_id,
                "cred_id_hash": token.cred_id_hash,
                "epoch": token.epoch,
                "redeemed": token.redeemed_bool,
                "created_at": token.created_at.isoformat()
            }
            
            await self.redis_client.setex(
                f"token:{token.token_id}",
                settings.TOKEN_EXPIRY_HOURS * 3600,
                json.dumps(token_data)
            )
            
        except Exception as e:
            logger.error(f"Error storing token in Redis: {e}")
    
    async def _get_revocation_from_db(self, credential_hash: str) -> Optional[Revocation]:
        """Get revocation record from database"""
        try:
            # This would need to be implemented with proper async database access
            # For now, return None as placeholder
            return None
        except Exception as e:
            logger.error(f"Error getting revocation from DB: {e}")
            return None
    
    async def _invalidate_credential_tokens(self, credential_hash: str):
        """Invalidate all tokens for a credential"""
        try:
            # Find all tokens for this credential in Redis
            pattern = f"token:*"
            keys = await self.redis_client.keys(pattern)
            
            for key in keys:
                token_data = await self.redis_client.get(key)
                if token_data:
                    token = json.loads(token_data)
                    if token.get("cred_id_hash") == credential_hash:
                        # Mark as redeemed
                        token["redeemed"] = True
                        token["redeemed_at"] = datetime.utcnow().isoformat()
                        
                        await self.redis_client.setex(
                            key,
                            3600,  # 1 hour
                            json.dumps(token)
                        )
            
            logger.info(f"Invalidated tokens for credential {credential_hash}")
            
        except Exception as e:
            logger.error(f"Error invalidating credential tokens: {e}")
    
    async def get_token_stats(self) -> Dict[str, Any]:
        """Get token statistics"""
        try:
            # Count active tokens
            pattern = f"token:*"
            keys = await self.redis_client.keys(pattern)
            
            active_count = 0
            redeemed_count = 0
            
            for key in keys:
                token_data = await self.redis_client.get(key)
                if token_data:
                    token = json.loads(token_data)
                    if token.get("redeemed", False):
                        redeemed_count += 1
                    else:
                        active_count += 1
            
            return {
                "active_tokens": active_count,
                "redeemed_tokens": redeemed_count,
                "total_tokens": active_count + redeemed_count
            }
            
        except Exception as e:
            logger.error(f"Error getting token stats: {e}")
            return {"active_tokens": 0, "redeemed_tokens": 0, "total_tokens": 0}
