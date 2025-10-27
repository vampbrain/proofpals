
"""
ProofPals Vetter Service
Handles blind signature issuance for reviewer credentials
"""

import logging
import hashlib
from typing import Optional, Dict, Any, Tuple
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models import Reviewer, AuditLog
from config import settings

logger = logging.getLogger(__name__)

try:
    import pp_clsag_core
    CRYPTO_AVAILABLE = True
except ImportError:
    logger.error("pp_clsag_core not available")
    CRYPTO_AVAILABLE = False


class VetterService:
    """Service for vetter operations and blind signature issuance"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("Crypto library not available")
        
        # Server keypair for blind signatures (2048-bit RSA)
        self.server_keypair = None
        self.public_key_bytes = None
    
    def initialize_server_keypair(self, bits: int = 2048):
        """
        Initialize server RSA keypair for blind signatures
        
        Args:
            bits: RSA key size (default 2048)
        """
        try:
            self.logger.info(f"Generating {bits}-bit RSA keypair for blind signatures...")
            self.server_keypair = pp_clsag_core.BlindRsaKeyPair(bits)
            self.public_key_bytes = self.server_keypair.export_public_key()
            self.logger.info("Server keypair initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize server keypair: {e}", exc_info=True)
            raise
    
    def get_public_key(self) -> bytes:
        """
        Get server's public key for client blinding
        
        Returns:
            Public key bytes
        """
        if not self.public_key_bytes:
            raise RuntimeError("Server keypair not initialized")
        
        return self.public_key_bytes
    
    async def issue_blind_signature(
        self,
        blinded_message: bytes,
        vetter_id: int,
        db: AsyncSession,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, Optional[bytes], Optional[str]]:
        """
        Issue a blind signature on a blinded message
        
        This is the core vetter operation. The vetter signs a blinded message
        without knowing what they're signing, enabling unlinkable credentials.
        
        Args:
            blinded_message: The blinded message from client
            vetter_id: ID of vetter issuing signature
            db: Database session
            metadata: Optional metadata about the issuance
            
        Returns:
            Tuple of (success, signature_bytes, error_message)
        """
        try:
            if not self.server_keypair:
                return False, None, "Server keypair not initialized"
            
            # Sign the blinded message
            blind_signature = self.server_keypair.sign_blinded_message(blinded_message)
            signature_bytes = blind_signature.get_signature()
            
            # Log the issuance for audit
            await self._log_audit(
                db,
                "blind_signature_issued",
                "blind_signature",
                f"vetter_{vetter_id}",
                {
                    "vetter_id": vetter_id,
                    "blinded_message_hash": hashlib.sha256(blinded_message).hexdigest()[:16],
                    "metadata": metadata or {}
                }
            )
            
            self.logger.info(
                f"Blind signature issued by vetter {vetter_id}"
            )
            
            return True, signature_bytes, None
            
        except Exception as e:
            self.logger.error(f"Error issuing blind signature: {e}", exc_info=True)
            return False, None, f"Failed to issue signature: {str(e)}"
    
    async def register_credential(
        self,
        credential_hash: str,
        profile_hash: Optional[str],
        credential_meta: Optional[Dict[str, Any]],
        db: AsyncSession
    ) -> Tuple[bool, Optional[int], Optional[str]]:
        """
        Register a new reviewer credential
        
        This stores the credential hash after the client has unblinded
        their signature and derived their credential.
        
        Args:
            credential_hash: Hash of the credential
            profile_hash: Optional profile identifier
            credential_meta: Optional encrypted metadata
            db: Database session
            
        Returns:
            Tuple of (success, reviewer_id, error_message)
        """
        try:
            # Check if credential already exists
            result = await db.execute(
                select(Reviewer).where(
                    Reviewer.credential_hash == credential_hash
                )
            )
            existing = result.scalar_one_or_none()
            
            if existing:
                return False, None, "Credential already registered"
            
            # Create new reviewer record
            reviewer = Reviewer(
                credential_hash=credential_hash,
                profile_hash=profile_hash,
                credential_meta=credential_meta,
                revoked=False,
                created_at=datetime.utcnow()
            )
            
            db.add(reviewer)
            await db.commit()
            await db.refresh(reviewer)
            
            # Log registration
            await self._log_audit(
                db,
                "credential_registered",
                "reviewer",
                str(reviewer.id),
                {
                    "credential_hash": credential_hash[:16],
                    "has_profile": profile_hash is not None
                }
            )
            
            self.logger.info(
                f"Credential registered: reviewer_id={reviewer.id}"
            )
            
            return True, reviewer.id, None
            
        except Exception as e:
            self.logger.error(f"Error registering credential: {e}", exc_info=True)
            await db.rollback()
            return False, None, f"Registration failed: {str(e)}"
    
    async def verify_credential(
        self,
        credential_hash: str,
        db: AsyncSession
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """
        Verify a credential is valid and not revoked
        
        Args:
            credential_hash: Credential hash to verify
            db: Database session
            
        Returns:
            Tuple of (is_valid, credential_info, error_message)
        """
        try:
            result = await db.execute(
                select(Reviewer).where(
                    Reviewer.credential_hash == credential_hash
                )
            )
            reviewer = result.scalar_one_or_none()
            
            if not reviewer:
                return False, None, "Credential not found"
            
            if reviewer.revoked:
                return False, None, "Credential has been revoked"
            
            credential_info = {
                "reviewer_id": reviewer.id,
                "credential_hash": reviewer.credential_hash,
                "created_at": reviewer.created_at.isoformat(),
                "revoked": reviewer.revoked
            }
            
            return True, credential_info, None
            
        except Exception as e:
            self.logger.error(f"Error verifying credential: {e}", exc_info=True)
            return False, None, f"Verification failed: {str(e)}"
    
    async def revoke_credential(
        self,
        credential_hash: str,
        reason: str,
        revoked_by: int,
        evidence: Optional[str],
        db: AsyncSession
    ) -> Tuple[bool, Optional[str]]:
        """
        Revoke a credential
        
        Args:
            credential_hash: Credential to revoke
            reason: Reason for revocation
            revoked_by: ID of vetter/admin revoking
            evidence: Optional evidence for revocation
            db: Database session
            
        Returns:
            Tuple of (success, error_message)
        """
        try:
            from models import Revocation
            
            # Find reviewer
            result = await db.execute(
                select(Reviewer).where(
                    Reviewer.credential_hash == credential_hash
                )
            )
            reviewer = result.scalar_one_or_none()
            
            if not reviewer:
                return False, "Credential not found"
            
            if reviewer.revoked:
                return False, "Credential already revoked"
            
            # Mark as revoked
            reviewer.revoked = True
            
            # Create revocation record
            revocation = Revocation(
                credential_hash=credential_hash,
                reason=reason,
                evidence=evidence,
                revoked_at=datetime.utcnow(),
                revoked_by=str(revoked_by)
            )
            
            db.add(revocation)
            await db.commit()
            
            # Log revocation
            await self._log_audit(
                db,
                "credential_revoked",
                "reviewer",
                str(reviewer.id),
                {
                    "credential_hash": credential_hash[:16],
                    "reason": reason,
                    "revoked_by": revoked_by
                }
            )
            
            self.logger.warning(
                f"Credential revoked: {credential_hash[:16]}... "
                f"Reason: {reason}"
            )
            
            return True, None
            
        except Exception as e:
            self.logger.error(f"Error revoking credential: {e}", exc_info=True)
            await db.rollback()
            return False, f"Revocation failed: {str(e)}"
    
    async def get_vetter_statistics(self, db: AsyncSession) -> Dict[str, Any]:
        """
        Get statistics about credential issuance
        
        Returns:
            Dictionary with statistics
        """
        try:
            from sqlalchemy import func
            
            # Total reviewers
            result = await db.execute(
                select(func.count(Reviewer.id))
            )
            total_reviewers = result.scalar()
            
            # Active reviewers (not revoked)
            result = await db.execute(
                select(func.count(Reviewer.id)).where(
                    Reviewer.revoked == False
                )
            )
            active_reviewers = result.scalar()
            
            # Revoked reviewers
            revoked_reviewers = total_reviewers - active_reviewers
            
            return {
                "total_reviewers": total_reviewers,
                "active_reviewers": active_reviewers,
                "revoked_reviewers": revoked_reviewers,
                "revocation_rate": (
                    revoked_reviewers / total_reviewers * 100
                    if total_reviewers > 0 else 0
                )
            }
            
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}", exc_info=True)
            return {
                "total_reviewers": 0,
                "active_reviewers": 0,
                "revoked_reviewers": 0,
                "revocation_rate": 0,
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


# Global vetter service instance
_vetter_service: Optional[VetterService] = None


def get_vetter_service() -> VetterService:
    """Get global vetter service instance"""
    global _vetter_service
    if _vetter_service is None:
        _vetter_service = VetterService()
        # Initialize with 2048-bit RSA (production-ready)
        _vetter_service.initialize_server_keypair(2048)
    return _vetter_service
