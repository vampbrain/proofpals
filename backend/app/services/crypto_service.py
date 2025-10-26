"""
Crypto service for integrating with Rust crypto library
"""

import asyncio
import logging
from typing import Dict, Any, List, Tuple
import pp_clsag_core
from app.config import settings

logger = logging.getLogger(__name__)

class CryptoService:
    """Service for cryptographic operations using Rust library"""
    
    def __init__(self):
        self.initialized = False
        self.rsa_keypair = None
        
    async def initialize(self):
        """Initialize the crypto service"""
        try:
            # Initialize RSA keypair for blind signatures
            self.rsa_keypair = pp_clsag_core.BlindRsaKeyPair(settings.RSA_KEY_SIZE)
            self.initialized = True
            logger.info("Crypto service initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize crypto service: {e}")
            raise
    
    async def cleanup(self):
        """Cleanup crypto service resources"""
        self.initialized = False
        self.rsa_keypair = None
        logger.info("Crypto service cleaned up")
    
    async def health_check(self) -> Dict[str, Any]:
        """Check crypto service health"""
        return {
            "initialized": self.initialized,
            "rsa_key_size": settings.RSA_KEY_SIZE if self.rsa_keypair else None,
            "crypto_library": "pp_clsag_core"
        }
    
    async def generate_seed(self) -> bytes:
        """Generate a cryptographically secure seed"""
        try:
            seed = pp_clsag_core.generate_seed()
            return bytes(seed)
        except Exception as e:
            logger.error(f"Error generating seed: {e}")
            raise
    
    async def derive_keypair(self, seed: bytes) -> Tuple[bytes, bytes]:
        """Derive a keypair from a seed"""
        try:
            sk, pk = pp_clsag_core.derive_keypair(list(seed))
            return bytes(sk), bytes(pk)
        except Exception as e:
            logger.error(f"Error deriving keypair: {e}")
            raise
    
    async def compute_key_image(self, secret_key: bytes, public_key: bytes, context: bytes) -> bytes:
        """Compute a key image for linkability"""
        try:
            key_image = pp_clsag_core.key_image(
                bytes(secret_key),
                bytes(public_key),
                bytes(context)
            )
            return bytes(key_image)
        except Exception as e:
            logger.error(f"Error computing key image: {e}")
            raise
    
    async def create_ring_signature(
        self,
        message: bytes,
        ring_pubkeys: List[bytes],
        secret_key: bytes,
        signer_index: int
    ) -> Dict[str, Any]:
        """Create a CLSAG ring signature"""
        try:
            # Convert bytes to lists for Rust library
            ring_pubkeys_list = [list(pk) for pk in ring_pubkeys]
            
            signature = pp_clsag_core.clsag_sign(
                bytes(message),
                ring_pubkeys_list,
                bytes(secret_key),
                signer_index
            )
            
            return {
                "signature": signature,
                "key_image": bytes(signature.key_image),
                "valid": True
            }
        except Exception as e:
            logger.error(f"Error creating ring signature: {e}")
            raise
    
    async def verify_ring_signature(
        self,
        message: bytes,
        ring_pubkeys: List[bytes],
        signature_blob: str
    ) -> Dict[str, Any]:
        """Verify a CLSAG ring signature"""
        try:
            # Convert bytes to lists for Rust library
            ring_pubkeys_list = [list(pk) for pk in ring_pubkeys]
            
            # Parse signature blob (assuming it's JSON serialized)
            import json
            sig_data = json.loads(signature_blob)
            
            signature = pp_clsag_core.CLSAGSignature(
                sig_data["key_image"],
                sig_data["c1"],
                sig_data["responses"]
            )
            
            is_valid = pp_clsag_core.clsag_verify(
                bytes(message),
                ring_pubkeys_list,
                signature
            )
            
            return {
                "valid": is_valid,
                "key_image": bytes(signature.key_image) if is_valid else None
            }
        except Exception as e:
            logger.error(f"Error verifying ring signature: {e}")
            return {"valid": False, "error": str(e)}
    
    async def create_blind_signature(self, blinded_message: str, vetter_id: str) -> Any:
        """Create a blind signature for credential issuance"""
        try:
            if not self.rsa_keypair:
                raise Exception("RSA keypair not initialized")
            
            # Convert blinded message to bytes
            blinded_bytes = bytes.fromhex(blinded_message)
            
            # Sign the blinded message
            blind_signature = self.rsa_keypair.sign_blinded_message(blinded_bytes)
            
            return blind_signature
        except Exception as e:
            logger.error(f"Error creating blind signature: {e}")
            raise
    
    async def verify_blind_signature(
        self,
        message: bytes,
        signature: bytes,
        public_key: bytes
    ) -> bool:
        """Verify a blind signature"""
        try:
            is_valid = pp_clsag_core.verify_blind_signature(
                bytes(message),
                bytes(signature),
                bytes(public_key)
            )
            return is_valid
        except Exception as e:
            logger.error(f"Error verifying blind signature: {e}")
            return False
    
    async def create_pedersen_commitment(self, value: int, context: bytes) -> Dict[str, Any]:
        """Create a Pedersen commitment"""
        try:
            commitment = pp_clsag_core.pedersen_commit(value, bytes(context))
            
            return {
                "commitment": bytes(commitment.commitment),
                "value": commitment.value,
                "blinding_factor": bytes(commitment.blinding_factor)
            }
        except Exception as e:
            logger.error(f"Error creating Pedersen commitment: {e}")
            raise
    
    async def verify_pedersen_commitment(
        self,
        commitment: bytes,
        value: int,
        blinding_factor: bytes,
        context: bytes
    ) -> bool:
        """Verify a Pedersen commitment"""
        try:
            is_valid = pp_clsag_core.pedersen_verify(
                bytes(commitment),
                value,
                bytes(blinding_factor),
                bytes(context)
            )
            return is_valid
        except Exception as e:
            logger.error(f"Error verifying Pedersen commitment: {e}")
            return False
    
    async def canonicalize_ring(self, pubkeys: List[bytes]) -> List[bytes]:
        """Canonicalize a ring of public keys"""
        try:
            pubkeys_list = [list(pk) for pk in pubkeys]
            canonical = pp_clsag_core.canonicalize_ring(pubkeys_list)
            return [bytes(pk) for pk in canonical]
        except Exception as e:
            logger.error(f"Error canonicalizing ring: {e}")
            raise
    
    async def create_canonical_message(
        self,
        submission_id: str,
        genre: str,
        vote_type: str,
        epoch: int,
        nonce: str
    ) -> bytes:
        """Create a canonical message for voting"""
        try:
            message = pp_clsag_core.canonical_message(
                submission_id,
                genre,
                vote_type,
                epoch,
                nonce
            )
            return bytes(message)
        except Exception as e:
            logger.error(f"Error creating canonical message: {e}")
            raise
    
    async def batch_verify_signatures(
        self,
        messages: List[bytes],
        ring_pubkeys: List[bytes],
        signatures: List[str]
    ) -> List[bool]:
        """Batch verify multiple signatures"""
        try:
            # Convert to lists for Rust library
            ring_pubkeys_list = [list(pk) for pk in ring_pubkeys]
            
            results = pp_clsag_core.clsag_verify_batch(
                [list(msg) for msg in messages],
                ring_pubkeys_list,
                signatures
            )
            
            return results
        except Exception as e:
            logger.error(f"Error batch verifying signatures: {e}")
            raise
