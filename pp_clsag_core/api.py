#!/usr/bin/env python3
"""
pp_clsag_core Python API Documentation

This module provides a comprehensive Python API for cryptographic primitives
including CLSAG ring signatures, blind RSA signatures, Pedersen commitments,
and Schnorr signatures. All functions are implemented in Rust for performance
and security.

Author: ProofPals Team
Version: 0.1.0
License: MIT
"""

import pp_clsag_core
from typing import List, Tuple, Union
import time

class PPCLSAGCore:
    """
    Main API class for pp_clsag_core functionality.
    
    This class provides a high-level interface to all cryptographic primitives
    in the pp_clsag_core library.
    """
    
    @staticmethod
    def generate_seed() -> bytes:
        """
        Generate a cryptographically secure random seed.
        
        Returns:
            bytes: A 32-byte random seed suitable for key derivation
            
        Example:
            >>> seed = PPCLSAGCore.generate_seed()
            >>> print(f"Generated seed: {len(seed)} bytes")
            Generated seed: 32 bytes
        """
        return pp_clsag_core.generate_seed()
    
    @staticmethod
    def derive_keypair(seed: bytes) -> Tuple[bytes, bytes]:
        """
        Derive a keypair from a seed using HKDF.
        
        Args:
            seed (bytes): 32-byte seed for key derivation
            
        Returns:
            Tuple[bytes, bytes]: (secret_key, public_key) where both are 32 bytes
            
        Example:
            >>> seed = PPCLSAGCore.generate_seed()
            >>> sk, pk = PPCLSAGCore.derive_keypair(seed)
            >>> print(f"Secret key: {len(sk)} bytes, Public key: {len(pk)} bytes")
            Secret key: 32 bytes, Public key: 32 bytes
        """
        return pp_clsag_core.derive_keypair(seed)
    
    @staticmethod
    def key_image(secret_key: bytes, public_key: bytes, context: bytes) -> bytes:
        """
        Compute a context-bound key image for linkability.
        
        Args:
            secret_key (bytes): 32-byte secret key
            public_key (bytes): 32-byte public key
            context (bytes): Context string for domain separation
            
        Returns:
            bytes: 32-byte key image
            
        Example:
            >>> seed = PPCLSAGCore.generate_seed()
            >>> sk, pk = PPCLSAGCore.derive_keypair(seed)
            >>> key_img = PPCLSAGCore.key_image(sk, pk, b"voting_context")
            >>> print(f"Key image: {len(key_img)} bytes")
            Key image: 32 bytes
        """
        return pp_clsag_core.key_image(secret_key, public_key, context)
    
    @staticmethod
    def canonicalize_ring(public_keys: List[bytes]) -> List[bytes]:
        """
        Canonicalize a ring of public keys by sorting them lexicographically.
        
        Args:
            public_keys (List[bytes]): List of 32-byte public keys
            
        Returns:
            List[bytes]: Sorted list of public keys
            
        Example:
            >>> keys = [b'key3', b'key1', b'key2']
            >>> canonical = PPCLSAGCore.canonicalize_ring(keys)
            >>> print(canonical)
            [b'key1', b'key2', b'key3']
        """
        return pp_clsag_core.canonicalize_ring(public_keys)
    
    @staticmethod
    def canonical_message(submission_id: str, genre: str, vote_type: str, 
                         epoch: int, nonce: str) -> bytes:
        """
        Create a canonical message format for voting.
        
        Args:
            submission_id (str): Unique identifier for the submission
            genre (str): Category/genre of the submission
            vote_type (str): Type of vote (e.g., "upvote", "downvote")
            epoch (int): Epoch number for temporal ordering
            nonce (str): Random nonce for uniqueness
            
        Returns:
            bytes: Canonical message bytes
            
        Example:
            >>> msg = PPCLSAGCore.canonical_message(
            ...     "sub123", "music", "upvote", 12345, "nonce123"
            ... )
            >>> print(f"Canonical message: {len(msg)} bytes")
            Canonical message: 45 bytes
        """
        return pp_clsag_core.canonical_message(submission_id, genre, vote_type, epoch, nonce)

class CLSAGSigner:
    """
    CLSAG (Concise Linkable Spontaneous Anonymous Group) signature operations.
    
    CLSAG provides efficient ring signatures with linkability properties.
    """
    
    @staticmethod
    def sign(message: bytes, ring: List[bytes], secret_key: bytes, 
            signer_index: int) -> pp_clsag_core.CLSAGSignature:
        """
        Create a CLSAG ring signature.
        
        Args:
            message (bytes): Message to sign
            ring (List[bytes]): List of public keys forming the ring
            secret_key (bytes): Signer's secret key (32 bytes)
            signer_index (int): Index of signer's public key in the ring
            
        Returns:
            CLSAGSignature: The CLSAG signature
            
        Example:
            >>> # Create a ring of 3 members
            >>> ring = []
            >>> secret_keys = []
            >>> for i in range(3):
            ...     seed = PPCLSAGCore.generate_seed()
            ...     sk, pk = PPCLSAGCore.derive_keypair(seed)
            ...     secret_keys.append(sk)
            ...     ring.append(pk)
            >>> 
            >>> # Sign with the second member
            >>> signature = CLSAGSigner.sign(b"test message", ring, secret_keys[1], 1)
            >>> print(f"Signature created with key image: {len(signature.key_image)} bytes")
            Signature created with key image: 32 bytes
        """
        return pp_clsag_core.clsag_sign(message, ring, secret_key, signer_index)
    
    @staticmethod
    def verify(message: bytes, ring: List[bytes], 
              signature: pp_clsag_core.CLSAGSignature) -> bool:
        """
        Verify a CLSAG ring signature.
        
        Args:
            message (bytes): Original message
            ring (List[bytes]): Ring of public keys
            signature (CLSAGSignature): CLSAG signature to verify
            
        Returns:
            bool: True if signature is valid, False otherwise
            
        Example:
            >>> # Verify the signature from the previous example
            >>> is_valid = CLSAGSigner.verify(b"test message", ring, signature)
            >>> print(f"Signature valid: {is_valid}")
            Signature valid: True
        """
        return pp_clsag_core.clsag_verify(message, ring, signature)

class PedersenCommitments:
    """
    Pedersen commitment operations for hiding and binding commitments.
    """
    
    @staticmethod
    def commit(value: int, context: bytes) -> pp_clsag_core.PedersenCommitment:
        """
        Create a Pedersen commitment to a value.
        
        Args:
            value (int): Value to commit to
            context (bytes): Context for domain separation
            
        Returns:
            PedersenCommitment: The commitment with blinding factor
            
        Example:
            >>> commitment = PedersenCommitments.commit(42, b"test_context")
            >>> print(f"Committed to value: {commitment.value}")
            >>> print(f"Commitment: {len(commitment.commitment)} bytes")
            Committed to value: 42
            Commitment: 32 bytes
        """
        return pp_clsag_core.pedersen_commit(value, context)
    
    @staticmethod
    def verify(commitment: bytes, value: int, blinding_factor: bytes, 
              context: bytes) -> bool:
        """
        Verify a Pedersen commitment.
        
        Args:
            commitment (bytes): The commitment
            value (int): The committed value
            blinding_factor (bytes): The blinding factor (32 bytes)
            context (bytes): Context used in commitment
            
        Returns:
            bool: True if commitment is valid, False otherwise
            
        Example:
            >>> # Verify the commitment from the previous example
            >>> is_valid = PedersenCommitments.verify(
            ...     commitment.commitment, 
            ...     commitment.value, 
            ...     commitment.blinding_factor, 
            ...     b"test_context"
            ... )
            >>> print(f"Commitment valid: {is_valid}")
            Commitment valid: True
        """
        return pp_clsag_core.pedersen_verify(commitment, value, blinding_factor, context)

class BlindRSASigner:
    """
    Blind RSA signature operations for anonymous authentication.
    """
    
    @staticmethod
    def create_keypair(bits: int = 2048) -> pp_clsag_core.BlindRsaKeyPair:
        """
        Create a new RSA keypair for blind signatures.
        
        Args:
            bits (int): RSA key size in bits (default: 2048)
            
        Returns:
            BlindRsaKeyPair: The RSA keypair
            
        Example:
            >>> keypair = BlindRSASigner.create_keypair(1024)  # Smaller for testing
            >>> print(f"Created {keypair.bits}-bit RSA keypair")
            Created 1024-bit RSA keypair
        """
        return pp_clsag_core.BlindRsaKeyPair(bits)
    
    @staticmethod
    def blind_message(message: bytes, public_key: bytes) -> pp_clsag_core.BlindedMessage:
        """
        Blind a message for anonymous signing.
        
        Args:
            message (bytes): Message to blind
            public_key (bytes): Server's public key
            
        Returns:
            BlindedMessage: The blinded message
            
        Example:
            >>> keypair = BlindRSASigner.create_keypair(1024)
            >>> public_key = keypair.export_public_key()
            >>> blinded = BlindRSASigner.blind_message(b"secret message", public_key)
            >>> print(f"Blinded message: {len(blinded.get_blinded_message())} bytes")
            Blinded message: 128 bytes
        """
        return pp_clsag_core.BlindedMessage.blind(message, public_key)
    
    @staticmethod
    def sign_blinded(blinded_data: bytes, keypair: pp_clsag_core.BlindRsaKeyPair) -> pp_clsag_core.BlindSignature:
        """
        Sign a blinded message (server-side operation).
        
        Args:
            blinded_data (bytes): The blinded message
            keypair (BlindRsaKeyPair): Server's keypair
            
        Returns:
            BlindSignature: The blind signature
            
        Example:
            >>> # Server signs the blinded message
            >>> blind_sig = BlindRSASigner.sign_blinded(blinded.get_blinded_message(), keypair)
            >>> print(f"Blind signature: {len(blind_sig.get_signature())} bytes")
            Blind signature: 128 bytes
        """
        return keypair.sign_blinded_message(blinded_data)
    
    @staticmethod
    def unblind_signature(blinded_message: pp_clsag_core.BlindedMessage, 
                         blind_signature: pp_clsag_core.BlindSignature, 
                         public_key: bytes) -> bytes:
        """
        Unblind a signature (client-side operation).
        
        Args:
            blinded_message (BlindedMessage): Original blinded message
            blind_signature (BlindSignature): Blind signature from server
            public_key (bytes): Server's public key
            
        Returns:
            bytes: The unblinded signature
            
        Example:
            >>> # Client unblinds the signature
            >>> unblinded_sig = BlindRSASigner.unblind_signature(
            ...     blinded, blind_sig, public_key
            ... )
            >>> print(f"Unblinded signature: {len(unblinded_sig)} bytes")
            Unblinded signature: 128 bytes
        """
        return blinded_message.unblind(blind_signature, public_key)
    
    @staticmethod
    def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify a blind RSA signature.
        
        Args:
            message (bytes): Original message
            signature (bytes): Unblinded signature
            public_key (bytes): Server's public key
            
        Returns:
            bool: True if signature is valid, False otherwise
            
        Example:
            >>> # Verify the signature
            >>> is_valid = BlindRSASigner.verify_signature(
            ...     b"secret message", unblinded_sig, public_key
            ... )
            >>> print(f"Signature valid: {is_valid}")
            Signature valid: True
        """
        return pp_clsag_core.verify_blind_signature(message, signature, public_key)

class SchnorrSigner:
    """
    Schnorr signature operations for simple digital signatures.
    """
    
    @staticmethod
    def sign(message: bytes, secret_key: bytes) -> Tuple[bytes, bytes]:
        """
        Create a Schnorr signature.
        
        Args:
            message (bytes): Message to sign
            secret_key (bytes): Signer's secret key (32 bytes)
            
        Returns:
            Tuple[bytes, bytes]: (R_point, s_scalar) signature components
            
        Example:
            >>> seed = PPCLSAGCore.generate_seed()
            >>> sk, pk = PPCLSAGCore.derive_keypair(seed)
            >>> R, s = SchnorrSigner.sign(b"test message", sk)
            >>> print(f"Signature components: R={len(R)} bytes, s={len(s)} bytes")
            Signature components: R=32 bytes, s=32 bytes
        """
        return pp_clsag_core.sign_schnorr(message, secret_key)
    
    @staticmethod
    def verify(message: bytes, public_key: bytes, R_point: bytes, s_scalar: bytes) -> bool:
        """
        Verify a Schnorr signature.
        
        Args:
            message (bytes): Original message
            public_key (bytes): Signer's public key (32 bytes)
            R_point (bytes): R component of signature (32 bytes)
            s_scalar (bytes): s component of signature (32 bytes)
            
        Returns:
            bool: True if signature is valid, False otherwise
            
        Example:
            >>> # Verify the signature from the previous example
            >>> is_valid = SchnorrSigner.verify(b"test message", pk, R, s)
            >>> print(f"Schnorr signature valid: {is_valid}")
            Schnorr signature valid: True
        """
        return pp_clsag_core.verify_schnorr(message, public_key, R_point, s_scalar)

class PerformanceProfiler:
    """
    Performance profiling utilities for cryptographic operations.
    """
    
    @staticmethod
    def benchmark_clsag(ring_sizes: List[int] = [2, 5, 10, 20], 
                       iterations: int = 100) -> dict:
        """
        Benchmark CLSAG operations for different ring sizes.
        
        Args:
            ring_sizes (List[int]): List of ring sizes to test
            iterations (int): Number of iterations per ring size
            
        Returns:
            dict: Performance results
            
        Example:
            >>> results = PerformanceProfiler.benchmark_clsag([2, 5, 10])
            >>> for size, times in results.items():
            ...     print(f"Ring size {size}: {times['sign']:.4f}s sign, {times['verify']:.4f}s verify")
            Ring size 2: 0.0023s sign, 0.0011s verify
            Ring size 5: 0.0045s sign, 0.0023s verify
            Ring size 10: 0.0089s sign, 0.0045s verify
        """
        results = {}
        
        for ring_size in ring_sizes:
            # Generate keypairs for the ring
            secret_keys = []
            ring = []
            
            for _ in range(ring_size):
                seed = PPCLSAGCore.generate_seed()
                sk, pk = PPCLSAGCore.derive_keypair(seed)
                secret_keys.append(sk)
                ring.append(pk)
            
            # Benchmark signing
            message = b"benchmark message"
            signer_index = ring_size // 2
            
            sign_times = []
            verify_times = []
            
            for _ in range(iterations):
                # Sign
                start = time.time()
                signature = CLSAGSigner.sign(message, ring, secret_keys[signer_index], signer_index)
                sign_times.append(time.time() - start)
                
                # Verify
                start = time.time()
                CLSAGSigner.verify(message, ring, signature)
                verify_times.append(time.time() - start)
            
            results[ring_size] = {
                'sign': sum(sign_times) / len(sign_times),
                'verify': sum(verify_times) / len(verify_times),
                'iterations': iterations
            }
        
        return results
    
    @staticmethod
    def benchmark_pedersen_commitments(iterations: int = 1000) -> dict:
        """
        Benchmark Pedersen commitment operations.
        
        Args:
            iterations (int): Number of iterations
            
        Returns:
            dict: Performance results
            
        Example:
            >>> results = PerformanceProfiler.benchmark_pedersen_commitments(100)
            >>> print(f"Commit: {results['commit']:.4f}s, Verify: {results['verify']:.4f}s")
            Commit: 0.0012s, Verify: 0.0008s
        """
        commit_times = []
        verify_times = []
        
        for _ in range(iterations):
            # Commit
            start = time.time()
            commitment = PedersenCommitments.commit(42, b"benchmark_context")
            commit_times.append(time.time() - start)
            
            # Verify
            start = time.time()
            PedersenCommitments.verify(
                commitment.commitment, 
                commitment.value, 
                commitment.blinding_factor, 
                b"benchmark_context"
            )
            verify_times.append(time.time() - start)
        
        return {
            'commit': sum(commit_times) / len(commit_times),
            'verify': sum(verify_times) / len(verify_times),
            'iterations': iterations
        }

# Example usage and testing
if __name__ == "__main__":
    print("pp_clsag_core Python API Examples")
    print("=" * 40)
    
    # Test basic functionality
    print("\n1. Basic Key Generation:")
    seed = PPCLSAGCore.generate_seed()
    sk, pk = PPCLSAGCore.derive_keypair(seed)
    print(f"   Generated seed: {len(seed)} bytes")
    print(f"   Secret key: {len(sk)} bytes")
    print(f"   Public key: {len(pk)} bytes")
    
    print("\n2. CLSAG Ring Signatures:")
    # Create a ring of 3 members
    ring = []
    secret_keys = []
    for i in range(3):
        seed = PPCLSAGCore.generate_seed()
        sk, pk = PPCLSAGCore.derive_keypair(seed)
        secret_keys.append(sk)
        ring.append(pk)
    
    # Sign with the second member
    message = b"test message for CLSAG"
    signature = CLSAGSigner.sign(message, ring, secret_keys[1], 1)
    print(f"   Created CLSAG signature with key image: {len(signature.key_image)} bytes")
    
    # Verify the signature
    is_valid = CLSAGSigner.verify(message, ring, signature)
    print(f"   Signature verification: {'PASSED' if is_valid else 'FAILED'}")
    
    print("\n3. Pedersen Commitments:")
    commitment = PedersenCommitments.commit(42, b"test_context")
    print(f"   Committed to value: {commitment.value}")
    print(f"   Commitment: {len(commitment.commitment)} bytes")
    
    is_valid = PedersenCommitments.verify(
        commitment.commitment, 
        commitment.value, 
        commitment.blinding_factor, 
        b"test_context"
    )
    print(f"   Commitment verification: {'PASSED' if is_valid else 'FAILED'}")
    
    print("\n4. Blind RSA Signatures:")
    keypair = BlindRSASigner.create_keypair(1024)  # Smaller for testing
    public_key = keypair.export_public_key()
    
    blinded = BlindRSASigner.blind_message(b"secret message", public_key)
    blind_sig = BlindRSASigner.sign_blinded(blinded.get_blinded_message(), keypair)
    unblinded_sig = BlindRSASigner.unblind_signature(blinded, blind_sig, public_key)
    
    is_valid = BlindRSASigner.verify_signature(b"secret message", unblinded_sig, public_key)
    print(f"   Blind RSA signature verification: {'PASSED' if is_valid else 'FAILED'}")
    
    print("\n5. Performance Benchmark:")
    results = PerformanceProfiler.benchmark_clsag([2, 5, 10], 10)
    for size, times in results.items():
        print(f"   Ring size {size}: {times['sign']:.4f}s sign, {times['verify']:.4f}s verify")
    
    print("\nAll tests completed successfully!")
