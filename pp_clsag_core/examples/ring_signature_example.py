#!/usr/bin/env python3
"""
Example demonstrating CLSAG ring signatures in ProofPals.

This example shows:
1. Key generation
2. Creating a ring of public keys
3. Signing a message with a ring signature
4. Verifying the signature
5. Checking key image uniqueness to prevent double-voting
"""

import os
import pp_clsag_core as crypto
import hashlib

def main():
    # Generate some random seeds for our participants
    print("Generating keys for ring participants...")
    num_participants = 5
    seeds = [os.urandom(32) for _ in range(num_participants)]
    
    # Generate keypairs for all participants
    keypairs = []
    for i, seed in enumerate(seeds):
        sk, pk = crypto.keygen_from_seed(seed, f"participant-{i}".encode())
        keypairs.append((sk, pk))
        print(f"Participant {i}: Public key: {pk.hex()[:8]}...")
    
    # Choose one participant as the actual signer (index 2 in this example)
    signer_index = 2
    signer_sk, signer_pk = keypairs[signer_index]
    
    # Extract all public keys to form the ring
    ring_pubkeys = [pk for _, pk in keypairs]
    
    # Create a message to sign (e.g., a vote)
    message = b"I vote for Proposal #42"
    print(f"\nMessage to sign: {message.decode()}")
    
    # Sign the message with the ring signature
    print(f"Signing with participant {signer_index}'s key...")
    signature = crypto.ring_sign(message, ring_pubkeys, signer_sk, signer_index)
    
    # Extract the key image (used to prevent double-voting)
    key_image = crypto.compute_key_image(signer_sk, signer_pk, b"voting-context")
    print(f"Key image: {key_image.hex()[:16]}...")
    
    # Verify the signature
    print("\nVerifying signature...")
    is_valid = crypto.ring_verify(message, ring_pubkeys, signature)
    print(f"Signature valid: {is_valid}")
    
    # Try to verify with a different message (should fail)
    different_message = b"I vote for Proposal #43"
    is_valid_different = crypto.ring_verify(different_message, ring_pubkeys, signature)
    print(f"Signature valid for different message: {is_valid_different} (should be False)")
    
    # Demonstrate key image uniqueness
    print("\nDemonstrating key image uniqueness for double-vote prevention:")
    # Same signer tries to sign a different message
    second_message = b"I vote for Proposal #43 instead"
    second_signature = crypto.ring_sign(second_message, ring_pubkeys, signer_sk, signer_index)
    
    # Extract key image from second signature (should be the same)
    second_key_image = crypto.compute_key_image(signer_sk, signer_pk, b"voting-context")
    
    print(f"First key image:  {key_image.hex()[:16]}...")
    print(f"Second key image: {second_key_image.hex()[:16]}...")
    print(f"Key images match: {key_image == second_key_image}")
    print("This allows detection of double-voting while preserving anonymity.")

if __name__ == "__main__":
    main()