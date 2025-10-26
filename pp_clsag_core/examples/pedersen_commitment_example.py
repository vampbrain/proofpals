#!/usr/bin/env python3
"""
Example demonstrating Pedersen commitments in ProofPals.

This example shows:
1. Creating Pedersen commitments
2. Verifying commitments
3. Demonstrating the binding and hiding properties
"""

import os
import pp_clsag_core as crypto
import secrets

def main():
    print("Pedersen Commitment Example")
    print("===========================")
    
    # Create a commitment to a value
    value = 42
    # Generate a random blinding factor
    blinding_factor = secrets.token_bytes(32)
    
    print(f"Creating commitment to value: {value}")
    
    # Create the commitment with a specific context
    context = b"example-commitment"
    commitment = crypto.pedersen_commit(value, blinding_factor, context)
    
    print(f"Commitment: {commitment.hex()[:16]}...")
    
    # Verify the commitment
    print("\nVerifying commitment...")
    is_valid = crypto.pedersen_verify(commitment, value, blinding_factor, context)
    print(f"Commitment valid: {is_valid}")
    
    # Try to verify with a different value (should fail - binding property)
    different_value = 43
    is_valid_different = crypto.pedersen_verify(commitment, different_value, blinding_factor, context)
    print(f"Commitment valid for different value: {is_valid_different} (should be False)")
    
    # Demonstrate the hiding property
    print("\nDemonstrating hiding property:")
    # Create two commitments to the same value with different blinding factors
    value = 100
    blinding_factor1 = secrets.token_bytes(32)
    blinding_factor2 = secrets.token_bytes(32)
    
    commitment1 = crypto.pedersen_commit(value, blinding_factor1, context)
    commitment2 = crypto.pedersen_commit(value, blinding_factor2, context)
    
    print(f"Commitment 1 (value={value}): {commitment1.hex()[:16]}...")
    print(f"Commitment 2 (value={value}): {commitment2.hex()[:16]}...")
    print(f"Commitments are different: {commitment1 != commitment2}")
    print("This demonstrates the hiding property - same value produces different commitments with different blinding factors.")
    
    # Demonstrate context separation
    print("\nDemonstrating context separation:")
    context1 = b"context-1"
    context2 = b"context-2"
    
    value = 42
    blinding = secrets.token_bytes(32)
    
    commitment1 = crypto.pedersen_commit(value, blinding, context1)
    commitment2 = crypto.pedersen_commit(value, blinding, context2)
    
    print(f"Commitment with context1: {commitment1.hex()[:16]}...")
    print(f"Commitment with context2: {commitment2.hex()[:16]}...")
    print(f"Commitments are different: {commitment1 != commitment2}")
    print("This demonstrates context separation - same value and blinding factor produce different commitments with different contexts.")

if __name__ == "__main__":
    main()