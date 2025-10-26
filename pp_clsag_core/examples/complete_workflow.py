#!/usr/bin/env python3
"""
Complete ProofPals Workflow Example

This example demonstrates a complete workflow using all cryptographic primitives:
1. Blind credential issuance
2. Anonymous voting with ring signatures
3. Vote verification and double-vote prevention
"""

import os
import secrets
import pp_clsag_core as crypto

def main():
    print("ProofPals Complete Workflow Example")
    print("===================================")
    
    # ===== SETUP PHASE =====
    print("\n--- Setup Phase ---")
    
    # Server generates RSA keypair for blind signatures
    print("Server: Generating credential issuing keys...")
    server_keypair = crypto.BlindRsaKeyPair(1024)  # 1024 bits for example
    server_public_key = server_keypair.export_public_key()
    
    # Generate participants (5 honest voters)
    num_participants = 5
    print(f"Generating {num_participants} participant keys...")
    
    # Each participant generates a keypair
    participant_seeds = [os.urandom(32) for _ in range(num_participants)]
    participant_keypairs = []
    
    for i, seed in enumerate(participant_seeds):
        sk, pk = crypto.keygen_from_seed(seed, f"participant-{i}".encode())
        participant_keypairs.append((sk, pk))
        print(f"Participant {i}: Public key: {pk.hex()[:8]}...")
    
    # ===== CREDENTIAL ISSUANCE PHASE =====
    print("\n--- Credential Issuance Phase ---")
    
    # Each participant requests a blind credential
    participant_credentials = []
    
    for i, (sk, pk) in enumerate(participant_keypairs):
        # Participant creates a credential request message
        credential_id = f"credential-for-epoch-1-user-{i}".encode()
        
        print(f"Participant {i}: Requesting credential...")
        # Blind the credential request
        blinded_request = crypto.BlindedMessage.blind(credential_id, server_public_key)
        blinded_data = blinded_request.get_blinded_message()
        
        # Server signs the blinded request
        print(f"Server: Issuing blind signature for participant {i}...")
        blind_signature = server_keypair.sign_blinded_message(blinded_data)
        
        # Participant unblinds the signature
        unblinded_signature = blinded_request.unblind(blind_signature, server_public_key)
        
        # Store the credential (ID + signature)
        participant_credentials.append((credential_id, unblinded_signature))
        print(f"Participant {i}: Received valid credential")
    
    # ===== VOTING PHASE =====
    print("\n--- Voting Phase ---")
    
    # Create a proposal with a commitment to hide the actual vote count until reveal
    proposal_id = b"Proposal-42"
    initial_vote_count = 0
    vote_count_blinding = secrets.token_bytes(32)
    
    # Create a commitment to the initial vote count
    vote_count_commitment = crypto.pedersen_commit(
        initial_vote_count, 
        vote_count_blinding, 
        b"vote-tally-commitment"
    )
    print(f"Initial vote count commitment: {vote_count_commitment.hex()[:16]}...")
    
    # Collect votes using ring signatures
    print("\nCollecting votes...")
    votes = []
    key_images = []
    
    # Extract all public keys to form the ring
    ring_pubkeys = [pk for _, pk in participant_keypairs]
    
    # Let's say 3 participants vote (0, 2, and 4)
    voting_indices = [0, 2, 4]
    
    for i in voting_indices:
        sk, pk = participant_keypairs[i]
        credential_id, credential_sig = participant_credentials[i]
        
        # Verify the credential
        is_valid_credential = crypto.verify_blind_signature(
            credential_id, 
            credential_sig, 
            server_public_key
        )
        
        if not is_valid_credential:
            print(f"Participant {i}: Invalid credential, vote rejected")
            continue
        
        # Create the vote message
        vote_message = proposal_id + b":YES"
        
        # Sign the vote with a ring signature
        print(f"Participant {i}: Casting anonymous vote...")
        signature = crypto.ring_sign(vote_message, ring_pubkeys, sk, i)
        
        # Compute key image to prevent double voting
        key_image = crypto.compute_key_image(sk, pk, b"voting-context")
        
        # Add vote to the collection
        votes.append((vote_message, signature))
        key_images.append(key_image)
    
    # ===== VERIFICATION PHASE =====
    print("\n--- Verification Phase ---")
    
    print("Verifying votes and checking for duplicates...")
    valid_votes = 0
    unique_key_images = set()
    
    for i, (vote_message, signature) in enumerate(votes):
        # Verify the signature
        is_valid = crypto.ring_verify(vote_message, ring_pubkeys, signature)
        
        # Check if this is a duplicate vote (same key image)
        key_image = key_images[i]
        is_duplicate = key_image.hex() in unique_key_images
        
        if is_valid and not is_duplicate:
            print(f"Vote {i}: Valid and unique")
            valid_votes += 1
            unique_key_images.add(key_image.hex())
        elif is_valid and is_duplicate:
            print(f"Vote {i}: Valid but DUPLICATE - rejected")
        else:
            print(f"Vote {i}: Invalid signature - rejected")
    
    # ===== TALLY PHASE =====
    print("\n--- Tally Phase ---")
    
    # Update the vote count
    final_vote_count = valid_votes
    
    # Verify the updated commitment
    updated_commitment = crypto.pedersen_commit(
        final_vote_count, 
        vote_count_blinding, 
        b"vote-tally-commitment"
    )
    
    print(f"Final vote tally: {final_vote_count}")
    print(f"Final vote count commitment: {updated_commitment.hex()[:16]}...")
    
    # Reveal the vote count and blinding factor to prove the tally
    print("\nRevealing vote count commitment...")
    is_valid_tally = crypto.pedersen_verify(
        updated_commitment,
        final_vote_count,
        vote_count_blinding,
        b"vote-tally-commitment"
    )
    
    print(f"Vote tally commitment verification: {is_valid_tally}")
    print("\nWorkflow complete!")

if __name__ == "__main__":
    main()