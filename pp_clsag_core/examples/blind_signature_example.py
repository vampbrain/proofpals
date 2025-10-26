#!/usr/bin/env python3
"""
Example demonstrating blind-RSA signatures in ProofPals.

This example shows:
1. Server key generation
2. Client message blinding
3. Server blind signing
4. Client unblinding
5. Signature verification
"""

import pp_clsag_core as crypto

def main():
    print("Blind-RSA Signature Example")
    print("===========================")
    
    # === SERVER SIDE ===
    print("Server: Generating RSA key pair...")
    # Use smaller key size for example (1024 bits)
    server_keypair = crypto.BlindRsaKeyPair(1024)
    public_key = server_keypair.export_public_key()
    print(f"Server: Public key generated ({len(public_key)} bytes)")
    
    # === CLIENT SIDE ===
    print("\nClient: Creating message to be signed...")
    message = b"Issue credential token for user 12345"
    print(f"Client: Message: {message.decode()}")
    
    print("Client: Blinding the message...")
    blinded_message = crypto.BlindedMessage.blind(message, public_key)
    blinded_data = blinded_message.get_blinded_message()
    print(f"Client: Blinded message: {blinded_data[:16].hex()}...")
    
    # === SERVER SIDE ===
    print("\nServer: Signing the blinded message...")
    blind_signature = server_keypair.sign_blinded_message(blinded_data)
    signature_data = blind_signature.get_signature()
    print(f"Server: Blind signature: {signature_data[:16].hex()}...")
    
    # === CLIENT SIDE ===
    print("\nClient: Unblinding the signature...")
    unblinded_signature = blinded_message.unblind(blind_signature, public_key)
    print(f"Client: Unblinded signature: {unblinded_signature[:16].hex()}...")
    
    # === VERIFICATION ===
    print("\nVerifying the signature...")
    is_valid = crypto.verify_blind_signature(message, unblinded_signature, public_key)
    print(f"Signature valid: {is_valid}")
    
    # Try to verify with a different message (should fail)
    different_message = b"Issue credential token for user 54321"
    is_valid_different = crypto.verify_blind_signature(different_message, unblinded_signature, public_key)
    print(f"Signature valid for different message: {is_valid_different} (should be False)")
    
    # === DEMONSTRATE UNLINKABILITY ===
    print("\nDemonstrating unlinkability:")
    # Client blinds the same message again with a different blinding factor
    blinded_message2 = crypto.BlindedMessage.blind(message, public_key)
    blinded_data2 = blinded_message2.get_blinded_message()
    
    print(f"First blinded message:  {blinded_data[:16].hex()}...")
    print(f"Second blinded message: {blinded_data2[:16].hex()}...")
    print(f"Blinded messages are different: {blinded_data != blinded_data2}")
    print("This demonstrates unlinkability - the server cannot link the blinded message to the original message.")

if __name__ == "__main__":
    main()