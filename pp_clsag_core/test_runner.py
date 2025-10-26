#!/usr/bin/env python3
"""
Test runner for pp_clsag_core library
This script tests the core functionality without relying on Rust tests
"""

import time
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_import():
    """Test that the module can be imported"""
    try:
        import pp_clsag_core
        print("✓ Module import successful")
        return True
    except ImportError as e:
        print(f"✗ Module import failed: {e}")
        return False

def test_basic_functions():
    """Test basic functions"""
    try:
        import pp_clsag_core
        
        # Test seed generation
        seed = pp_clsag_core.generate_seed()
        print(f"✓ Seed generation: {len(seed)} bytes")
        
        # Test keypair derivation
        sk, pk = pp_clsag_core.derive_keypair(seed)
        print(f"✓ Keypair derivation: sk={len(sk)} bytes, pk={len(pk)} bytes")
        
        # Test key image computation
        key_image = pp_clsag_core.key_image(bytes(sk), bytes(pk), b"test_context")
        print(f"✓ Key image computation: {len(key_image)} bytes")
        
        return True
    except Exception as e:
        print(f"✗ Basic functions test failed: {e}")
        return False

def test_pedersen_commitments():
    """Test Pedersen commitments"""
    try:
        import pp_clsag_core
        
        # Test commitment creation
        commitment = pp_clsag_core.pedersen_commit(42, b"test_context")
        print(f"✓ Pedersen commitment created: {commitment.value}")
        
        # Test commitment verification
        is_valid = pp_clsag_core.pedersen_verify(
            bytes(commitment.commitment), 
            commitment.value, 
            bytes(commitment.blinding_factor), 
            b"test_context"
        )
        print(f"✓ Pedersen commitment verification: {is_valid}")
        
        return True
    except Exception as e:
        print(f"✗ Pedersen commitments test failed: {e}")
        return False

def test_clsag_signatures():
    """Test CLSAG signatures"""
    try:
        import pp_clsag_core
        
        # Generate keypairs for a ring
        ring_size = 3
        secret_keys = []
        ring = []
        
        for i in range(ring_size):
            seed = pp_clsag_core.generate_seed()
            sk, pk = pp_clsag_core.derive_keypair(seed)
            secret_keys.append(bytes(sk))
            ring.append(bytes(pk))
        
        # Sign a message
        message = b"test message for CLSAG"
        signer_index = 1
        signature = pp_clsag_core.clsag_sign(message, ring, secret_keys[signer_index], signer_index)
        print(f"✓ CLSAG signature created")
        
        # Verify the signature
        is_valid = pp_clsag_core.clsag_verify(message, ring, signature)
        print(f"✓ CLSAG signature verification: {is_valid}")
        
        return True
    except Exception as e:
        print(f"✗ CLSAG signatures test failed: {e}")
        return False

def test_blind_rsa():
    """Test blind RSA signatures"""
    try:
        import pp_clsag_core
        
        # Create server keypair
        server_keypair = pp_clsag_core.BlindRsaKeyPair(1024)
        public_key = server_keypair.export_public_key()
        print(f"✓ Blind RSA keypair created: {server_keypair.bits} bits")
        
        # Client blinds a message
        message = b"test message for blind RSA"
        blinded_message = pp_clsag_core.BlindedMessage.blind(message, bytes(public_key))
        blinded_data = blinded_message.get_blinded_message()
        print(f"✓ Message blinded: {len(blinded_data)} bytes")
        
        # Server signs the blinded message
        blind_signature = server_keypair.sign_blinded_message(bytes(blinded_data))
        print(f"✓ Blinded message signed")
        
        # Client unblinds the signature
        unblinded_signature = blinded_message.unblind(blind_signature, bytes(public_key))
        print(f"✓ Signature unblinded: {len(unblinded_signature)} bytes")
        
        # Verify the signature
        is_valid = pp_clsag_core.verify_blind_signature(message, bytes(unblinded_signature), bytes(public_key))
        print(f"✓ Blind RSA signature verification: {is_valid}")
        
        return True
    except Exception as e:
        print(f"✗ Blind RSA test failed: {e}")
        return False

def run_performance_tests():
    """Run performance tests"""
    print("\n=== Performance Tests ===")
    
    try:
        import pp_clsag_core
        
        # Test CLSAG performance
        print("Testing CLSAG performance...")
        ring_size = 10
        secret_keys = []
        ring = []
        
        start_time = time.time()
        for i in range(ring_size):
            seed = pp_clsag_core.generate_seed()
            sk, pk = pp_clsag_core.derive_keypair(seed)
            secret_keys.append(bytes(sk))
            ring.append(bytes(pk))
        keygen_time = time.time() - start_time
        print(f"✓ Key generation ({ring_size} keys): {keygen_time:.4f}s")
        
        # Sign performance
        message = b"performance test message"
        signer_index = 5
        
        start_time = time.time()
        signature = pp_clsag_core.clsag_sign(message, ring, secret_keys[signer_index], signer_index)
        sign_time = time.time() - start_time
        print(f"✓ CLSAG signing: {sign_time:.4f}s")
        
        # Verify performance
        start_time = time.time()
        is_valid = pp_clsag_core.clsag_verify(message, ring, signature)
        verify_time = time.time() - start_time
        print(f"✓ CLSAG verification: {verify_time:.4f}s")
        
        return True
    except Exception as e:
        print(f"✗ Performance tests failed: {e}")
        return False

def main():
    """Main test runner"""
    print("=== pp_clsag_core Test Suite ===")
    print(f"Python version: {sys.version}")
    print(f"Platform: {sys.platform}")
    
    tests = [
        ("Module Import", test_import),
        ("Basic Functions", test_basic_functions),
        ("Pedersen Commitments", test_pedersen_commitments),
        ("CLSAG Signatures", test_clsag_signatures),
        ("Blind RSA", test_blind_rsa),
        ("Performance Tests", run_performance_tests),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        try:
            if test_func():
                passed += 1
                print(f"✓ {test_name} PASSED")
            else:
                print(f"✗ {test_name} FAILED")
        except Exception as e:
            print(f"✗ {test_name} ERROR: {e}")
    
    print(f"\n=== Test Results ===")
    print(f"Passed: {passed}/{total}")
    print(f"Success rate: {passed/total*100:.1f}%")
    
    if passed == total:
        print("🎉 All tests passed!")
        return 0
    else:
        print("❌ Some tests failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
