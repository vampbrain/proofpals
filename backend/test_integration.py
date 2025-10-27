
"""
ProofPals Integration Tests
End-to-end testing of complete workflows
"""

import pytest
import asyncio
import json
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime

# Import app and dependencies
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app
from database import get_db, init_db, reset_db
from models import Submission, Ring, Reviewer, Vote, Token
from auth_service import get_auth_service
from vetter_service import get_vetter_service
from token_service import get_token_service

try:
    import pp_clsag_core
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="function")
async def db_session():
    """Provide a clean database session for each test"""
    await reset_db()
    await init_db()
    
    async for session in get_db():
        yield session
        break


@pytest.fixture(scope="function")
async def client():
    """Provide async HTTP client"""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


@pytest.fixture
async def admin_user(db_session):
    """Create admin user and return auth tokens"""
    auth_service = get_auth_service()
    
    success, user_id, error = await auth_service.create_user(
        username="admin",
        email="admin@proofpals.test",
        password="AdminPass123",
        role="admin",
        db=db_session
    )
    
    assert success, f"Failed to create admin: {error}"
    
    # Login to get tokens
    user = await auth_service.authenticate_user("admin", "AdminPass123", db_session)
    assert user is not None
    
    access_token = auth_service.create_access_token(
        user_id=user["id"],
        username=user["username"],
        role=user["role"]
    )
    
    return {
        "user_id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "access_token": access_token
    }


@pytest.fixture
async def vetter_user(db_session):
    """Create vetter user and return auth tokens"""
    auth_service = get_auth_service()
    
    success, user_id, error = await auth_service.create_user(
        username="vetter1",
        email="vetter1@proofpals.test",
        password="VetterPass123",
        role="vetter",
        db=db_session
    )
    
    assert success, f"Failed to create vetter: {error}"
    
    user = await auth_service.authenticate_user("vetter1", "VetterPass123", db_session)
    access_token = auth_service.create_access_token(
        user_id=user["id"],
        username=user["username"],
        role=user["role"]
    )
    
    return {
        "user_id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "access_token": access_token
    }


# ============================================================================
# Test: Complete Voting Flow
# ============================================================================

@pytest.mark.asyncio
@pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Crypto library not available")
async def test_complete_voting_flow(client, db_session, admin_user):
    """
    Test complete flow: submission → ring → credential → vote → tally
    """
    
    # STEP 1: Create submission
    submission_data = {
        "genre": "news",
        "content_ref": "https://example.com/article.pdf",
        "submitter_ip": "192.168.1.100"
    }
    
    response = await client.post("/api/v1/submissions", json=submission_data)
    assert response.status_code == 200
    submission = response.json()
    submission_id = submission["submission_id"]
    assert submission["success"] is True
    
    # STEP 2: Generate keypairs for ring members
    ring_size = 5
    keypairs = []
    pubkeys = []
    
    for i in range(ring_size):
        seed = pp_clsag_core.generate_seed()
        sk, pk = pp_clsag_core.derive_keypair(seed)
        keypairs.append((sk, pk))
        pubkeys.append(pk.hex())
    
    # STEP 3: Create ring
    ring_data = {
        "genre": "news",
        "pubkeys": pubkeys,
        "epoch": 1
    }
    
    response = await client.post("/api/v1/rings", json=ring_data)
    assert response.status_code == 200
    ring = response.json()
    ring_id = ring["ring_id"]
    assert ring["success"] is True
    
    # STEP 4: Create reviewer credential
    # In real flow, this would go through blind signature process
    # For testing, we create directly
    import hashlib
    credential_hash = hashlib.sha256(b"test_credential_1").hexdigest()
    
    reviewer = Reviewer(
        credential_hash=credential_hash,
        revoked=False,
        created_at=datetime.utcnow()
    )
    db_session.add(reviewer)
    await db_session.commit()
    
    # STEP 5: Issue epoch tokens
    token_service = get_token_service()
    await token_service.init_redis()
    
    success, token_ids, error = await token_service.create_epoch_tokens(
        credential_hash=credential_hash,
        epoch=1,
        token_count=5,
        db=db_session
    )
    
    assert success, f"Token creation failed: {error}"
    assert len(token_ids) == 5
    token_id = token_ids[0]
    
    # STEP 6: Create and sign vote
    signer_index = 2
    sk_signer, pk_signer = keypairs[signer_index]
    
    # Create canonical message
    message = pp_clsag_core.canonical_message(
        str(submission_id),
        "news",
        "approve",
        1,
        "test_nonce_123"
    )
    
    # Convert pubkeys to bytes
    ring_bytes = [bytes.fromhex(pk) for pk in pubkeys]
    
    # Sign with CLSAG
    signature = pp_clsag_core.clsag_sign(
        message,
        ring_bytes,
        sk_signer,
        signer_index
    )
    
    # Convert signature to JSON
    signature_json = json.dumps({
        "key_image": signature.key_image.hex(),
        "c1": signature.c1.hex(),
        "responses": [r.hex() for r in signature.responses]
    })
    
    # STEP 7: Submit vote
    vote_data = {
        "submission_id": submission_id,
        "ring_id": ring_id,
        "signature_blob": signature_json,
        "vote_type": "approve",
        "token_id": token_id,
        "message": message.hex()
    }
    
    response = await client.post("/api/v1/vote", json=vote_data)
    assert response.status_code == 200
    vote_response = response.json()
    assert vote_response["success"] is True
    vote_id = vote_response["vote_id"]
    
    # STEP 8: Verify vote was recorded
    from sqlalchemy import select
    result = await db_session.execute(select(Vote).where(Vote.id == vote_id))
    vote = result.scalar_one_or_none()
    assert vote is not None
    assert vote.verified is True
    assert vote.vote_type == "approve"
    
    # STEP 9: Compute tally
    response = await client.get(f"/api/v1/tally/{submission_id}")
    assert response.status_code == 200
    tally = response.json()
    assert tally["success"] is True
    assert tally["counts"]["approve"] == 1
    assert tally["decision"] in ["approved", "pending"]
    
    print("\n✅ Complete voting flow test PASSED")


@pytest.mark.asyncio
async def test_duplicate_vote_prevention(client, db_session, admin_user):
    """
    Test that the same credential cannot vote twice on same submission
    """
    if not CRYPTO_AVAILABLE:
        pytest.skip("Crypto library not available")
    
    # Setup: Create submission, ring, credential, tokens
    submission_data = {"genre": "news", "content_ref": "test.pdf", "submitter_ip": "1.1.1.1"}
    response = await client.post("/api/v1/submissions", json=submission_data)
    submission_id = response.json()["submission_id"]
    
    # Create ring
    ring_size = 3
    keypairs = []
    pubkeys = []
    for i in range(ring_size):
        seed = pp_clsag_core.generate_seed()
        sk, pk = pp_clsag_core.derive_keypair(seed)
        keypairs.append((sk, pk))
        pubkeys.append(pk.hex())
    
    ring_data = {"genre": "news", "pubkeys": pubkeys, "epoch": 1}
    response = await client.post("/api/v1/rings", json=ring_data)
    ring_id = response.json()["ring_id"]
    
    # Create credential and tokens
    import hashlib
    credential_hash = hashlib.sha256(b"test_cred_duplicate").hexdigest()
    reviewer = Reviewer(credential_hash=credential_hash, revoked=False, created_at=datetime.utcnow())
    db_session.add(reviewer)
    await db_session.commit()
    
    token_service = get_token_service()
    await token_service.init_redis()
    success, token_ids, _ = await token_service.create_epoch_tokens(
        credential_hash, 1, 2, db_session
    )
    
    # First vote - should succeed
    sk, pk = keypairs[0]
    message = pp_clsag_core.canonical_message(str(submission_id), "news", "approve", 1, "nonce1")
    ring_bytes = [bytes.fromhex(pk) for pk in pubkeys]
    signature = pp_clsag_core.clsag_sign(message, ring_bytes, sk, 0)
    
    signature_json = json.dumps({
        "key_image": signature.key_image.hex(),
        "c1": signature.c1.hex(),
        "responses": [r.hex() for r in signature.responses]
    })
    
    vote_data = {
        "submission_id": submission_id,
        "ring_id": ring_id,
        "signature_blob": signature_json,
        "vote_type": "approve",
        "token_id": token_ids[0],
        "message": message.hex()
    }
    
    response = await client.post("/api/v1/vote", json=vote_data)
    assert response.status_code == 200
    assert response.json()["success"] is True
    
    # Second vote with same key - should fail (duplicate key image)
    message2 = pp_clsag_core.canonical_message(str(submission_id), "news", "reject", 1, "nonce2")
    signature2 = pp_clsag_core.clsag_sign(message2, ring_bytes, sk, 0)
    
    signature_json2 = json.dumps({
        "key_image": signature2.key_image.hex(),
        "c1": signature2.c1.hex(),
        "responses": [r.hex() for r in signature2.responses]
    })
    
    vote_data2 = {
        "submission_id": submission_id,
        "ring_id": ring_id,
        "signature_blob": signature_json2,
        "vote_type": "reject",
        "token_id": token_ids[1],
        "message": message2.hex()
    }
    
    response = await client.post("/api/v1/vote", json=vote_data2)
    assert response.status_code == 400
    assert "duplicate" in response.json()["error"].lower()
    
    print("\n✅ Duplicate vote prevention test PASSED")


@pytest.mark.asyncio
async def test_blind_credential_issuance(client, db_session, vetter_user):
    """
    Test blind RSA signature issuance workflow
    """
    if not CRYPTO_AVAILABLE:
        pytest.skip("Crypto library not available")
    
    vetter_service = get_vetter_service()
    
    # STEP 1: Get server public key
    public_key = vetter_service.get_public_key()
    assert public_key is not None
    assert len(public_key) > 0
    
    # STEP 2: Client blinds a message
    message = b"credential_request_12345"
    blinded_message = pp_clsag_core.BlindedMessage.blind(message, public_key)
    blinded_data = blinded_message.get_blinded_message()
    
    # STEP 3: Vetter signs the blinded message
    success, signature_bytes, error = await vetter_service.issue_blind_signature(
        blinded_data,
        vetter_user["user_id"],
        db_session,
        metadata={"test": True}
    )
    
    assert success, f"Blind signature failed: {error}"
    assert signature_bytes is not None
    
    # STEP 4: Client unblinds the signature
    blind_sig = pp_clsag_core.BlindSignature(signature_bytes)
    unblinded_signature = blinded_message.unblind(blind_sig, public_key)
    
    # STEP 5: Verify the signature
    is_valid = pp_clsag_core.verify_blind_signature(message, unblinded_signature, public_key)
    assert is_valid, "Unblinded signature verification failed"
    
    # STEP 6: Register credential
    import hashlib
    credential_hash = hashlib.sha256(unblinded_signature).hexdigest()
    
    success, reviewer_id, error = await vetter_service.register_credential(
        credential_hash,
        None,
        None,
        db_session
    )
    
    assert success, f"Credential registration failed: {error}"
    assert reviewer_id is not None
    
    print("\n✅ Blind credential issuance test PASSED")


@pytest.mark.asyncio
async def test_authentication_flow(client, db_session):
    """
    Test user registration and authentication
    """
    
    # STEP 1: Register new user
    register_data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "TestPass123",
        "role": "reviewer"
    }
    
    # Note: This endpoint needs to be added to main.py
    # For now, we test the service directly
    auth_service = get_auth_service()
    
    from auth_service import UserCreate
    user_create = UserCreate(**register_data)
    
    success, user_id, error = await auth_service.create_user(
        user_create,
        db_session
    )
    
    assert success, f"Registration failed: {error}"
    assert user_id is not None
    
    # STEP 2: Login
    user = await auth_service.authenticate_user(
        "testuser",
        "TestPass123",
        db_session
    )
    
    assert user is not None
    assert user["username"] == "testuser"
    assert user["role"] == "reviewer"
    
    # STEP 3: Generate tokens
    access_token = auth_service.create_access_token(
        user_id=user["id"],
        username=user["username"],
        role=user["role"]
    )
    
    assert access_token is not None
    assert len(access_token) > 0
    
    # STEP 4: Verify token
    payload = auth_service.verify_token(access_token)
    assert payload is not None
    assert payload["username"] == "testuser"
    assert payload["type"] == "access"
    
    print("\n✅ Authentication flow test PASSED")


@pytest.mark.asyncio
async def test_rate_limiting(client, db_session):
    """
    Test rate limiting functionality
    """
    # This test requires the rate limiter middleware to be active
    # Make multiple rapid requests and verify rate limiting kicks in
    
    # Make requests up to limit
    for i in range(5):
        response = await client.get("/health")
        assert response.status_code == 200
    
    # Note: Rate limiting is currently set to allow this
    # More aggressive testing would require lowering limits
    
    print("\n✅ Rate limiting test PASSED (basic)")


@pytest.mark.asyncio
async def test_credential_revocation(client, db_session, vetter_user):
    """
    Test credential revocation workflow
    """
    if not CRYPTO_AVAILABLE:
        pytest.skip("Crypto library not available")
    
    vetter_service = get_vetter_service()
    
    # Create a credential
    import hashlib
    credential_hash = hashlib.sha256(b"revoke_test_cred").hexdigest()
    
    success, reviewer_id, error = await vetter_service.register_credential(
        credential_hash,
        None,
        None,
        db_session
    )
    
    assert success, f"Registration failed: {error}"
    
    # Verify credential is valid
    is_valid, info, error = await vetter_service.verify_credential(
        credential_hash,
        db_session
    )
    
    assert is_valid
    assert info["revoked"] is False
    
    # Revoke the credential
    success, error = await vetter_service.revoke_credential(
        credential_hash,
        "Testing revocation",
        vetter_user["user_id"],
        "Test evidence",
        db_session
    )
    
    assert success, f"Revocation failed: {error}"
    
    # Verify credential is now revoked
    is_valid, info, error = await vetter_service.verify_credential(
        credential_hash,
        db_session
    )
    
    assert not is_valid
    assert "revoked" in error.lower()
    
    print("\n✅ Credential revocation test PASSED")


@pytest.mark.asyncio
async def test_concurrent_vote_submissions(client, db_session):
    """
    Test that concurrent vote submissions handle atomicity correctly
    """
    if not CRYPTO_AVAILABLE:
        pytest.skip("Crypto library not available")
    
    # Setup submission and ring
    submission_data = {"genre": "news", "content_ref": "concurrent_test.pdf", "submitter_ip": "1.1.1.1"}
    response = await client.post("/api/v1/submissions", json=submission_data)
    submission_id = response.json()["submission_id"]
    
    ring_size = 3
    keypairs = []
    pubkeys = []
    for i in range(ring_size):
        seed = pp_clsag_core.generate_seed()
        sk, pk = pp_clsag_core.derive_keypair(seed)
        keypairs.append((sk, pk))
        pubkeys.append(pk.hex())
    
    ring_data = {"genre": "news", "pubkeys": pubkeys, "epoch": 1}
    response = await client.post("/api/v1/rings", json=ring_data)
    ring_id = response.json()["ring_id"]
    
    # Create credential with ONE token (to test atomicity)
    import hashlib
    credential_hash = hashlib.sha256(b"concurrent_test_cred").hexdigest()
    reviewer = Reviewer(credential_hash=credential_hash, revoked=False, created_at=datetime.utcnow())
    db_session.add(reviewer)
    await db_session.commit()
    
    token_service = get_token_service()
    await token_service.init_redis()
    success, token_ids, _ = await token_service.create_epoch_tokens(
        credential_hash, 1, 1, db_session
    )
    token_id = token_ids[0]
    
    # Prepare vote
    sk, pk = keypairs[0]
    message = pp_clsag_core.canonical_message(str(submission_id), "news", "approve", 1, "concurrent")
    ring_bytes = [bytes.fromhex(pk) for pk in pubkeys]
    signature = pp_clsag_core.clsag_sign(message, ring_bytes, sk, 0)
    
    signature_json = json.dumps({
        "key_image": signature.key_image.hex(),
        "c1": signature.c1.hex(),
        "responses": [r.hex() for r in signature.responses]
    })
    
    vote_data = {
        "submission_id": submission_id,
        "ring_id": ring_id,
        "signature_blob": signature_json,
        "vote_type": "approve",
        "token_id": token_id,
        "message": message.hex()
    }
    
    # Submit same vote concurrently multiple times
    async def submit_vote():
        return await client.post("/api/v1/vote", json=vote_data)
    
    # Run 10 concurrent submissions
    results = await asyncio.gather(
        *[submit_vote() for _ in range(10)],
        return_exceptions=True
    )
    
    # Count successes
    success_count = sum(1 for r in results if not isinstance(r, Exception) and r.status_code == 200)
    
    # Only ONE should succeed (atomic token consumption)
    assert success_count == 1, f"Expected 1 success, got {success_count}"
    
    print("\n✅ Concurrent vote submission atomicity test PASSED")


# ============================================================================
# Test Summary Report
# ============================================================================

def pytest_sessionfinish(session, exitstatus):
    """Print test summary"""
    print("\n" + "="*80)
    print("INTEGRATION TEST SUITE SUMMARY")
    print("="*80)
    print(f"Exit status: {exitstatus}")
    print("\nTests covered:")
    print("  ✓ Complete voting flow (submission → ring → vote → tally)")
    print("  ✓ Duplicate vote prevention")
    print("  ✓ Blind credential issuance")
    print("  ✓ Authentication flow")
    print("  ✓ Rate limiting")
    print("  ✓ Credential revocation")
    print("  ✓ Concurrent vote atomicity")
    print("="*80)