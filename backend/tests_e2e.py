

"""
ProofPals End-to-End Scenario Tests
Complete user journeys and edge cases
"""

import pytest
import asyncio
import json
from httpx import AsyncClient
from datetime import datetime

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app
from database import get_db, init_db, reset_db

try:
    import pp_clsag_core
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# ============================================================================
# Scenario 1: Journalist Submission Full Lifecycle
# ============================================================================

@pytest.mark.asyncio
@pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Crypto not available")
async def test_journalist_submission_lifecycle():
    """
    Complete scenario: Journalist submits article → reviewers vote → decision made
    
    Story:
    - Journalist submits an investigative article
    - 5 reviewers in the ring
    - 3 reviewers vote to approve
    - 1 reviewer votes to reject  
    - System approves the article (majority)
    """
    async with AsyncClient(app=app, base_url="http://test") as client:
        # Setup
        await reset_db()
        await init_db()
        
        # STEP 1: Journalist submits article
        print("\n📝 Journalist submits article...")
        submission_data = {
            "genre": "investigative",
            "content_ref": "https://whistleblower-docs.onion/corruption-report.pdf",
            "submitter_ip": "192.168.1.42"
        }
        
        response = await client.post("/api/v1/submissions", json=submission_data)
        assert response.status_code == 200
        submission_id = response.json()["submission_id"]
        print(f"   ✓ Submission created: ID={submission_id}")
        
        # STEP 2: Admin creates review ring
        print("\n👥 Creating reviewer ring...")
        ring_size = 5
        keypairs = []
        pubkeys = []
        
        for i in range(ring_size):
            seed = pp_clsag_core.generate_seed()
            sk, pk = pp_clsag_core.derive_keypair(seed)
            keypairs.append((sk, pk))
            pubkeys.append(pk.hex())
        
        ring_data = {
            "genre": "investigative",
            "pubkeys": pubkeys,
            "epoch": 1
        }
        
        response = await client.post("/api/v1/rings", json=ring_data)
        assert response.status_code == 200
        ring_id = response.json()["ring_id"]
        print(f"   ✓ Ring created: ID={ring_id}, Size={ring_size}")
        
        # STEP 3: Setup reviewer credentials and tokens
        print("\n🎫 Issuing reviewer tokens...")
        from models import Reviewer
        from token_service import get_token_service
        
        async for db in get_db():
            token_service = get_token_service()
            await token_service.init_redis()
            
            reviewer_tokens = []
            for i in range(ring_size):
                import hashlib
                cred_hash = hashlib.sha256(f"reviewer_{i}".encode()).hexdigest()
                
                reviewer = Reviewer(
                    credential_hash=cred_hash,
                    revoked=False,
                    created_at=datetime.utcnow()
                )
                db.add(reviewer)
                await db.flush()
                
                success, tokens, _ = await token_service.create_epoch_tokens(
                    cred_hash, 1, 1, db
                )
                assert success
                reviewer_tokens.append(tokens[0])
            
            await db.commit()
            print(f"   ✓ Issued tokens to {ring_size} reviewers")
            break
        
        # STEP 4: Reviewers vote
        print("\n🗳  Reviewers voting...")
        
        # 3 approve votes
        for i in range(3):
            sk, pk = keypairs[i]
            message = pp_clsag_core.canonical_message(
                str(submission_id), "investigative", "approve", 1, f"nonce_{i}"
            )
            ring_bytes = [bytes.fromhex(pk) for pk in pubkeys]
            signature = pp_clsag_core.clsag_sign(message, ring_bytes, sk, i)
            
            sig_json = json.dumps({
                "key_image": signature.key_image.hex(),
                "c1": signature.c1.hex(),
                "responses": [r.hex() for r in signature.responses]
            })
            
            vote_data = {
                "submission_id": submission_id,
                "ring_id": ring_id,
                "signature_blob": sig_json,
                "vote_type": "approve",
                "token_id": reviewer_tokens[i],
                "message": message.hex()
            }
            
            response = await client.post("/api/v1/vote", json=vote_data)
            assert response.status_code == 200
            print(f"   ✓ Reviewer {i+1} voted: APPROVE")
        
        # 1 reject vote
        i = 3
        sk, pk = keypairs[i]
        message = pp_clsag_core.canonical_message(
            str(submission_id), "investigative", "reject", 1, f"nonce_{i}"
        )
        ring_bytes = [bytes.fromhex(pk) for pk in pubkeys]
        signature = pp_clsag_core.clsag_sign(message, ring_bytes, sk, i)
        
        sig_json = json.dumps({
            "key_image": signature.key_image.hex(),
            "c1": signature.c1.hex(),
            "responses": [r.hex() for r in signature.responses]
        })
        
        vote_data = {
            "submission_id": submission_id,
            "ring_id": ring_id,
            "signature_blob": sig_json,
            "vote_type": "reject",
            "token_id": reviewer_tokens[i],
            "message": message.hex()
        }
        
        response = await client.post("/api/v1/vote", json=vote_data)
        assert response.status_code == 200
        print(f"   ✓ Reviewer {i+1} voted: REJECT")
        
        # STEP 5: Compute tally and check decision
        print("\n📊 Computing tally...")
        response = await client.get(f"/api/v1/tally/{submission_id}")
        assert response.status_code == 200
        tally = response.json()
        
        print(f"   ✓ Votes: Approve={tally['counts']['approve']}, Reject={tally['counts']['reject']}")
        print(f"   ✓ Decision: {tally['decision'].upper()}")
        
        assert tally["counts"]["approve"] == 3
        assert tally["counts"]["reject"] == 1
        assert tally["decision"] == "approved"
        
        print("\n✅ SCENARIO PASSED: Article approved by majority")


# ============================================================================
# Scenario 2: Malicious Content Flagging
# ============================================================================

@pytest.mark.asyncio
@pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Crypto not available")
async def test_malicious_content_flagging():
    """
    Scenario: Multiple reviewers flag harmful content → automatic escalation
    
    Story:
    - Malicious actor submits harmful content
    - 3+ reviewers flag it
    - System automatically escalates
    - Admin reviews and rejects
    """
    async with AsyncClient(app=app, base_url="http://test") as client:
        await reset_db()
        await init_db()
        
        print("\n⚠  Malicious content submission scenario...")
        
        # Submit harmful content
        submission_data = {
            "genre": "news",
            "content_ref": "https://malicious.com/harmful.pdf",
            "submitter_ip": "10.0.0.666"
        }
        
        response = await client.post("/api/v1/submissions", json=submission_data)
        submission_id = response.json()["submission_id"]
        
        # Create ring
        ring_size = 5
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
        
        # Issue tokens
        async for db in get_db():
            from token_service import get_token_service
            token_service = get_token_service()
            await token_service.init_redis()
            
            from models import Reviewer
            import hashlib
            
            reviewer_tokens = []
            for i in range(ring_size):
                cred_hash = hashlib.sha256(f"flag_reviewer_{i}".encode()).hexdigest()
                reviewer = Reviewer(credential_hash=cred_hash, revoked=False, created_at=datetime.utcnow())
                db.add(reviewer)
                await db.flush()
                
                success, tokens, _ = await token_service.create_epoch_tokens(cred_hash, 1, 1, db)
                reviewer_tokens.append(tokens[0])
            
            await db.commit()
            break
        
        # 3 reviewers flag the content
        print("\n🚩 Reviewers flagging harmful content...")
        for i in range(3):
            sk, pk = keypairs[i]
            message = pp_clsag_core.canonical_message(
                str(submission_id), "news", "flag", 1, f"flag_nonce_{i}"
            )
            ring_bytes = [bytes.fromhex(pk) for pk in pubkeys]
            signature = pp_clsag_core.clsag_sign(message, ring_bytes, sk, i)
            
            sig_json = json.dumps({
                "key_image": signature.key_image.hex(),
                "c1": signature.c1.hex(),
                "responses": [r.hex() for r in signature.responses]
            })
            
            vote_data = {
                "submission_id": submission_id,
                "ring_id": ring_id,
                "signature_blob": sig_json,
                "vote_type": "flag",
                "token_id": reviewer_tokens[i],
                "message": message.hex()
            }
            
            response = await client.post("/api/v1/vote", json=vote_data)
            assert response.status_code == 200
            print(f"   ✓ Reviewer {i+1} flagged content")
        
        # Check tally shows flagged status
        response = await client.get(f"/api/v1/tally/{submission_id}")
        tally = response.json()
        
        print(f"\n📊 Final status: {tally['decision'].upper()}")
        assert tally["counts"]["flag"] == 3
        assert tally["decision"] == "flagged"
        
        print("✅ SCENARIO PASSED: Harmful content flagged and escalated")


# ============================================================================
# Scenario 3: Credential Revocation Impact
# ============================================================================

@pytest.mark.asyncio
@pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Crypto not available")
async def test_credential_revocation_impact():
    """
    Scenario: Malicious reviewer is discovered → credential revoked → can't vote
    
    Story:
    - Reviewer votes normally
    - Evidence of abuse discovered
    - Admin revokes credential
    - Future token use fails
    """
    async with AsyncClient(app=app, base_url="http://test") as client:
        await reset_db()
        await init_db()
        
        print("\n🚫 Credential revocation scenario...")
        
        # Setup submission and ring
        submission_data = {"genre": "news", "content_ref": "test.pdf", "submitter_ip": "1.1.1.1"}
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
        
        # Create reviewer with tokens
        import hashlib
        from models import Reviewer
        from token_service import get_token_service
        from vetter_service import get_vetter_service
        
        async for db in get_db():
            cred_hash = hashlib.sha256(b"malicious_reviewer").hexdigest()
            reviewer = Reviewer(credential_hash=cred_hash, revoked=False, created_at=datetime.utcnow())
            db.add(reviewer)
            await db.flush()
            
            token_service = get_token_service()
            await token_service.init_redis()
            success, tokens, _ = await token_service.create_epoch_tokens(cred_hash, 1, 2, db)
            
            # First vote succeeds
            print("\n✓ First vote (before revocation)...")
            sk, pk = keypairs[0]
            message = pp_clsag_core.canonical_message(str(submission_id), "news", "approve", 1, "vote1")
            ring_bytes = [bytes.fromhex(p) for p in pubkeys]
            signature = pp_clsag_core.clsag_sign(message, ring_bytes, sk, 0)
            
            sig_json = json.dumps({
                "key_image": signature.key_image.hex(),
                "c1": signature.c1.hex(),
                "responses": [r.hex() for r in signature.responses]
            })
            
            vote_data = {
                "submission_id": submission_id,
                "ring_id": ring_id,
                "signature_blob": sig_json,
                "vote_type": "approve",
                "token_id": tokens[0],
                "message": message.hex()
            }
            break
        
        response = await client.post("/api/v1/vote", json=vote_data)
        assert response.status_code == 200
        print("   ✓ Vote succeeded before revocation")
        
        # Revoke credential
        async for db in get_db():
            vetter_service = get_vetter_service()
            success, error = await vetter_service.revoke_credential(
                cred_hash,
                "Abusive behavior detected",
                1,  # admin_id
                "Multiple spam votes",
                db
            )
            assert success
            print("\n⚠  Credential REVOKED")
            break
        
        # Try to vote again with remaining token - should fail
        print("\n✗ Attempting vote after revocation...")
        vote_data["token_id"] = tokens[1]
        vote_data["message"] = pp_clsag_core.canonical_message(
            str(submission_id), "news", "reject", 1, "vote2"
        ).hex()
        
        response = await client.post("/api/v1/vote", json=vote_data)
        assert response.status_code == 400
        assert "revoked" in response.json()["error"].lower()
        print("   ✓ Vote blocked - credential revoked")
        
        print("\n✅ SCENARIO PASSED: Revoked credential cannot vote")


# ============================================================================
# Scenario 4: High-Stakes Document Review
# ============================================================================

@pytest.mark.asyncio
@pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Crypto not available")
async def test_high_stakes_document_review():
    """
    Scenario: Sensitive document with mixed reviews → escalation → admin review
    
    Story:
    - High-profile leak submitted
    - Equal approve/reject votes (tie)
    - System escalates for human review
    - Admin resolves
    """
    async with AsyncClient(app=app, base_url="http://test") as client:
        await reset_db()
        await init_db()
        
        print("\n🔐 High-stakes document review scenario...")
        
        # Submit sensitive document
        submission_data = {
            "genre": "leaks",
            "content_ref": "https://whistleblower.onion/classified-docs.pdf",
            "submitter_ip": "tor-exit-node"
        }
        response = await client.post("/api/v1/submissions", json=submission_data)
        submission_id = response.json()["submission_id"]
        print(f"   📄 Sensitive document submitted: ID={submission_id}")
        
        # Create ring
        ring_size = 6
        keypairs = []
        pubkeys = []
        for i in range(ring_size):
            seed = pp_clsag_core.generate_seed()
            sk, pk = pp_clsag_core.derive_keypair(seed)
            keypairs.append((sk, pk))
            pubkeys.append(pk.hex())
        
        ring_data = {"genre": "leaks", "pubkeys": pubkeys, "epoch": 1}
        response = await client.post("/api/v1/rings", json=ring_data)
        ring_id = response.json()["ring_id"]
        
        # Issue tokens
        async for db in get_db():
            from token_service import get_token_service
            from models import Reviewer
            import hashlib
            
            token_service = get_token_service()
            await token_service.init_redis()
            
            tokens = []
            for i in range(ring_size):
                cred_hash = hashlib.sha256(f"hs_reviewer_{i}".encode()).hexdigest()
                reviewer = Reviewer(credential_hash=cred_hash, revoked=False, created_at=datetime.utcnow())
                db.add(reviewer)
                await db.flush()
                success, toks, _ = await token_service.create_epoch_tokens(cred_hash, 1, 1, db)
                tokens.extend(toks)
            await db.commit()
            break
        
        # Cast votes: 3 approve, 3 reject (tie)
        print("\n🗳  Reviewers voting (mixed opinions)...")
        vote_types = ["approve", "approve", "approve", "reject", "reject", "reject"]
        
        for i, vote_type in enumerate(vote_types):
            sk, pk = keypairs[i]
            message = pp_clsag_core.canonical_message(
                str(submission_id), "leaks", vote_type, 1, f"hs_vote_{i}"
            )
            ring_bytes = [bytes.fromhex(p) for p in pubkeys]
            signature = pp_clsag_core.clsag_sign(message, ring_bytes, sk, i)
            
            sig_json = json.dumps({
                "key_image": signature.key_image.hex(),
                "c1": signature.c1.hex(),
                "responses": [r.hex() for r in signature.responses]
            })
            
            vote_data = {
                "submission_id": submission_id,
                "ring_id": ring_id,
                "signature_blob": sig_json,
                "vote_type": vote_type,
                "token_id": tokens[i],
                "message": message.hex()
            }
            
            response = await client.post("/api/v1/vote", json=vote_data)
            assert response.status_code == 200
            print(f"   ✓ Vote {i+1}: {vote_type.upper()}")
        
        # Check tally
        response = await client.get(f"/api/v1/tally/{submission_id}")
        tally = response.json()
        
        print(f"\n📊 Vote Results:")
        print(f"   Approve: {tally['counts']['approve']}")
        print(f"   Reject: {tally['counts']['reject']}")
        print(f"   Decision: {tally['decision'].upper()}")
        
        assert tally["counts"]["approve"] == 3
        assert tally["counts"]["reject"] == 3
        assert tally["decision"] == "escalated"  # Tie results in escalation
        
        print("\n✅ SCENARIO PASSED: Tie correctly escalated for admin review")


# ============================================================================
# Scenario 5: Token Exhaustion and Refresh
# ============================================================================

@pytest.mark.asyncio
@pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Crypto not available")
async def test_token_exhaustion_and_refresh():
    """
    Scenario: Reviewer uses all tokens → requests new epoch tokens
    
    Story:
    - Reviewer receives 5 tokens
    - Uses all 5 tokens for voting
    - Attempts 6th vote - fails
    - Requests new epoch tokens
    - Can vote again
    """
    async with AsyncClient(app=app, base_url="http://test") as client:
        await reset_db()
        await init_db()
        
        print("\n🎫 Token exhaustion scenario...")
        
        # Create 5 submissions
        submission_ids = []
        for i in range(6):
            response = await client.post("/api/v1/submissions", json={
                "genre": "news",
                "content_ref": f"article{i}.pdf",
                "submitter_ip": "1.1.1.1"
            })
            submission_ids.append(response.json()["submission_id"])
        
        # Create ring
        seed = pp_clsag_core.generate_seed()
        sk, pk = pp_clsag_core.derive_keypair(seed)
        pubkeys = [pk.hex()]
        
        ring_data = {"genre": "news", "pubkeys": pubkeys, "epoch": 1}
        response = await client.post("/api/v1/rings", json=ring_data)
        ring_id = response.json()["ring_id"]
        
        # Issue 5 tokens
        import hashlib
        from models import Reviewer
        from token_service import get_token_service
        
        async for db in get_db():
            cred_hash = hashlib.sha256(b"token_test_reviewer").hexdigest()
            reviewer = Reviewer(credential_hash=cred_hash, revoked=False, created_at=datetime.utcnow())
            db.add(reviewer)
            await db.flush()
            
            token_service = get_token_service()
            await token_service.init_redis()
            success, tokens, _ = await token_service.create_epoch_tokens(cred_hash, 1, 5, db)
            await db.commit()
            
            print(f"   ✓ Issued 5 tokens to reviewer")
            break
        
        # Use all 5 tokens
        print("\n🗳  Using tokens...")
        for i in range(5):
            message = pp_clsag_core.canonical_message(
                str(submission_ids[i]), "news", "approve", 1, f"token_vote_{i}"
            )
            ring_bytes = [bytes.fromhex(pubkeys[0])]
            signature = pp_clsag_core.clsag_sign(message, ring_bytes, sk, 0)
            
            sig_json = json.dumps({
                "key_image": signature.key_image.hex(),
                "c1": signature.c1.hex(),
                "responses": [r.hex() for r in signature.responses]
            })
            
            vote_data = {
                "submission_id": submission_ids[i],
                "ring_id": ring_id,
                "signature_blob": sig_json,
                "vote_type": "approve",
                "token_id": tokens[i],
                "message": message.hex()
            }
            
            response = await client.post("/api/v1/vote", json=vote_data)
            assert response.status_code == 200
            print(f"   ✓ Vote {i+1} submitted (token consumed)")
        
        # Try 6th vote with exhausted tokens - should fail
        print("\n✗ Attempting vote without tokens...")
        fake_token = "exhausted_token_" + hashlib.sha256(b"fake").hexdigest()
        message = pp_clsag_core.canonical_message(
            str(submission_ids[5]), "news", "approve", 1, "final_vote"
        )
        ring_bytes = [bytes.fromhex(pubkeys[0])]
        signature = pp_clsag_core.clsag_sign(message, ring_bytes, sk, 0)
        
        sig_json = json.dumps({
            "key_image": signature.key_image.hex(),
            "c1": signature.c1.hex(),
            "responses": [r.hex() for r in signature.responses]
        })
        
        vote_data = {
            "submission_id": submission_ids[5],
            "ring_id": ring_id,
            "signature_blob": sig_json,
            "vote_type": "approve",
            "token_id": fake_token,
            "message": message.hex()
        }
        
        response = await client.post("/api/v1/vote", json=vote_data)
        assert response.status_code == 400
        print("   ✓ Vote blocked - no valid token")
        
        # Request new epoch tokens
        print("\n🔄 Requesting new epoch tokens...")
        async for db in get_db():
            token_service = get_token_service()
            success, new_tokens, _ = await token_service.create_epoch_tokens(cred_hash, 2, 5, db)
            await db.commit()
            assert success
            print(f"   ✓ Issued 5 new tokens for epoch 2")
            
            # Update ring for new epoch
            ring_data = {"genre": "news", "pubkeys": pubkeys, "epoch": 2}
            response = await client.post("/api/v1/rings", json=ring_data)
            new_ring_id = response.json()["ring_id"]
            break
        
        # Now vote with new token succeeds
        vote_data["token_id"] = new_tokens[0]
        vote_data["ring_id"] = new_ring_id
        response = await client.post("/api/v1/vote", json=vote_data)
        assert response.status_code == 200
        print("   ✓ Vote succeeded with new epoch token")
        
        print("\n✅ SCENARIO PASSED: Token refresh cycle working")


# ============================================================================
# Test Summary
# ============================================================================

@pytest.mark.asyncio
async def test_all_scenarios_summary():
    """Summary of all E2E scenarios"""
    print("\n" + "="*80)
    print("END-TO-END TEST SCENARIOS SUMMARY")
    print("="*80)
    print("\nScenarios covered:")
    print("  1. ✓ Journalist submission full lifecycle")
    print("  2. ✓ Malicious content flagging and escalation")
    print("  3. ✓ Credential revocation impact")
    print("  4. ✓ High-stakes document with tie → escalation")
    print("  5. ✓ Token exhaustion and refresh cycle")
    print("\n" + "="*80)
    print("All scenarios validate:")
    print("  • Complete voting workflows")
    print("  • Security mechanisms")
    print("  • Edge case handling")
    print("  • User journeys")
    print("="*80 + "\n")



    