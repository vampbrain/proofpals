#!/usr/bin/env python3
"""
ProofPals 5-Person Voting Scenario Test
Simulates a complete voting workflow with 5 reviewers
"""

import asyncio
import json
import hashlib
import requests
from datetime import datetime
from typing import List, Dict, Any

# Ensure stdout can emit Unicode on Windows consoles
try:
    import sys
    # Python 3.7+ supports reconfigure
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    try:
        import io, sys
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    except Exception:
        # If we can't reconfigure, fall back silently (prints may still fail)
        pass

# Configuration
BASE_URL = "http://localhost:8000"
ADMIN_TOKEN = None  # Will be set after login

# Step 1: Setup - Create admin and vetter accounts
async def setup_accounts():
    """Create necessary accounts for testing"""
    print("\n" + "="*80)
    print("STEP 1: Account Setup")
    print("="*80)
    
    global ADMIN_TOKEN
    
    # Register admin (using credentials from data.json)
    admin_data = {
        "username": "Yogesh",
        "email": "yogesh@proofpals.com",
        "password": "Ab2secure",
        "role": "admin"
    }
    
    response = requests.post(f"{BASE_URL}/api/v1/auth/register", json=admin_data)
    if response.status_code == 200:
        result = response.json()
        ADMIN_TOKEN = result["access_token"]
        print(f"✓ Admin registered: {admin_data['username']}")
    elif response.status_code == 400 and "already exists" in response.text.lower():
        # Login instead
        login_data = {"username": admin_data["username"], "password": admin_data["password"]}
        response = requests.post(f"{BASE_URL}/api/v1/auth/login", json=login_data)
        if response.status_code == 200:
            result = response.json()
            ADMIN_TOKEN = result["access_token"]
            print(f"✓ Admin logged in: {admin_data['username']}")
    else:
        print(f"✗ Admin setup failed: {response.status_code} - {response.text}")
        return False
    
    return True


# Step 2: Create a submission
async def create_submission() -> int:
    """Create a test submission"""
    print("\n" + "="*80)
    print("STEP 2: Create Submission")
    print("="*80)
    
    submission_data = {
        "genre": "news",
        "content_ref": "https://example.com/test-article-5person.pdf",
        "submitter_ip": "192.168.1.50"
    }
    
    response = requests.post(
        f"{BASE_URL}/api/v1/submissions",
        json=submission_data
    )
    
    if response.status_code == 200:
        result = response.json()
        submission_id = result["submission_id"]
        print(f"✓ Submission created: ID={submission_id}")
        print(f"  - Genre: {submission_data['genre']}")
        print(f"  - Content: {submission_data['content_ref']}")
        return submission_id
    else:
        print(f"✗ Submission creation failed: {response.status_code} - {response.text}")
        return None


# Step 3: Create ring with 5 reviewers
async def create_ring_with_keypairs() -> tuple:
    """Create ring with 5 reviewer keypairs"""
    print("\n" + "="*80)
    print("STEP 3: Create Ring with 5 Reviewers")
    print("="*80)
    
    try:
        import pp_clsag_core
    except ImportError:
        print("✗ Crypto library not available")
        return None, None, None
    
    # Generate 5 keypairs
    ring_size = 5
    keypairs = []
    pubkeys = []
    
    print(f"\nGenerating {ring_size} keypairs...")
    for i in range(ring_size):
        seed = pp_clsag_core.generate_seed()
        sk, pk = pp_clsag_core.derive_keypair(seed)

        # Convert list → bytes if needed
        if isinstance(sk, list):
            sk = bytes(sk)
        if isinstance(pk, list):
            pk = bytes(pk)

        keypairs.append((sk, pk))
        pubkeys.append(pk.hex())  # send as hex string
        print(f"  ✓ Reviewer {i+1}: pk={pk.hex()[:16]}...")
    
    # Create ring
    ring_data = {
        "genre": "news",
        "pubkeys": pubkeys,
        "epoch": 1
    }
    
    headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    response = requests.post(
        f"{BASE_URL}/api/v1/rings",
        json=ring_data,
        headers=headers
    )
    
    if response.status_code == 200:
        result = response.json()
        ring_id = result["ring_id"]
        print(f"\n✓ Ring created: ID={ring_id}")
        print(f"  - Size: {ring_size} members")
        print(f"  - Genre: {ring_data['genre']}")
        print(f"  - Epoch: {ring_data['epoch']}")
        return ring_id, keypairs, pubkeys
    else:
        print(f"\n✗ Ring creation failed: {response.status_code} - {response.text}")
        return None, None, None


# Step 4: Issue tokens to reviewers
async def issue_tokens_to_reviewers(num_reviewers: int) -> List[Dict[str, Any]]:
    """Issue tokens to all reviewers"""
    print("\n" + "="*80)
    print("STEP 4: Issue Tokens to Reviewers")
    print("="*80)
    
    reviewer_data = []
    
    # Create reviewers in database and issue tokens
    from database import AsyncSessionLocal
    from models import Reviewer
    from token_service import get_token_service
    
    async with AsyncSessionLocal() as db:
        token_service = get_token_service()
        await token_service.init_redis()
        
        for i in range(num_reviewers):
            # Create credential hash
            cred_hash = hashlib.sha256(
                f"reviewer_5person_{i}_{datetime.utcnow().isoformat()}".encode()
            ).hexdigest()
            
            # Create reviewer
            reviewer = Reviewer(
                credential_hash=cred_hash,
                revoked=False,
                created_at=datetime.utcnow()
            )
            db.add(reviewer)
            await db.flush()
            
            # Issue 3 tokens per reviewer
            success, tokens, error = await token_service.create_epoch_tokens(
                cred_hash, 1, 3, db
            )
            
            if success:
                reviewer_data.append({
                    "id": i,
                    "credential_hash": cred_hash,
                    "tokens": tokens
                })
                print(f"  ✓ Reviewer {i+1}: {len(tokens)} tokens issued")
            else:
                print(f"  ✗ Reviewer {i+1}: Token issuance failed - {error}")
        
        await db.commit()
    
    return reviewer_data


# Step 5: Cast votes
async def cast_votes(
    submission_id: int,
    ring_id: int,
    keypairs: List[tuple],
    pubkeys: List[str],
    reviewer_data: List[Dict[str, Any]],
    vote_pattern: List[str]
) -> List[Dict[str, Any]]:
    """Cast votes according to pattern"""
    print("\n" + "="*80)
    print("STEP 5: Cast Votes")
    print("="*80)
    
    import pp_clsag_core
    
    vote_results = []
    
    for i, vote_type in enumerate(vote_pattern):
        sk, pk = keypairs[i]
        token_id = reviewer_data[i]["tokens"][0]
        
        # Create canonical message
        message = pp_clsag_core.canonical_message(
            str(submission_id),
            "news",
            vote_type,
            1,
            f"5person_vote_{i}"
        )
        # Ensure message is bytes for signing
        if isinstance(message, list):
            message = bytes(message)
        
        # Convert pubkeys to bytes
        ring_bytes = [bytes.fromhex(pk) for pk in pubkeys]
        
        # Sign with LSAG (exposes accessible fields for tests)
        signature = pp_clsag_core.ring_sign(message, ring_bytes, sk, i)
        
        # Quick local verify to sanity-check signature
        try:
            ok, _ = pp_clsag_core.ring_verify(message, ring_bytes, signature)
            print(f"    local verify: {ok}")
        except Exception as _e:
            print(f"    local verify error: {_e}")

        # Normalize signature parts to bytes, then JSON-encode
        def _to_bytes(x):
            return bytes(x) if isinstance(x, list) else x

        signature_json = json.dumps({
            "key_image": _to_bytes(signature.key_image).hex(),
            "c_0": _to_bytes(signature.c_0).hex(),
            "responses": [_to_bytes(r).hex() for r in signature.responses]
        })
        
        # Submit vote
        vote_data = {
            "submission_id": submission_id,
            "ring_id": ring_id,
            "signature_blob": signature_json,
            "vote_type": vote_type,
            "token_id": token_id,
            "message": message.hex()
        }
        
        headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
        response = requests.post(
            f"{BASE_URL}/api/v1/vote",
            json=vote_data,
            headers=headers
        )
        
        if response.status_code == 200:
            result = response.json()
            vote_results.append({
                "reviewer": i + 1,
                "vote_type": vote_type,
                "success": True,
                "vote_id": result.get("vote_id")
            })
            print(f"  ✓ Reviewer {i+1} voted: {vote_type.upper()}")
        else:
            vote_results.append({
                "reviewer": i + 1,
                "vote_type": vote_type,
                "success": False,
                "error": response.text
            })
            print(f"  ✗ Reviewer {i+1} vote failed: {response.status_code} -> {response.text}")
    
    return vote_results


# Step 6: Get tally
async def get_tally(submission_id: int) -> Dict[str, Any]:
    """Get vote tally and decision"""
    print("\n" + "="*80)
    print("STEP 6: Compute Tally and Decision")
    print("="*80)
    
    response = requests.get(f"{BASE_URL}/api/v1/tally/{submission_id}")
    
    if response.status_code == 200:
        result = response.json()
        print(f"\n📊 Vote Results:")
        print(f"  - Approve:  {result['counts']['approve']}")
        print(f"  - Reject:   {result['counts']['reject']}")
        print(f"  - Escalate: {result['counts']['escalate']}")
        print(f"  - Flag:     {result['counts']['flag']}")
        print(f"  - Total:    {result['total_votes']}")
        print(f"\n🎯 Decision: {result['decision'].upper()}")
        return result
    else:
        print(f"✗ Tally retrieval failed: {response.status_code}")
        return None


# Test scenarios
async def run_scenario_1():
    """Scenario 1: Clear Approval (4 approve, 1 reject)"""
    print("\n" + "="*80)
    print("SCENARIO 1: Clear Approval")
    print("Expected: 4 approve, 1 reject → APPROVED")
    print("="*80)
    
    if not await setup_accounts():
        return
    
    submission_id = await create_submission()
    if not submission_id:
        return
    
    ring_id, keypairs, pubkeys = await create_ring_with_keypairs()
    if not ring_id:
        return
    
    reviewer_data = await issue_tokens_to_reviewers(5)
    if not reviewer_data:
        return
    
    vote_pattern = ["approve", "approve", "approve", "approve", "reject"]
    vote_results = await cast_votes(
        submission_id, ring_id, keypairs, pubkeys, reviewer_data, vote_pattern
    )
    
    tally = await get_tally(submission_id)
    
    # Verify result
    if tally and tally["decision"] == "approved":
        print("\n✅ SCENARIO 1 PASSED: Article approved as expected")
    else:
        print("\n❌ SCENARIO 1 FAILED: Unexpected decision")


async def run_scenario_2():
    """Scenario 2: Tie (2 approve, 2 reject, 1 escalate)"""
    print("\n" + "="*80)
    print("SCENARIO 2: Mixed Votes with Tie")
    print("Expected: 2 approve, 2 reject, 1 escalate → ESCALATED")
    print("="*80)
    
    if not await setup_accounts():
        return
    
    submission_id = await create_submission()
    if not submission_id:
        return
    
    ring_id, keypairs, pubkeys = await create_ring_with_keypairs()
    if not ring_id:
        return
    
    reviewer_data = await issue_tokens_to_reviewers(5)
    if not reviewer_data:
        return
    
    vote_pattern = ["approve", "approve", "reject", "reject", "escalate"]
    vote_results = await cast_votes(
        submission_id, ring_id, keypairs, pubkeys, reviewer_data, vote_pattern
    )
    
    tally = await get_tally(submission_id)
    
    # Verify result
    if tally and tally["decision"] == "escalated":
        print("\n✅ SCENARIO 2 PASSED: Content escalated as expected")
    else:
        print("\n❌ SCENARIO 2 FAILED: Unexpected decision")


async def run_scenario_3():
    """Scenario 3: Flagged Content (3 flags)"""
    print("\n" + "="*80)
    print("SCENARIO 3: Flagged Content")
    print("Expected: 3 flags → FLAGGED")
    print("="*80)
    
    if not await setup_accounts():
        return
    
    submission_id = await create_submission()
    if not submission_id:
        return
    
    ring_id, keypairs, pubkeys = await create_ring_with_keypairs()
    if not ring_id:
        return
    
    reviewer_data = await issue_tokens_to_reviewers(5)
    if not reviewer_data:
        return
    
    vote_pattern = ["flag", "flag", "flag", "approve", "approve"]
    vote_results = await cast_votes(
        submission_id, ring_id, keypairs, pubkeys, reviewer_data, vote_pattern
    )
    
    tally = await get_tally(submission_id)
    
    # Verify result
    if tally and tally["decision"] == "flagged":
        print("\n✅ SCENARIO 3 PASSED: Content flagged as expected")
    else:
        print("\n❌ SCENARIO 3 FAILED: Unexpected decision")


# Main execution
async def main():
    """Run all test scenarios"""
    print("\n" + "="*80)
    print("ProofPals 5-Person Voting Test Suite")
    print("="*80)
    
    # Run scenarios
    await run_scenario_1()
    await asyncio.sleep(2)
    
    await run_scenario_2()
    await asyncio.sleep(2)
    
    await run_scenario_3()
    
    print("\n" + "="*80)
    print("Test Suite Complete")
    print("="*80)


if __name__ == "__main__":
    asyncio.run(main())