#!/usr/bin/env python3
"""
Quick test script to verify ProofPals backend installation
Run this after setup to ensure everything works
"""

import asyncio
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

print("=" * 60)
print("ProofPals Backend Quick Test")
print("=" * 60)

# Test 1: Configuration
print("\n1. Testing configuration...")
try:
    from config import settings
    print(f"   ✓ Config loaded")
    print(f"   - Database: {settings.DATABASE_URL[:30]}...")
    print(f"   - Redis: {settings.REDIS_URL}")
    print(f"   - Debug mode: {settings.DEBUG}")
except Exception as e:
    print(f"   ✗ Config failed: {e}")
    sys.exit(1)

# Test 2: Database connection
print("\n2. Testing database connection...")
try:
    from database import engine
    import asyncio
    from sqlalchemy import text
    
    async def test_db():
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            return result.scalar()
    
    result = asyncio.run(test_db())
    if result == 1:
        print("   ✓ Database connection OK")
    else:
        print("   ✗ Database query returned unexpected result")
        sys.exit(1)
except Exception as e:
    print(f"   ✗ Database connection failed: {e}")
    print("   → Make sure PostgreSQL is running")
    sys.exit(1)

# Test 3: Redis connection
print("\n3. Testing Redis connection...")
try:
    import redis.asyncio as redis
    
    async def test_redis():
        client = await redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True
        )
        await client.set("test_key", "test_value")
        value = await client.get("test_key")
        await client.delete("test_key")
        await client.close()
        return value == "test_value"
    
    result = asyncio.run(test_redis())
    if result:
        print("   ✓ Redis connection OK")
    else:
        print("   ✗ Redis test failed")
        sys.exit(1)
except Exception as e:
    print(f"   ✗ Redis connection failed: {e}")
    print("   → Make sure Redis is running")
    sys.exit(1)

# Test 4: Crypto library
print("\n4. Testing crypto library...")
try:
    import pp_clsag_core
    
    # Test basic operations
    seed = pp_clsag_core.generate_seed()
    sk, pk = pp_clsag_core.derive_keypair(seed)
    
    print("   ✓ Crypto library loaded")
    print(f"   - Generated seed: {len(seed)} bytes")
    print(f"   - Generated keypair: sk={len(sk)}, pk={len(pk)} bytes")
except ImportError as e:
    print(f"   ✗ Crypto library not found: {e}")
    print("   → Run: cd ../pp_clsag_core && maturin develop --release")
    sys.exit(1)
except Exception as e:
    print(f"   ✗ Crypto library error: {e}")
    sys.exit(1)

# Test 5: Initialize database tables
print("\n5. Testing database initialization...")
try:
    from database import init_db
    
    asyncio.run(init_db())
    print("   ✓ Database tables created/verified")
except Exception as e:
    print(f"   ✗ Database initialization failed: {e}")
    sys.exit(1)

# Test 6: Services initialization
print("\n6. Testing services...")
try:
    from crypto_service import get_crypto_service
    from token_service import get_token_service
    from vote_service import get_vote_service
    from tally_service import get_tally_service
    
    crypto_service = get_crypto_service()
    token_service = get_token_service()
    vote_service = get_vote_service()
    tally_service = get_tally_service()
    
    print("   ✓ All services initialized")
    print(f"   - Crypto service: {crypto_service.__class__.__name__}")
    print(f"   - Token service: {token_service.__class__.__name__}")
    print(f"   - Vote service: {vote_service.__class__.__name__}")
    print(f"   - Tally service: {tally_service.__class__.__name__}")
except Exception as e:
    print(f"   ✗ Service initialization failed: {e}")
    sys.exit(1)

# Test 7: Crypto service health check
print("\n7. Testing crypto service health...")
try:
    health = crypto_service.health_check()
    if health["status"] == "healthy":
        print("   ✓ Crypto service healthy")
        print(f"   - Library: {health['library']}")
        print(f"   - Operations: {len(health['operations'])} available")
    else:
        print(f"   ✗ Crypto service unhealthy: {health.get('error')}")
        sys.exit(1)
except Exception as e:
    print(f"   ✗ Crypto health check failed: {e}")
    sys.exit(1)

# Test 8: Full integration test
print("\n8. Running integration test...")
try:
    from database import AsyncSessionLocal
    from models import Submission, Ring, Reviewer
    import hashlib
    
    async def integration_test():
        async with AsyncSessionLocal() as db:
            # Create a test submission
            submission = Submission(
                genre="test",
                content_ref="test_ref",
                submitter_ip_hash=hashlib.sha256(b"test_ip").hexdigest(),
                status="pending"
            )
            db.add(submission)
            await db.commit()
            await db.refresh(submission)
            
            # Create a test ring
            ring = Ring(
                genre="test",
                pubkeys=["abc123", "def456"],
                epoch=1,
                active=True
            )
            db.add(ring)
            await db.commit()
            await db.refresh(ring)
            
            # Create a test reviewer
            reviewer = Reviewer(
                credential_hash=hashlib.sha256(b"test_cred").hexdigest(),
                revoked=False
            )
            db.add(reviewer)
            await db.commit()
            
            print(f"   ✓ Created test submission (ID: {submission.id})")
            print(f"   ✓ Created test ring (ID: {ring.id})")
            print(f"   ✓ Created test reviewer")
            
            # Clean up
            await db.delete(submission)
            await db.delete(ring)
            await db.delete(reviewer)
            await db.commit()
            
            return True
    
    result = asyncio.run(integration_test())
    if result:
        print("   ✓ Integration test passed")
except Exception as e:
    print(f"   ✗ Integration test failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Summary
print("\n" + "=" * 60)
print("✅ All tests passed!")
print("=" * 60)
print("\nYou can now start the server:")
print("  python main.py")
print("\nOr:")
print("  uvicorn main:app --reload")
print("\nThen visit:")
print("  http://localhost:8000/health")
print("  http://localhost:8000/docs")
print("=" * 60)