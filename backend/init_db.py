#!/usr/bin/env python3
"""
Database Initialization Script
Run this to set up the database tables
"""

import asyncio
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

print("=" * 80)
print("ProofPals Database Initialization")
print("=" * 80)


async def main():
    """Initialize database"""
    
    # Step 1: Check configuration
    print("\n1. Checking configuration...")
    try:
        from config import settings
        print(f"   ✓ Configuration loaded")
        print(f"   - Database: {settings.DATABASE_URL.split('@')[0]}@...")
    except Exception as e:
        print(f"   ✗ Configuration error: {e}")
        return 1
    
    # Step 2: Test database connection
    print("\n2. Testing database connection...")
    try:
        from database import check_connection
        is_connected = await check_connection()
        if is_connected:
            print("   ✓ Database connection successful")
        else:
            print("   ✗ Database connection failed")
            print("\n   Troubleshooting:")
            print("   - Is PostgreSQL running? Check: brew services list | grep postgresql")
            print("   - Is the database created? Run: psql postgres")
            print("     Then: CREATE DATABASE proofpals_db;")
            print("   - Check DATABASE_URL in .env file")
            return 1
    except Exception as e:
        print(f"   ✗ Connection error: {e}")
        return 1
    
    # Step 3: Import models
    print("\n3. Loading database models...")
    try:
        from models import (
            Submission, Ring, Reviewer, Vote, Token,
            Escalation, AuditLog, Tally, Revocation,
            get_all_models
        )
        models = get_all_models()
        print(f"   ✓ Loaded {len(models)} models")
        for model in models:
            print(f"     - {model.__tablename__}")
    except Exception as e:
        print(f"   ✗ Model loading error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    # Step 4: Create tables
    print("\n4. Creating database tables...")
    try:
        from database import init_db
        await init_db()
        print("   ✓ All tables created successfully")
    except Exception as e:
        print(f"   ✗ Table creation error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    # Step 5: Verify tables
    print("\n5. Verifying tables...")
    try:
        from database import engine
        from sqlalchemy import inspect, text
        
        async with engine.connect() as conn:
            # Get table names from database
            result = await conn.execute(text("""
                SELECT tablename 
                FROM pg_tables 
                WHERE schemaname = 'public'
                ORDER BY tablename
            """))
            
            tables = [row[0] for row in result]
            print(f"   ✓ Found {len(tables)} tables in database:")
            for table in tables:
                print(f"     - {table}")
            
            # Check specific tables
            expected_tables = {
                'submissions', 'rings', 'reviewers', 'votes', 'tokens',
                'escalations', 'audit_logs', 'tallies', 'revocations'
            }
            missing = expected_tables - set(tables)
            if missing:
                print(f"\n   ⚠️  Warning: Missing tables: {missing}")
            else:
                print(f"\n   ✓ All expected tables present")
    
    except Exception as e:
        print(f"   ⚠️  Warning: Could not verify tables: {e}")
        print("   Tables might still be created correctly")
    
    # Step 6: Show schema info
    print("\n6. Database schema:")
    try:
        from models import print_schema_info
        print_schema_info()
    except:
        pass
    
    # Success!
    print("\n" + "=" * 80)
    print("✅ Database initialization complete!")
    print("=" * 80)
    print("\nNext steps:")
    print("  1. Start the server: python main.py")
    print("  2. Test the API: http://localhost:8000/docs")
    print("  3. Run tests: pytest test_backend.py -v")
    print("=" * 80)
    
    return 0


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nFatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)