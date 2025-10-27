#!/usr/bin/env python3
"""
Create Admin User Script
Run this after database initialization to create the first admin user
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from auth_service import get_auth_service, UserCreate
from database import get_db


async def create_admin_user():
    """Create the first admin user"""
    
    print("=" * 80)
    print("ProofPals - Create Admin User")
    print("=" * 80)
    
    # Get admin details
    print("\nEnter admin credentials:")
    username = input("Username (default: admin): ").strip() or "admin"
    email = input("Email (default: admin@proofpals.local): ").strip() or "admin@proofpals.local"
    
    # Password with validation
    while True:
        password = input("Password (min 8 chars, must have upper, lower, digit): ").strip()
        if len(password) >= 8 and \
           any(c.isupper() for c in password) and \
           any(c.islower() for c in password) and \
           any(c.isdigit() for c in password):
            break
        print("❌ Password doesn't meet requirements. Try again.")
    
    # Create user
    print("\nCreating admin user...")
    
    auth_service = get_auth_service()
    
    user_create = UserCreate(
        username=username,
        email=email,
        password=password,
        role="admin"
    )
    
    async for db in get_db():
        success, user_id, error = await auth_service.create_user(user_create, db)
        
        if not success:
            print(f"❌ Failed to create admin user: {error}")
            return 1
        
        print(f"✅ Admin user created successfully!")
        print(f"   User ID: {user_id}")
        print(f"   Username: {username}")
        print(f"   Email: {email}")
        print(f"   Role: admin")
        print("\nYou can now login at POST /api/v1/auth/login")
        
        break
    
    return 0


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(create_admin_user())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\nCancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nFatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)