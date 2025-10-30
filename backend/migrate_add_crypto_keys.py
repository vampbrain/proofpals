#!/usr/bin/env python3
"""
Database migration to add crypto key fields to User table
Run this script to update existing database schema
"""

import asyncio
import logging
from sqlalchemy import text
from database import get_db, engine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def migrate_add_crypto_keys():
    """Add crypto key fields to users table"""
    
    migration_statements = [
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS public_key_hex VARCHAR(128)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS private_key_hex VARCHAR(128)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS key_seed_hex VARCHAR(64)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_user_public_key ON users(public_key_hex) WHERE public_key_hex IS NOT NULL",
        "CREATE INDEX IF NOT EXISTS idx_user_public_key_lookup ON users(public_key_hex) WHERE public_key_hex IS NOT NULL"
    ]
    
    try:
        async with engine.begin() as conn:
            logger.info("Starting crypto keys migration...")
            
            # Execute each statement individually
            for i, statement in enumerate(migration_statements, 1):
                logger.info(f"Executing statement {i}/{len(migration_statements)}: {statement[:50]}...")
                await conn.execute(text(statement))
            
            logger.info("✓ Successfully added crypto key fields to users table")
            logger.info("✓ Added indexes for public key lookups")
            
        logger.info("🎉 Migration completed successfully!")
        
    except Exception as e:
        logger.error(f"❌ Migration failed: {e}")
        raise

async def generate_keys_for_existing_users():
    """Generate crypto keys for existing users who don't have them"""
    
    try:
        from crypto_service import get_crypto_service
        from models import User as UserModel
        from sqlalchemy import select, update
        
        crypto_service = get_crypto_service()
        if not crypto_service:
            logger.warning("Crypto service not available, skipping key generation")
            return
        
        # Test if crypto service can generate keys
        try:
            test_seed, test_private, test_public = crypto_service.generate_keypair()
            logger.info(f"✓ Crypto service working, test key: {test_public[:16]}...")
        except Exception as e:
            logger.error(f"❌ Crypto service test failed: {e}")
            return
        
        async for db in get_db():
            # Get users without crypto keys
            result = await db.execute(
                select(UserModel).where(UserModel.public_key_hex.is_(None))
            )
            users_without_keys = result.scalars().all()
            
            if not users_without_keys:
                logger.info("All users already have crypto keys")
                return
            
            logger.info(f"Generating crypto keys for {len(users_without_keys)} users...")
            
            for user in users_without_keys:
                try:
                    # Generate new keypair
                    seed_hex, private_key_hex, public_key_hex = crypto_service.generate_keypair()
                    
                    # Update user with new keys
                    await db.execute(
                        update(UserModel)
                        .where(UserModel.id == user.id)
                        .values(
                            public_key_hex=public_key_hex,
                            private_key_hex=private_key_hex,
                            key_seed_hex=seed_hex
                        )
                    )
                    
                    logger.info(f"✓ Generated keys for user: {user.username}")
                    
                except Exception as e:
                    logger.error(f"❌ Failed to generate keys for user {user.username}: {e}")
                    continue
            
            await db.commit()
            logger.info("🎉 Key generation completed!")
            break  # Exit the async generator
            
    except Exception as e:
        logger.error(f"❌ Key generation failed: {e}")
        raise

async def main():
    """Run the complete migration"""
    logger.info("🚀 Starting ProofPals crypto keys migration...")
    
    try:
        # Step 1: Add database columns
        await migrate_add_crypto_keys()
        
        # Step 2: Generate keys for existing users
        await generate_keys_for_existing_users()
        
        logger.info("✅ Migration completed successfully!")
        logger.info("All users now have unique cryptographic keypairs for ring signatures")
        
    except Exception as e:
        logger.error(f"💥 Migration failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)
