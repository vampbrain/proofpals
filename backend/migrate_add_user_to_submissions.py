#!/usr/bin/env python3
"""
Migration: Add user_id to submissions table
"""

import asyncio
import logging
from sqlalchemy import text
from database import get_db

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def migrate_add_user_to_submissions():
    """Add user_id column to submissions table"""
    logger.info("🚀 Starting submissions user association migration...")
    
    try:
        async for db in get_db():
            # Add user_id column to submissions table
            logger.info("Adding user_id column to submissions table...")
            await db.execute(text("""
                ALTER TABLE submissions 
                ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id)
            """))
            
            # Create index for user_id
            logger.info("Creating index on user_id...")
            await db.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_submission_user_id ON submissions(user_id)
            """))
            
            await db.commit()
            logger.info("✅ Successfully added user_id to submissions table")
            break
            
    except Exception as e:
        logger.error(f"❌ Migration failed: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(migrate_add_user_to_submissions())
