"""
ProofPals Database Configuration
Complete async SQLAlchemy setup with PostgreSQL
"""

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, declarative_base
from sqlalchemy.pool import NullPool, QueuePool
from typing import AsyncGenerator
import logging

logger = logging.getLogger(__name__)

# Import settings
try:
    from config import settings
    DATABASE_URL = settings.DATABASE_URL
except ImportError:
    # Fallback for testing
    DATABASE_URL = "postgresql://proofpals:proofpals123@localhost:5432/proofpals_db"

# Convert postgres:// to postgresql+asyncpg:// for async driver
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
elif DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)

logger.info(f"Database URL configured: {DATABASE_URL.split('@')[0]}@...")

# Create async engine with proper configuration
engine = create_async_engine(
    DATABASE_URL,
    echo=False,  # Set to True for SQL query logging
    future=True,
    pool_pre_ping=True,  # Verify connections before using
    pool_size=10,        # Number of connections to maintain
    max_overflow=20,     # Additional connections allowed
    pool_recycle=3600,   # Recycle connections after 1 hour
    poolclass=QueuePool,
)

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    """Base class for all database models"""
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency for getting database session
    
    Usage in FastAPI:
        @app.get("/route")
        async def my_route(db: AsyncSession = Depends(get_db)):
            # Use db here
            pass
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            await session.close()


async def init_db():
    """
    Initialize database - create all tables
    
    This should be called on application startup
    """
    try:
        async with engine.begin() as conn:
            # Import all models to ensure they're registered
            from models import (
                Submission, Ring, Reviewer, Vote, Token,
                Escalation, AuditLog, Tally, Revocation
            )
            
            # Create all tables
            await conn.run_sync(Base.metadata.create_all)
            logger.info("✓ Database tables created/verified")
            
            # Log table names
            table_names = Base.metadata.tables.keys()
            logger.info(f"  Tables: {', '.join(table_names)}")
            
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise


async def drop_all_tables():
    """
    Drop all tables (use with caution!)
    Only for testing/development
    """
    try:
        async with engine.begin() as conn:
            from models import Base
            await conn.run_sync(Base.metadata.drop_all)
            logger.warning("⚠️  All database tables dropped")
    except Exception as e:
        logger.error(f"Failed to drop tables: {e}")
        raise


async def reset_db():
    """
    Reset database - drop and recreate all tables
    Only for testing/development
    """
    logger.warning("⚠️  Resetting database...")
    await drop_all_tables()
    await init_db()
    logger.info("✓ Database reset complete")


async def close_db():
    """Close database connections"""
    try:
        await engine.dispose()
        logger.info("✓ Database connections closed")
    except Exception as e:
        logger.error(f"Error closing database: {e}")


async def check_connection():
    """
    Check database connection
    Returns True if connection is working
    """
    try:
        async with engine.connect() as conn:
            from sqlalchemy import text
            result = await conn.execute(text("SELECT 1"))
            value = result.scalar()
            return value == 1
    except Exception as e:
        logger.error(f"Database connection check failed: {e}")
        return False


# For testing and scripts
if __name__ == "__main__":
    import asyncio
    
    async def test_db():
        print("Testing database connection...")
        
        # Test connection
        is_connected = await check_connection()
        if is_connected:
            print("✓ Database connection successful")
        else:
            print("✗ Database connection failed")
            return
        
        # Initialize tables
        print("\nInitializing database tables...")
        await init_db()
        
        # Show tables
        print("\nDatabase ready!")
        print(f"Tables created: {len(Base.metadata.tables)}")
        for table_name in Base.metadata.tables.keys():
            print(f"  - {table_name}")
    
    asyncio.run(test_db())