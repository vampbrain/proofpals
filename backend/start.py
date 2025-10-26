#!/usr/bin/env python3
"""
ProofPals Backend Startup Script
"""

import os
import sys
import subprocess
import asyncio
import logging
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def check_dependencies():
    """Check if all required dependencies are installed"""
    try:
        import fastapi
        import uvicorn
        import sqlalchemy
        import redis
        import pydantic
        logger.info("✓ All Python dependencies are installed")
        return True
    except ImportError as e:
        logger.error(f"✗ Missing dependency: {e}")
        return False

def check_rust_crypto_library():
    """Check if the Rust crypto library is available"""
    try:
        # Add the crypto library path
        crypto_path = Path(__file__).parent.parent / "pp_clsag_core"
        sys.path.insert(0, str(crypto_path))
        
        import pp_clsag_core
        logger.info("✓ Rust crypto library is available")
        return True
    except ImportError as e:
        logger.error(f"✗ Rust crypto library not found: {e}")
        logger.error("Please build the crypto library first:")
        logger.error("  cd ../pp_clsag_core")
        logger.error("  cargo build --release")
        logger.error("  pip install .")
        return False

def check_redis_connection():
    """Check if Redis is running"""
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, db=0)
        r.ping()
        logger.info("✓ Redis is running")
        return True
    except Exception as e:
        logger.error(f"✗ Redis connection failed: {e}")
        logger.error("Please start Redis:")
        logger.error("  redis-server")
        return False

def setup_database():
    """Setup the database"""
    try:
        from app.database import engine, Base
        Base.metadata.create_all(bind=engine)
        logger.info("✓ Database setup complete")
        return True
    except Exception as e:
        logger.error(f"✗ Database setup failed: {e}")
        return False

def run_migrations():
    """Run database migrations"""
    try:
        # Check if alembic is available
        result = subprocess.run(
            ["alembic", "upgrade", "head"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent
        )
        
        if result.returncode == 0:
            logger.info("✓ Database migrations completed")
            return True
        else:
            logger.error(f"✗ Migration failed: {result.stderr}")
            return False
    except FileNotFoundError:
        logger.warning("⚠ Alembic not found, skipping migrations")
        return True
    except Exception as e:
        logger.error(f"✗ Migration error: {e}")
        return False

def start_server():
    """Start the FastAPI server"""
    try:
        import uvicorn
        from main import app
        
        logger.info("🚀 Starting ProofPals Backend Server...")
        logger.info("📡 Server will be available at: http://localhost:8000")
        logger.info("📚 API documentation at: http://localhost:8000/docs")
        logger.info("🔍 Health check at: http://localhost:8000/health")
        
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8000,
            reload=True,
            log_level="info"
        )
    except Exception as e:
        logger.error(f"✗ Failed to start server: {e}")
        return False

def main():
    """Main startup function"""
    logger.info("🔧 ProofPals Backend Startup")
    logger.info("=" * 50)
    
    # Check dependencies
    if not check_dependencies():
        logger.error("❌ Dependency check failed")
        return 1
    
    # Check Rust crypto library
    if not check_rust_crypto_library():
        logger.error("❌ Crypto library check failed")
        return 1
    
    # Check Redis
    if not check_redis_connection():
        logger.error("❌ Redis check failed")
        return 1
    
    # Setup database
    if not setup_database():
        logger.error("❌ Database setup failed")
        return 1
    
    # Run migrations
    if not run_migrations():
        logger.error("❌ Migration failed")
        return 1
    
    logger.info("✅ All checks passed!")
    logger.info("=" * 50)
    
    # Start server
    start_server()
    return 0

if __name__ == "__main__":
    sys.exit(main())
