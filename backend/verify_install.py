#!/usr/bin/env python3
"""
Installation Verification Script
Checks that all components are properly installed
"""

import sys
import subprocess
from pathlib import Path
from dotenv import load_dotenv
import os

load_dotenv()  # <--- Load .env variables

import redis
import psycopg2

print("=" * 80)
print("ProofPals Installation Verification")
print("=" * 80)

errors = []
warnings = []


def check_python_version():
    print("\n1. Checking Python version...")
    version = sys.version_info
    if version.major == 3 and version.minor >= 11:
        print(f"   ✓ Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print(f"   ✗ Python {version.major}.{version.minor}.{version.micro} (need 3.11+)")
        errors.append("Python version too old")
        return False


def check_postgresql():
    print("\n2. Checking PostgreSQL via Python...")
    try:
        DATABASE_URL = os.getenv("DATABASE_URL")
        conn = psycopg2.connect(DATABASE_URL)
        conn.close()
        print(f"   ✓ Connected to PostgreSQL successfully")
        return True
    except Exception as e:
        print(f"   ✗ PostgreSQL connection failed: {e}")
        errors.append("PostgreSQL not reachable")
        return False


def check_redis():
    print("\n3. Checking Redis via Python...")
    try:
        REDIS_URL = os.getenv("REDIS_URL")
        r = redis.Redis.from_url(REDIS_URL)
        if r.ping():
            print(f"   ✓ Redis connected successfully (PING)")
            return True
        else:
            print(f"   ✗ Redis did not respond to PING")
            errors.append("Redis not reachable")
            return False
    except Exception as e:
        print(f"   ✗ Redis connection failed: {e}")
        errors.append("Redis not reachable")
        return False


def check_python_packages():
    print("\n4. Checking Python packages...")
    required_packages = [
        "fastapi",
        "uvicorn",
        "sqlalchemy",
        "asyncpg",
        "redis",
        "pydantic",
        "pydantic_settings"
    ]
    missing = []
    for package in required_packages:
        try:
            __import__(package.replace("-", "_"))
            print(f"   ✓ {package}")
        except ImportError:
            print(f"   ✗ {package}")
            missing.append(package)
    if missing:
        errors.append(f"Missing packages: {', '.join(missing)}")
        print(f"\n   Install with: pip install {' '.join(missing)}")
        return False
    return True


def check_crypto_library():
    print("\n5. Checking crypto library...")
    try:
        import pp_clsag_core
        seed = pp_clsag_core.generate_seed()
        sk, pk = pp_clsag_core.derive_keypair(seed)
        print(f"   ✓ pp_clsag_core works: seed={len(seed)} bytes, sk={len(sk)}, pk={len(pk)} bytes")
        return True
    except Exception as e:
        print(f"   ✗ Crypto library error: {e}")
        errors.append("pp_clsag_core not working")
        return False


def check_env_file():
    print("\n6. Checking .env file...")
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        print("   ✓ .env file exists")
        # Optional: verify keys
        db_url = os.getenv("DATABASE_URL")
        redis_url = os.getenv("REDIS_URL")
        if db_url and redis_url:
            print(f"   ✓ DATABASE_URL and REDIS_URL loaded")
            return True
        else:
            print(f"   ✗ Environment variables missing")
            errors.append(".env missing required variables")
            return False
    else:
        print("   ✗ .env file not found")
        errors.append(".env file missing")
        return False


def check_file_structure():
    print("\n7. Checking file structure...")
    required_files = [
        "config.py",
        "database.py",
        "models.py",
        "main.py",
        "crypto_service.py",
        "token_service.py",
        "vote_service.py",
        "tally_service.py",
        "requirements.txt"
    ]
    missing = []
    for filename in required_files:
        if not (Path(__file__).parent / filename).exists():
            print(f"   ✗ {filename}")
            missing.append(filename)
        else:
            print(f"   ✓ {filename}")
    if missing:
        errors.append(f"Missing files: {', '.join(missing)}")
        return False
    return True


def main():
    checks = [
        ("Python Version", check_python_version),
        ("PostgreSQL", check_postgresql),
        ("Redis", check_redis),
        ("Python Packages", check_python_packages),
        ("Crypto Library", check_crypto_library),
        (".env file", check_env_file),
        ("File Structure", check_file_structure),
    ]
    passed = 0
    failed = 0
    for name, func in checks:
        try:
            if func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"   ✗ {name} check failed: {e}")
            failed += 1

    print("\n" + "=" * 80)
    print("Installation Verification Summary")
    print("=" * 80)
    print(f"\nPassed: {passed}/{len(checks)}")
    print(f"Failed: {failed}/{len(checks)}")
    if errors:
        print(f"\n❌ Errors:")
        for e in errors:
            print(f" - {e}")
    if not errors:
        print("\n✅ Installation verification passed!")
        print("Next steps: python init_db.py, python main.py")
        return 0
    else:
        print("\n❌ Installation incomplete. Fix the above errors.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
