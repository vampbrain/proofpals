# ProofPals Backend Setup Guide

## Prerequisites

Before starting, ensure you have:
- Python 3.11+ installed
- PostgreSQL 15+ installed and running
- Redis 7+ installed and running
- The Rust crypto library (`pp_clsag_core`) built and installed

## Step 1: Install PostgreSQL (Without Docker)

### On macOS:
```bash
# Install PostgreSQL using Homebrew
brew install postgresql@15

# Start PostgreSQL
brew services start postgresql@15

# Create database and user
psql postgres
```

In PostgreSQL shell:
```sql
CREATE DATABASE proofpals_db;
CREATE USER proofpals WITH PASSWORD 'proofpals123';
GRANT ALL PRIVILEGES ON DATABASE proofpals_db TO proofpals;
\q
```

### On Ubuntu/Debian:
```bash
# Install PostgreSQL
sudo apt update
sudo apt install postgresql postgresql-contrib

# Start PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database and user
sudo -u postgres psql
```

In PostgreSQL shell:
```sql
CREATE DATABASE proofpals_db;
CREATE USER proofpals WITH PASSWORD 'proofpals123';
GRANT ALL PRIVILEGES ON DATABASE proofpals_db TO proofpals;
\q
```

### On Windows:
1. Download PostgreSQL installer from https://www.postgresql.org/download/windows/
2. Run installer and follow setup wizard
3. Use pgAdmin or psql to create database:
```sql
CREATE DATABASE proofpals_db;
CREATE USER proofpals WITH PASSWORD 'proofpals123';
GRANT ALL PRIVILEGES ON DATABASE proofpals_db TO proofpals;
```

## Step 2: Install Redis (Without Docker)

### On macOS:
```bash
brew install redis
brew services start redis
```

### On Ubuntu/Debian:
```bash
sudo apt update
sudo apt install redis-server
sudo systemctl start redis-server
sudo systemctl enable redis-server
```

### On Windows:
1. Download Redis from https://github.com/microsoftarchive/redis/releases
2. Extract and run `redis-server.exe`
3. Or use WSL2 and follow Ubuntu instructions

## Step 3: Setup Python Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt

# Install asyncpg for PostgreSQL async support
pip install asyncpg
```

## Step 4: Install Rust Crypto Library

```bash
# Navigate to crypto library directory
cd ../pp_clsag_core

# Build and install the library
pip install maturin
maturin develop --release

# Verify installation
python -c "import pp_clsag_core; print('Crypto library OK')"

# Return to backend directory
cd ../backend
```

## Step 5: Configure Environment

```bash
# Copy the .env file (already created)
# Edit if needed to change passwords or ports

# Verify database connection
python -c "from config import settings; print(settings.DATABASE_URL)"
```

## Step 6: Initialize Database

```bash
# Run the database initialization
python -c "
import asyncio
from database import init_db
asyncio.run(init_db())
print('Database initialized successfully')
"
```

## Step 7: Start the Server

```bash
# Start the backend server
python main.py

# Or use uvicorn directly:
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The server will start at http://localhost:8000

## Step 8: Verify Installation

Open your browser and visit:
- Health check: http://localhost:8000/health
- API docs: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Testing the System

### 1. Test Health Endpoint
```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00",
  "version": "1.0.0",
  "crypto_library": "pp_clsag_core",
  "database": "postgresql"
}
```

### 2. Create a Test Submission
```bash
curl -X POST http://localhost:8000/api/v1/submissions \
  -H "Content-Type: application/json" \
  -d '{
    "genre": "news",
    "content_ref": "https://example.com/article.pdf",
    "submitter_ip": "192.168.1.1"
  }'
```

### 3. Create a Test Ring
```bash
curl -X POST http://localhost:8000/api/v1/rings \
  -H "Content-Type: application/json" \
  -d '{
    "genre": "news",
    "pubkeys": [
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
    ],
    "epoch": 1
  }'
```

### 4. Run Complete Test Suite
```bash
# Run all tests
pytest test_backend.py -v

# Run with coverage
pytest test_backend.py -v --cov=app --cov-report=html
```

## Common Issues and Solutions

### Issue: Cannot connect to PostgreSQL
**Solution:**
```bash
# Check if PostgreSQL is running
# macOS:
brew services list | grep postgresql

# Linux:
sudo systemctl status postgresql

# Check if you can connect
psql -U proofpals -d proofpals_db -h localhost
```

### Issue: Cannot connect to Redis
**Solution:**
```bash
# Check if Redis is running
# macOS:
brew services list | grep redis

# Linux:
sudo systemctl status redis-server

# Test Redis connection
redis-cli ping
# Should return: PONG
```

### Issue: Crypto library not found
**Solution:**
```bash
# Reinstall the crypto library
cd ../pp_clsag_core
pip uninstall pp_clsag_core
maturin develop --release
cd ../backend
```

### Issue: Database tables not created
**Solution:**
```bash
# Reinitialize database
python -c "
import asyncio
from database import init_db, engine, Base
async def reset():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
asyncio.run(reset())
"
```

## Development Workflow

### 1. Start Development Services
```bash
# Terminal 1: PostgreSQL (if not running as service)
# Already running from setup

# Terminal 2: Redis (if not running as service)
# Already running from setup

# Terminal 3: Backend
source venv/bin/activate
uvicorn main:app --reload

# Terminal 4: Run tests
pytest --watch
```

### 2. Database Migrations (Future)
When you make model changes:
```bash
# Create migration
alembic revision --autogenerate -m "description"

# Apply migration
alembic upgrade head

# Rollback if needed
alembic downgrade -1
```

### 3. Monitoring Logs
```bash
# View server logs in real-time
tail -f logs/proofpals.log

# Or just watch the terminal running uvicorn
```

## Next Steps

1. ✅ Backend is running
2. ⬜ Build frontend React app
3. ⬜ Connect frontend to backend
4. ⬜ Test end-to-end voting flow
5. ⬜ Add authentication and authorization
6. ⬜ Deploy to production

## Architecture Overview

```
┌─────────────────┐
│   Frontend      │
│   (React)       │
└────────┬────────┘
         │
         │ HTTP/REST
         │
┌────────▼────────┐
│   FastAPI       │
│   Backend       │
├─────────────────┤
│ • Vote Service  │
│ • Token Service │
│ • Tally Service │
│ • Crypto Service│
└───┬─────────┬───┘
    │         │
    │         │
┌───▼───┐ ┌──▼───┐
│ Redis │ │ Postgres│
│       │ │         │
└───────┘ └─────────┘
```

## Production Checklist

Before deploying to production:

- [ ] Change SECRET_KEY to a random value
- [ ] Set DEBUG=False
- [ ] Use strong database passwords
- [ ] Configure CORS for specific origins
- [ ] Set up HTTPS/TLS
- [ ] Configure rate limiting
- [ ] Set up monitoring and alerting
- [ ] Create backup strategy for database
- [ ] Review and harden security settings
- [ ] Set up logging aggregation
- [ ] Configure firewall rules

## Support

For issues or questions:
1. Check the logs in the terminal
2. Review this setup guide
3. Check the tasklist.md for architecture details
4. Test each component individually