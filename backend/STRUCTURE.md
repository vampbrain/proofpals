# ProofPals Backend Project Structure

```
/backend
│
├── config.py                 # Configuration and environment variables
├── database.py              # Database setup and session management
├── models.py                # SQLAlchemy database models (9 tables)
├── main.py                  # FastAPI application and routes
│
├── crypto_service.py        # Wrapper for Rust crypto library
├── token_service.py         # Token management with Redis atomicity
├── vote_service.py          # Vote submission and verification
├── tally_service.py         # Vote counting and decision logic
│
├── requirements.txt         # Python dependencies
├── .env                     # Environment configuration
│
├── SETUP.md                # Installation and setup guide
├── STRUCTURE.md            # This file
│
├── quick_test.py           # Quick verification script
├── test_concurrency.py     # Critical atomicity tests
└── test_backend.py         # Full test suite
```

## Core Files Explained

### Configuration Files

**config.py**
- Loads environment variables using Pydantic Settings
- Contains all configurable parameters
- Provides `get_settings()` function for dependency injection

**database.py**
- Async SQLAlchemy setup with PostgreSQL
- Connection pooling configuration
- Provides `get_db()` dependency for FastAPI routes
- `init_db()` and `close_db()` for lifecycle management

**.env**
- Database URL (PostgreSQL)
- Redis URL
- Secret keys and security settings
- Rate limits and thresholds

### Database Models

**models.py** - 9 tables:

1. **Submission** - Content submissions from users
   - genre, content_ref, status, timestamps
   - IP/MAC hashes for escalation only

2. **Ring** - Anonymity rings of reviewer public keys
   - genre, pubkeys (JSON array), epoch, active flag
   - Indexed for fast lookups

3. **Reviewer** - Verified reviewers with credentials
   - credential_hash (unique), revoked flag
   - Links to blind signatures

4. **Vote** - Individual votes on submissions
   - signature_blob, key_image, vote_type, token_id
   - **Critical indexes**: (submission_id, key_image) prevents duplicates

5. **Token** - Epoch tokens for vote consumption
   - token_id (PK), credential_hash, redeemed flag
   - Atomic consumption via Redis + database

6. **Escalation** - Flagged submissions
   - reason, evidence_blob (encrypted), status
   - For human review and legal requests

7. **AuditLog** - Append-only audit trail
   - event_type, entity_type, details (JSON)
   - Full traceability

8. **Tally** - Computed vote tallies
   - vote counts by type, final_decision
   - Links to submission

9. **Revocation** - Revoked credentials
   - credential_hash, reason, timestamp
   - Checked before token consumption

### Service Layer

**crypto_service.py**
- Wraps Rust `pp_clsag_core` library
- Key functions:
  - `verify_clsag_signature()` - Returns (is_valid, key_image)
  - `canonicalize_ring()` - Sort public keys
  - `verify_blind_signature()` - For credential verification
  - `health_check()` - Service status

**token_service.py** ⚠️ CRITICAL FOR ATOMICITY
- `verify_and_consume_token()` - **THE KEY FUNCTION**
  - Uses Redis SETNX for atomic locking
  - Checks database for token validity
  - Verifies credential not revoked
  - Updates database atomically
  - **Prevents double-spending/double-voting**
- `create_epoch_tokens()` - Issue tokens to credentials
- `get_token_stats()` - Monitoring metrics

**vote_service.py**
- `submit_vote()` - Full vote processing pipeline:
  1. Consume token (atomic)
  2. Verify ring signature
  3. Check duplicate key_image
  4. Store vote
  5. Log audit trail
- `get_vote_count()` - Vote statistics
- `check_has_voted()` - Duplicate detection

**tally_service.py**
- `compute_tally()` - Vote counting and decision
  - Decision rules:
    - flags >= 3 → ESCALATED
    - approve > reject → APPROVED
    - reject > approve → REJECTED
    - tie → ESCALATED
- `should_compute_tally()` - Check vote threshold
- `get_statistics()` - System metrics

### Main Application

**main.py**
- FastAPI app initialization
- CORS middleware
- 11 API endpoints:
  - `POST /api/v1/vote` - Submit vote
  - `GET /api/v1/tally/{id}` - Get tally
  - `POST /api/v1/present-credential` - Get tokens
  - `POST /api/v1/submissions` - Create submission
  - `GET /api/v1/submissions/{id}` - Get submission
  - `POST /api/v1/rings` - Create ring
  - `GET /api/v1/rings/{id}` - Get ring
  - `GET /api/v1/statistics` - System stats
  - `GET /health` - Health check
  - Plus docs at `/docs` and `/redoc`

### Testing Files

**quick_test.py**
- Verifies basic installation
- Tests all dependencies
- Runs integration test
- Quick sanity check

**test_concurrency.py** ⚠️ CRITICAL TEST
- Tests atomic token consumption
- Runs 100 concurrent requests
- **Must pass**: Only 1 should succeed
- Proves no race conditions
- Should be run before production

**test_backend.py**
- Full test suite (from your friend)
- Unit tests for all endpoints
- Integration tests
- Coverage reporting

## Data Flow

### Vote Submission Flow

```
1. Client → POST /api/v1/vote
   ├─ Request includes:
   │  - submission_id
   │  - ring_id
   │  - signature_blob (CLSAG)
   │  - vote_type
   │  - token_id
   │  └─ message (canonical format)
   │
2. FastAPI main.py
   └─ Validates request schema
   
3. vote_service.submit_vote()
   ├─ 3a. token_service.verify_and_consume_token()
   │   ├─ Redis: SETNX token:{id} (atomic lock)
   │   ├─ Database: Check token exists & not redeemed
   │   ├─ Database: Check credential not revoked
   │   └─ Database: UPDATE token SET redeemed=TRUE
   │
   ├─ 3b. Fetch ring from database
   │
   ├─ 3c. crypto_service.verify_clsag_signature()
   │   └─ Rust: pp_clsag_core.clsag_verify()
   │       → Returns (is_valid, key_image)
   │
   ├─ 3d. Check duplicate: SELECT * WHERE key_image=X
   │   └─ If exists → REJECT (already voted)
   │
   ├─ 3e. INSERT INTO votes
   │
   └─ 3f. Log audit entry
   
4. Check vote threshold
   └─ If enough votes → tally_service.compute_tally()
   
5. Return success response
```

### Token Issuance Flow

```
1. Client → POST /api/v1/present-credential
   ├─ credential_hash
   ├─ epoch
   └─ token_count
   
2. token_service.create_epoch_tokens()
   ├─ Verify credential exists
   ├─ Check not revoked
   ├─ Generate N unique token_ids (SHA256)
   ├─ INSERT INTO tokens (batch)
   └─ Return token_ids[]
   
3. Client stores tokens locally
   └─ Uses one token per vote
```

## Security Features

### 1. Atomic Token Consumption
- Redis SETNX prevents simultaneous consumption
- Database transaction ensures consistency
- Race condition impossible

### 2. Duplicate Vote Prevention
- Key image uniqueness per submission
- Database unique index enforces it
- Same credential can't vote twice

### 3. Anonymity Protection
- Ring signatures hide identity
- Key images link votes without revealing signer
- No PK→identity mapping stored

### 4. Audit Trail
- All events logged immutably
- IP addresses only in audit logs
- Escalation requires trustee consensus

### 5. Revocation System
- Credentials can be revoked
- Checked before every token use
- Prevents misbehaving reviewers

## Performance Considerations

### Database Indexes
- `votes(submission_id, key_image)` - Duplicate detection
- `tokens(token_id, redeemed)` - Fast lookups
- `rings(genre, epoch, active)` - Ring queries
- All foreign keys indexed

### Connection Pooling
- SQLAlchemy pool: 10 connections, 20 max overflow
- Redis connection pool managed automatically
- Async operations throughout

### Caching Strategy
- Redis for token locks (5 min expiry)
- Database query results cached where appropriate
- Ring data rarely changes (can cache)

## Monitoring Endpoints

- `GET /health` - Service status
- `GET /api/v1/statistics` - Vote/token metrics
- Audit logs in database for analysis
- Prometheus metrics (future)

## Next Steps

1. ✅ Backend complete
2. ⬜ Build frontend
3. ⬜ Add authentication
4. ⬜ Deploy to staging
5. ⬜ Security audit
6. ⬜ Load testing
7. ⬜ Production deployment