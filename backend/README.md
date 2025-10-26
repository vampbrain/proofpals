# ProofPals Backend

A comprehensive FastAPI backend for the ProofPals anonymous journalist review system, featuring cryptographic primitives, rate limiting, concurrency protection, and comprehensive monitoring.

## Features

- **🔐 Cryptographic Operations**: Integration with Rust crypto library for CLSAG signatures, blind RSA, and Pedersen commitments
- **🗳️ Anonymous Voting**: Ring-based anonymous voting with linkability detection
- **🎫 Token Management**: Epoch-based token issuance and credential revocation
- **⚡ Performance**: Rate limiting, concurrency protection, and Redis caching
- **📊 Monitoring**: Comprehensive logging, metrics, and audit trails
- **🛡️ Security**: Input validation, CORS protection, and security headers

## Architecture

```
backend/
├── app/
│   ├── models/          # SQLAlchemy database models
│   ├── schemas/         # Pydantic request/response schemas
│   ├── services/        # Business logic services
│   ├── middleware/      # Rate limiting and concurrency protection
│   ├── utils/           # Security and utility functions
│   └── database/        # Database configuration
├── alembic/             # Database migrations
├── main.py              # FastAPI application entry point
├── start.py             # Startup script with health checks
├── requirements.txt     # Python dependencies
└── test_backend.py      # Comprehensive test suite
```

## Quick Start

### Prerequisites

1. **Python 3.8+** with virtual environment
2. **Redis** server running on localhost:6379
3. **Rust crypto library** built and installed (see `../pp_clsag_core/`)

### Installation

1. **Clone and navigate to backend**:
   ```bash
   cd backend
   ```

2. **Create virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Build and install crypto library**:
   ```bash
   cd ../pp_clsag_core
   cargo build --release
   pip install .
   cd ../backend
   ```

5. **Start Redis**:
   ```bash
   redis-server
   ```

6. **Run startup script**:
   ```bash
   python start.py
   ```

The server will be available at:
- **API**: http://localhost:8000
- **Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

## API Endpoints

### Core Operations

- `POST /rings` - Create voting rings (admin only)
- `GET /rings/{id}/pubkeys` - Get ring public keys (server internal)
- `POST /vetter/blind-sign` - Create blind signatures (vetter only)
- `POST /present-credential` - Present credentials and receive tokens
- `POST /vote` - Submit anonymous votes
- `GET /tally/{id}` - Get tally results (admin only)
- `POST /revoke-credential` - Revoke credentials (vetter only)

### Monitoring

- `GET /health` - System health check
- `GET /metrics` - System metrics (admin only)
- `GET /events` - Audit events (admin only)

## Configuration

Copy `env.example` to `.env` and modify as needed:

```bash
cp env.example .env
```

Key settings:
- `DATABASE_URL`: SQLite database path
- `REDIS_HOST/PORT`: Redis connection details
- `SECRET_KEY`: Cryptographic secret key
- `RATE_LIMIT_REQUESTS`: Requests per minute limit
- `VOTE_THRESHOLD`: Minimum votes for tallying

## Authentication

The API uses API key authentication. Set the `X-API-Key` header:

```bash
curl -H "X-API-Key: admin-key-123" http://localhost:8000/health
```

Default API keys (change in production):
- `admin-key-123`: Full admin access
- `vetter-key-456`: Vetter operations only
- `server-internal-key-789`: Server internal operations

## Database

The system uses SQLite by default with the following tables:

- **submissions**: Content submissions for review
- **rings**: Anonymous voting rings
- **reviewers**: Credential management
- **votes**: Anonymous vote records
- **tokens**: Epoch-based voting tokens
- **escalations**: Flagged content escalations
- **audit_logs**: System audit trail
- **tallies**: Vote aggregation results
- **revocations**: Revoked credentials

### Migrations

Run database migrations:

```bash
alembic upgrade head
```

## Testing

Run the comprehensive test suite:

```bash
pytest test_backend.py -v
```

Tests cover:
- API endpoint functionality
- Data validation
- Rate limiting
- Concurrency protection
- Security features
- Database operations
- Service integration

## Security Features

### Rate Limiting
- Sliding window rate limiting
- Configurable requests per minute
- Rate limit headers in responses

### Concurrency Protection
- Request semaphores
- Resource-level locking
- Race condition prevention

### Input Validation
- Pydantic schema validation
- SQL injection prevention
- XSS protection
- Input sanitization

### Audit Logging
- Comprehensive event logging
- Security event tracking
- Audit trail export
- Log retention policies

## Performance Features

### Caching
- Redis-based caching
- Token validation caching
- Ring data caching
- Tally result caching

### Batch Operations
- Batch signature verification
- Batch token operations
- Efficient database queries
- Connection pooling

### Monitoring
- Real-time metrics
- Performance tracking
- Health checks
- System statistics

## Development

### Code Style
- Black for code formatting
- isort for import sorting
- flake8 for linting
- mypy for type checking

### Running in Development
```bash
# With auto-reload
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# With specific log level
uvicorn main:app --log-level debug
```

### Adding New Endpoints

1. **Define schema** in `app/schemas/`
2. **Add model** in `app/models/`
3. **Create service** in `app/services/`
4. **Add endpoint** in `main.py`
5. **Write tests** in `test_backend.py`

## Production Deployment

### Environment Variables
Set production environment variables:
- `DEBUG=false`
- `SECRET_KEY=<strong-random-key>`
- `DATABASE_URL=<production-database>`
- `REDIS_HOST=<production-redis>`

### Security Checklist
- [ ] Change default API keys
- [ ] Use strong SECRET_KEY
- [ ] Enable HTTPS
- [ ] Configure CORS properly
- [ ] Set up monitoring
- [ ] Enable log aggregation
- [ ] Configure backup strategy

### Scaling Considerations
- Use PostgreSQL for production database
- Deploy Redis cluster for high availability
- Use load balancer for multiple instances
- Implement horizontal scaling
- Monitor resource usage

## Troubleshooting

### Common Issues

1. **Redis connection failed**:
   ```bash
   redis-server
   ```

2. **Crypto library not found**:
   ```bash
   cd ../pp_clsag_core
   cargo build --release
   pip install .
   ```

3. **Database errors**:
   ```bash
   alembic upgrade head
   ```

4. **Import errors**:
   ```bash
   pip install -r requirements.txt
   ```

### Logs
Check application logs for detailed error information:
```bash
tail -f logs/app.log
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Run the test suite
5. Submit a pull request

## License

This project is part of the ProofPals system. See the main repository for license information.
