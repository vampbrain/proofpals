"""
Configuration Updates for backend/config.py

Add these settings to the Settings class in backend/config.py
"""

# ============================================================================
# ADD THESE FIELDS TO THE Settings CLASS
# ============================================================================

class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # ... existing fields ...
    
    # Rate Limiting Configuration (ADD THESE)
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_PER_IP: int = 100  # requests per window
    RATE_LIMIT_PER_USER: int = 200  # requests per window for authenticated users
    RATE_LIMIT_PER_TOKEN: int = 50  # vote submissions per window
    RATE_LIMIT_WINDOW: int = 60  # window in seconds
    RATE_LIMIT_BURST: int = 20  # burst allowance
    
    # JWT Configuration (ADD THESE if not present)
    JWT_SECRET_KEY: str = "your-secret-key-change-in-production"  # Same as SECRET_KEY or separate
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    
    # Monitoring Configuration (ADD THESE)
    MONITORING_ENABLED: bool = True
    PROMETHEUS_ENABLED: bool = True
    ANOMALY_DETECTION_ENABLED: bool = True
    
    # Escalation Configuration (ADD THESE)
    ESCALATION_ENABLED: bool = True
    ESCALATION_WORKER_ENABLED: bool = False  # Set to True when Celery is configured
    ESCALATION_EMAIL_NOTIFICATIONS: bool = False
    ESCALATION_WEBHOOK_URL: Optional[str] = None
    
    # Performance Configuration (ADD THESE)
    MAX_CONCURRENT_REQUESTS: int = 1000
    REQUEST_TIMEOUT: int = 30  # seconds
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20
    
    # Logging Configuration (ADD THESE)
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"  # "json" or "text"
    LOG_FILE: Optional[str] = "logs/proofpals.log"
    
    class Config:
        env_file = ".env"
        case_sensitive = True


# ============================================================================
# EXAMPLE .env FILE ADDITIONS
# ============================================================================

"""
Add these to your .env file:

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_IP=100
RATE_LIMIT_PER_USER=200
RATE_LIMIT_PER_TOKEN=50
RATE_LIMIT_WINDOW=60
RATE_LIMIT_BURST=20

# JWT
JWT_SECRET_KEY=your-super-secret-jwt-key-change-in-production
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=30

# Monitoring
MONITORING_ENABLED=true
PROMETHEUS_ENABLED=true
ANOMALY_DETECTION_ENABLED=true

# Escalation
ESCALATION_ENABLED=true
ESCALATION_WORKER_ENABLED=false
ESCALATION_EMAIL_NOTIFICATIONS=false

# Performance
MAX_CONCURRENT_REQUESTS=1000
REQUEST_TIMEOUT=30
DATABASE_POOL_SIZE=10
DATABASE_MAX_OVERFLOW=20

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
LOG_FILE=logs/proofpals.log
"""