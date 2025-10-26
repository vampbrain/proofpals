"""
Configuration settings for ProofPals Backend
"""

from pydantic import BaseSettings
from typing import List, Optional
import os

class Settings(BaseSettings):
    # Application settings
    APP_NAME: str = "ProofPals Backend"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Database settings
    DATABASE_URL: str = "sqlite:///./proofpals.db"
    
    # Redis settings
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: Optional[str] = None
    
    # Security settings
    SECRET_KEY: str = "your-secret-key-change-in-production"
    API_KEY_HEADER: str = "X-API-Key"
    
    # CORS settings
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8080"]
    ALLOWED_HOSTS: List[str] = ["localhost", "127.0.0.1"]
    
    # Rate limiting settings
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60  # seconds
    
    # Token settings
    TOKEN_EXPIRY_HOURS: int = 24
    MAX_TOKENS_PER_CREDENTIAL: int = 10
    
    # Voting settings
    VOTE_THRESHOLD: int = 3
    URGENT_FLAG_LIMIT: int = 5
    FLAG_FRACTION: float = 0.3
    
    # Crypto settings
    RSA_KEY_SIZE: int = 2048
    MAX_RING_SIZE: int = 1000
    
    # Monitoring settings
    LOG_LEVEL: str = "INFO"
    METRICS_RETENTION_DAYS: int = 30
    
    # Escalation settings
    ESCALATION_TIMEOUT_HOURS: int = 24
    TRUSTEE_THRESHOLD: int = 3
    
    class Config:
        env_file = ".env"
        case_sensitive = True

# Create settings instance
settings = Settings()
