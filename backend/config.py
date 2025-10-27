"""
ProofPals Backend Configuration
Handles environment variables and application settings
"""

from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import Optional
import os


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # Database Configuration
    DATABASE_URL: str = "postgresql://proofpals:proofpals123@localhost:5432/proofpals_db"
    
    # Redis Configuration
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_TOKEN_EXPIRY: int = 300  # 5 minutes
    
    # Security
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Application Settings
    APP_NAME: str = "ProofPals Backend"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    
    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60  # seconds
    
    # Vote Thresholds
    URGENT_FLAG_LIMIT: int = 3
    MIN_VOTES_FOR_TALLY: int = 3
    
    # Token Configuration
    DEFAULT_EPOCH_TOKEN_COUNT: int = 5
    
    # Crypto Library
    CRYPTO_LIBRARY_PATH: Optional[str] = None
    
    # Rate Limiting Configuration
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_PER_IP: int = 100
    RATE_LIMIT_PER_USER: int = 200
    RATE_LIMIT_PER_TOKEN: int = 50
    RATE_LIMIT_WINDOW: int = 60
    RATE_LIMIT_BURST: int = 20
    
    # JWT Configuration
    JWT_SECRET_KEY: str = "your-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    
    # Monitoring Configuration
    MONITORING_ENABLED: bool = True
    PROMETHEUS_ENABLED: bool = True
    ANOMALY_DETECTION_ENABLED: bool = True
    
    # Escalation Configuration
    ESCALATION_ENABLED: bool = True
    ESCALATION_WORKER_ENABLED: bool = False
    ESCALATION_EMAIL_NOTIFICATIONS: bool = False
    ESCALATION_WEBHOOK_URL: Optional[str] = None
    
    # Performance Configuration
    MAX_CONCURRENT_REQUESTS: int = 1000
    REQUEST_TIMEOUT: int = 30
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20
    
    # Logging Configuration
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    LOG_FILE: Optional[str] = "logs/proofpals.log"
    
    
    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()


# Global settings instance
settings = get_settings()