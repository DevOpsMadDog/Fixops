"""
Enterprise configuration management with environment-based settings
"""

import os
from functools import lru_cache
from typing import List, Optional, Union

from pydantic_settings import BaseSettings
from pydantic import Field, field_validator


class Settings(BaseSettings):
    """Application settings with enterprise security and performance configuration"""
    
    # Application Configuration
    APP_NAME: str = "FixOps Blended Enterprise"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = Field(default="development")
    DEBUG: bool = Field(default=False)
    
    # Performance Configuration
    HOT_PATH_TARGET_LATENCY_US: int = 299
    MAX_CONNECTIONS_PER_POOL: int = 20
    CONNECTION_POOL_OVERFLOW: int = 30
    CACHE_TTL_SECONDS: int = 300
    
    # Security Configuration
    SECRET_KEY: str = Field(default="fixops_enterprise_secret_key_change_in_production")
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ALLOWED_HOSTS: List[str] = Field(default=["localhost", "127.0.0.1"])
    
    # Database Configuration
    DATABASE_URL: str = Field(default="sqlite+aiosqlite:///./fixops_enterprise.db")
    DATABASE_POOL_SIZE: int = Field(default=10)
    DATABASE_MAX_OVERFLOW: int = Field(default=20)
    DATABASE_POOL_TIMEOUT: int = Field(default=30)
    
    # Redis Configuration
    REDIS_URL: str = Field(default="redis://localhost:6379/0")
    REDIS_MAX_CONNECTIONS: int = Field(default=50)
    
    # Message Queue Configuration
    RABBITMQ_URL: str = Field(default="amqp://localhost:5672")
    CELERY_BROKER_URL: str = Field(default="redis://localhost:6379/1")
    CELERY_RESULT_BACKEND: str = Field(default="redis://localhost:6379/2")
    
    # CORS Configuration
    CORS_ORIGINS: List[str] = Field(default=["http://localhost:3000"])
    
    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = Field(default=1000)
    RATE_LIMIT_WINDOW: int = Field(default=60)
    
    # Monitoring & Observability
    ENABLE_METRICS: bool = Field(default=True)
    ENABLE_TRACING: bool = Field(default=True)
    JAEGER_ENDPOINT: Optional[str] = Field(default=None)
    
    # External Integrations
    SLACK_BOT_TOKEN: Optional[str] = Field(default=None)
    JIRA_URL: Optional[str] = Field(default=None)
    JIRA_USERNAME: Optional[str] = Field(default=None)
    JIRA_API_TOKEN: Optional[str] = Field(default=None)
    
    # ML & Analytics Configuration
    ML_MODEL_PATH: str = Field(default="/app/models")
    ENABLE_ML_INFERENCE: bool = Field(default=True)
    ML_BATCH_SIZE: int = Field(default=32)
    
    # Compliance & Security
    AUDIT_LOG_RETENTION_DAYS: int = Field(default=2555)
    ENCRYPT_SENSITIVE_DATA: bool = Field(default=True)
    REQUIRE_MFA: bool = Field(default=False)
    
    @field_validator("CORS_ORIGINS", "ALLOWED_HOSTS", mode="before")
    @classmethod
    def parse_list_fields(cls, v):
        if isinstance(v, str):
            return [item.strip() for item in v.split(",")]
        return v
    
    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """Get cached application settings"""
    return Settings()