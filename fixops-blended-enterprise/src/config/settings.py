"""
Enterprise configuration management with environment-based settings
"""

import os
from functools import lru_cache
from typing import List, Optional

from pydantic_settings import BaseSettings
from pydantic import Field, validator


class Settings(BaseSettings):
    """Application settings with enterprise security and performance configuration"""
    
    # Application Configuration
    APP_NAME: str = "FixOps Blended Enterprise"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = Field(default="development", env="ENVIRONMENT")
    DEBUG: bool = Field(default=False, env="DEBUG")
    
    # Performance Configuration
    HOT_PATH_TARGET_LATENCY_US: int = 299
    MAX_CONNECTIONS_PER_POOL: int = 20
    CONNECTION_POOL_OVERFLOW: int = 30
    CACHE_TTL_SECONDS: int = 300
    
    # Security Configuration
    SECRET_KEY: str = Field(..., env="SECRET_KEY")
    JWT_ALGORITHM: str = "RS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ALLOWED_HOSTS: List[str] = Field(default=["*"], env="ALLOWED_HOSTS")
    
    # Database Configuration (PostgreSQL)
    DATABASE_URL: str = Field(..., env="DATABASE_URL")
    DATABASE_POOL_SIZE: int = Field(default=10, env="DATABASE_POOL_SIZE")
    DATABASE_MAX_OVERFLOW: int = Field(default=20, env="DATABASE_MAX_OVERFLOW")
    DATABASE_POOL_TIMEOUT: int = Field(default=30, env="DATABASE_POOL_TIMEOUT")
    
    # Redis Configuration
    REDIS_URL: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    REDIS_MAX_CONNECTIONS: int = Field(default=50, env="REDIS_MAX_CONNECTIONS")
    
    # Message Queue Configuration (RabbitMQ)
    RABBITMQ_URL: str = Field(default="amqp://localhost:5672", env="RABBITMQ_URL")
    CELERY_BROKER_URL: str = Field(default="redis://localhost:6379/1", env="CELERY_BROKER_URL")
    CELERY_RESULT_BACKEND: str = Field(default="redis://localhost:6379/2", env="CELERY_RESULT_BACKEND")
    
    # CORS Configuration
    CORS_ORIGINS: List[str] = Field(
        default=["http://localhost:3000", "https://localhost:3000"],
        env="CORS_ORIGINS"
    )
    
    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = Field(default=1000, env="RATE_LIMIT_REQUESTS")
    RATE_LIMIT_WINDOW: int = Field(default=60, env="RATE_LIMIT_WINDOW")
    
    # Monitoring & Observability
    ENABLE_METRICS: bool = Field(default=True, env="ENABLE_METRICS")
    ENABLE_TRACING: bool = Field(default=True, env="ENABLE_TRACING")
    JAEGER_ENDPOINT: Optional[str] = Field(default=None, env="JAEGER_ENDPOINT")
    
    # External Integrations
    SLACK_BOT_TOKEN: Optional[str] = Field(default=None, env="SLACK_BOT_TOKEN")
    JIRA_URL: Optional[str] = Field(default=None, env="JIRA_URL")
    JIRA_USERNAME: Optional[str] = Field(default=None, env="JIRA_USERNAME")
    JIRA_API_TOKEN: Optional[str] = Field(default=None, env="JIRA_API_TOKEN")
    
    # ML & Analytics Configuration
    ML_MODEL_PATH: str = Field(default="/app/models", env="ML_MODEL_PATH")
    ENABLE_ML_INFERENCE: bool = Field(default=True, env="ENABLE_ML_INFERENCE")
    ML_BATCH_SIZE: int = Field(default=32, env="ML_BATCH_SIZE")
    
    # Compliance & Security
    AUDIT_LOG_RETENTION_DAYS: int = Field(default=2555, env="AUDIT_LOG_RETENTION_DAYS")  # 7 years
    ENCRYPT_SENSITIVE_DATA: bool = Field(default=True, env="ENCRYPT_SENSITIVE_DATA")
    REQUIRE_MFA: bool = Field(default=True, env="REQUIRE_MFA")
    
    @validator("CORS_ORIGINS", pre=True)
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v
    
    @validator("ALLOWED_HOSTS", pre=True)
    def parse_allowed_hosts(cls, v):
        if isinstance(v, str):
            return [host.strip() for host in v.split(",")]
        return v
    
    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """Get cached application settings"""
    return Settings()