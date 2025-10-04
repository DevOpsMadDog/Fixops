"""Runtime configuration backed by :mod:`pydantic` settings models."""

from __future__ import annotations

import os
from enum import Enum
from functools import lru_cache
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class RuntimeMode(str, Enum):
    """Supported execution modes for the platform."""

    DEMO = "demo"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Application settings with enterprise security and performance configuration."""

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

    # FixOps Operation Mode
    DEMO_MODE: bool = Field(default=True, description="Enable demo mode with simulated data")

    # Demo Mode Configuration
    DEMO_VECTOR_DB_PATTERNS: int = Field(default=2847)
    DEMO_GOLDEN_REGRESSION_CASES: int = Field(default=1247)
    DEMO_BUSINESS_CONTEXTS: int = Field(default=342)

    # Real Integration Settings (used when DEMO_MODE=False)
    JIRA_URL: Optional[str] = Field(default=None)
    JIRA_USERNAME: Optional[str] = Field(default=None)
    JIRA_API_TOKEN: Optional[str] = Field(default=None)
    CONFLUENCE_URL: Optional[str] = Field(default=None)
    CONFLUENCE_USERNAME: Optional[str] = Field(default=None)
    CONFLUENCE_API_TOKEN: Optional[str] = Field(default=None)

    # Vector Store
    PGVECTOR_ENABLED: bool = Field(default=False)
    PGVECTOR_DSN: Optional[str] = Field(default=None, description="postgresql+psycopg://user:pass@host:5432/db")
    VECTOR_DB_URL: Optional[str] = Field(default=None)
    SECURITY_PATTERNS_DB_URL: Optional[str] = Field(default=None)
    THREAT_INTEL_API_KEY: Optional[str] = Field(default=None)

    # External Feeds / Feature Flags (SSVC deck alignment)
    ENABLED_EPSS: bool = Field(default=True)
    ENABLED_KEV: bool = Field(default=True)
    ENABLED_VEX: bool = Field(default=False)
    ENABLED_RSS_SIDECAR: bool = Field(default=False)

    # Security Configuration
    SECRET_KEY: str = Field(default=os.getenv("SECRET_KEY", "change-me"))
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ALLOWED_HOSTS: List[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1"])

    # Database Configuration
    DATABASE_URL: str = Field(default=os.getenv("MONGO_URL", "mongodb://mongodb:27017/fixops_production"))
    DATABASE_POOL_SIZE: int = Field(default=10)
    DATABASE_MAX_OVERFLOW: int = Field(default=20)
    DATABASE_POOL_TIMEOUT: int = Field(default=30)

    # Cache Configuration (MongoDB-based for Emergent compatibility)
    REDIS_URL: str = Field(default=os.getenv("REDIS_URL", "memory://"))
    REDIS_MAX_CONNECTIONS: int = Field(default=50)

    # Message Queue Configuration (disabled for stateless operation)
    RABBITMQ_URL: str = Field(default="memory://")
    CELERY_BROKER_URL: str = Field(default=os.getenv("CELERY_BROKER_URL", "memory://"))
    CELERY_RESULT_BACKEND: str = Field(default=os.getenv("CELERY_RESULT_BACKEND", "memory://"))

    # CORS Configuration
    CORS_ORIGINS: List[str] = Field(
        default_factory=lambda: [
            "http://localhost:3000",
            "https://vulnops-intelligence.preview.emergentagent.com",
            "https://*.emergent.host",
        ]
    )

    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = Field(default=1000)
    RATE_LIMIT_WINDOW: int = Field(default=60)

    # Monitoring & Observability
    ENABLE_METRICS: bool = Field(default=True)
    ENABLE_TRACING: bool = Field(default=True)
    JAEGER_ENDPOINT: Optional[str] = Field(default=None)

    # External Integrations
    SLACK_BOT_TOKEN: Optional[str] = Field(default=None)

    # ML & Analytics Configuration
    ML_MODEL_PATH: str = Field(default="/app/models")
    ENABLE_ML_INFERENCE: bool = Field(default=True)
    ML_BATCH_SIZE: int = Field(default=32)

    # Compliance & Security
    AUDIT_LOG_RETENTION_DAYS: int = Field(default=2555)
    ENCRYPT_SENSITIVE_DATA: bool = Field(default=True)
    REQUIRE_MFA: bool = Field(default=False)

    # LLM Integration - Multiple Providers
    EMERGENT_LLM_KEY: Optional[str] = Field(default=None)
    OPENAI_API_KEY: Optional[str] = Field(default=None)
    ANTHROPIC_API_KEY: Optional[str] = Field(default=None)
    GOOGLE_API_KEY: Optional[str] = Field(default=None)
    CYBER_LLM_API_KEY: Optional[str] = Field(default=None)

    # LLM Configuration
    LLM_TIMEOUT_SECONDS: int = Field(default=30)
    LLM_MAX_RETRIES: int = Field(default=3)
    LLM_CONSENSUS_THRESHOLD: float = Field(default=0.75)
    ENABLE_MULTI_LLM: bool = Field(default=True)

    @field_validator("CORS_ORIGINS", "ALLOWED_HOSTS", mode="before")
    @classmethod
    def parse_list_fields(cls, value: object):  # pragma: no cover - exercised indirectly
        if isinstance(value, str):
            return [item.strip() for item in value.split(",")]
        return value

    @property
    def runtime_mode(self) -> RuntimeMode:
        """Return the active runtime mode as an enum."""

        return RuntimeMode.DEMO if self.DEMO_MODE else RuntimeMode.PRODUCTION

    def missing_production_requirements(self) -> List[str]:
        """Enumerate configuration prerequisites that block production mode."""

        missing: List[str] = []

        def _require(condition: bool, identifier: str) -> None:
            if not condition:
                missing.append(identifier)

        _require(bool(self.EMERGENT_LLM_KEY), "EMERGENT_LLM_KEY")
        _require(
            bool(self.JIRA_URL and self.JIRA_USERNAME and self.JIRA_API_TOKEN),
            "JIRA_CREDENTIALS",
        )
        _require(
            bool(self.CONFLUENCE_URL and self.CONFLUENCE_USERNAME and self.CONFLUENCE_API_TOKEN),
            "CONFLUENCE_CREDENTIALS",
        )
        _require(bool(self.PGVECTOR_ENABLED and self.PGVECTOR_DSN), "PGVECTOR_DSN")
        _require(bool(self.THREAT_INTEL_API_KEY), "THREAT_INTEL_API_KEY")
        _require(bool(os.getenv("OPA_SERVER_URL")), "OPA_SERVER")

        return missing

    def production_requirements_met(self) -> bool:
        """Convenience helper that reports production readiness."""

        return not self.missing_production_requirements()

    def summary(self) -> dict[str, object]:
        """Return a concise description of the current runtime posture."""

        return {
            "mode": self.runtime_mode.value,
            "demo": self.runtime_mode is RuntimeMode.DEMO,
            "production_ready": self.production_requirements_met(),
            "missing": self.missing_production_requirements(),
        }

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """Return cached application settings."""

    return Settings()


def reload_settings() -> Settings:
    """Clear the cached settings instance and return a fresh copy."""

    get_settings.cache_clear()
    return get_settings()
