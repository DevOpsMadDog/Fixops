"""
Enterprise configuration management with environment-based settings
"""

import os
from functools import lru_cache
from typing import List, Optional, Union

from pydantic import Field, field_validator
from pydantic.fields import FieldInfo
from pydantic_settings import BaseSettings


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

    # FixOps Operation Mode
    DEMO_MODE: bool = Field(
        default=True, description="Enable demo mode with simulated data"
    )

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
    PGVECTOR_DSN: Optional[str] = Field(
        default=None, description="postgresql+psycopg://user:pass@host:5432/db"
    )

    # Real Vector DB Settings (legacy)
    VECTOR_DB_URL: Optional[str] = Field(default=None)
    SECURITY_PATTERNS_DB_URL: Optional[str] = Field(default=None)
    THREAT_INTEL_API_KEY: Optional[str] = Field(default=None)

    # External Feeds / Feature Flags (SSVC deck alignment)
    ENABLED_EPSS: bool = Field(default=True)
    ENABLED_KEV: bool = Field(default=True)
    ENABLED_VEX: bool = Field(default=False)
    ENABLED_RSS_SIDECAR: bool = Field(default=False)

    # Security Configuration
    SECRET_KEY: str = Field(default=os.getenv("SECRET_KEY"))
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ALLOWED_HOSTS: List[str] = Field(default=["localhost", "127.0.0.1"])
    SIGNING_PROVIDER: str = Field(
        default=os.getenv("SIGNING_PROVIDER", "env"),
        description="Signing backend provider (env, aws_kms, azure_key_vault)",
    )
    KEY_ID: Optional[str] = Field(
        default=os.getenv("KEY_ID"), description="Remote key identifier"
    )
    SIGNING_ROTATION_SLA_DAYS: int = Field(
        default=int(os.getenv("SIGNING_ROTATION_SLA_DAYS", "30")),
        description="Maximum age in days before signing material must rotate",
    )
    AWS_REGION: Optional[str] = Field(
        default=os.getenv("AWS_REGION"), description="AWS region for KMS operations"
    )
    AZURE_VAULT_URL: Optional[str] = Field(
        default=os.getenv("AZURE_VAULT_URL"), description="Azure Key Vault base URL"
    )
    OPA_SERVER_URL: Optional[str] = Field(
        default=os.getenv("OPA_SERVER_URL"),
        description="Base URL for the external OPA server",
    )
    OPA_POLICY_PACKAGE: str = Field(
        default=os.getenv("OPA_POLICY_PACKAGE", "fixops"),
        description="OPA policy package used for bundle queries",
    )
    OPA_HEALTH_PATH: str = Field(
        default=os.getenv("OPA_HEALTH_PATH", "/health"),
        description="OPA health endpoint path",
    )
    OPA_BUNDLE_STATUS_PATH: Optional[str] = Field(
        default=os.getenv("OPA_BUNDLE_STATUS_PATH"),
        description="Optional OPA bundle status endpoint for readiness checks",
    )
    OPA_AUTH_TOKEN: Optional[str] = Field(
        default=os.getenv("OPA_AUTH_TOKEN"),
        description="Bearer token for authenticating with the OPA server",
    )
    OPA_REQUEST_TIMEOUT: int = Field(
        default=int(os.getenv("OPA_REQUEST_TIMEOUT", "5")),
        description="Timeout in seconds for OPA HTTP requests",
    )

    # Database Configuration
    DATABASE_URL: str = Field(
        default=os.getenv("MONGO_URL", "mongodb://mongodb:27017/fixops_production")
    )
    DATABASE_POOL_SIZE: int = Field(default=10)
    DATABASE_MAX_OVERFLOW: int = Field(default=20)
    DATABASE_POOL_TIMEOUT: int = Field(default=30)

    # Cache Configuration (MongoDB-based for Emergent compatibility)
    REDIS_URL: str = Field(default=os.getenv("REDIS_URL", "memory://"))
    REDIS_MAX_CONNECTIONS: int = Field(default=50)

    # Message Queue Configuration (disabled for stateless operation)
    RABBITMQ_URL: str = Field(default="memory://")
    CELERY_BROKER_URL: str = Field(default=os.getenv("CELERY_BROKER_URL", "memory://"))
    CELERY_RESULT_BACKEND: str = Field(
        default=os.getenv("CELERY_RESULT_BACKEND", "memory://")
    )

    # CORS Configuration
    CORS_ORIGINS: List[str] = Field(
        default=[
            "http://localhost:3000",
            "https://vulnops-intelligence.preview.emergentagent.com",
            "https://*.emergent.host",
        ]
    )

    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = Field(default=1000)
    RATE_LIMIT_WINDOW: int = Field(default=60)
    FIXOPS_RL_ENABLED: bool = Field(default=True)
    FIXOPS_RL_REQ_PER_MIN: int = Field(default=120)

    # Scheduler Controls
    FIXOPS_SCHED_ENABLED: bool = Field(default=True)
    FIXOPS_SCHED_INTERVAL_HOURS: int = Field(default=24)

    # Security Defaults
    FIXOPS_ALLOWED_ORIGINS: List[str] = Field(default_factory=list)

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
    ML_MODEL_PATH: str = Field(default="models")
    ENABLE_ML_INFERENCE: bool = Field(default=True)
    ML_BATCH_SIZE: int = Field(default=32)
    ENABLE_RL_EXPERIMENTS: bool = Field(
        default=False, description="Enable reinforcement learning experiment toggles"
    )
    ENABLE_SHAP_EXPERIMENTS: bool = Field(
        default=False, description="Enable SHAP explainability experiment toggles"
    )

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

    @property
    def primary_llm_api_key(self) -> Optional[str]:
        """Return the preferred API key for ChatGPT-backed features."""

        return self.OPENAI_API_KEY or self.EMERGENT_LLM_KEY

    @field_validator(
        "CORS_ORIGINS", "ALLOWED_HOSTS", "FIXOPS_ALLOWED_ORIGINS", mode="before"
    )
    @classmethod
    def parse_list_fields(cls, v):
        if isinstance(v, str):
            return [item.strip() for item in v.split(",")]
        return v

    class Config:
        env_file = ".env"
        case_sensitive = True


def _ensure_list(value: Union[List[str], FieldInfo, None]) -> List[str]:
    if isinstance(value, FieldInfo):
        raw = value.default
    else:
        raw = value
    if not raw:
        return []
    if isinstance(raw, str):
        return [item.strip() for item in raw.split(",") if item.strip()]
    return list(raw)


def resolve_allowed_origins(config: Settings) -> list[str]:
    """Compute the allowed origins list with production safeguards."""

    explicit_values = _ensure_list(getattr(config, "FIXOPS_ALLOWED_ORIGINS", []))
    env_override = os.getenv("FIXOPS_ALLOWED_ORIGINS")
    if env_override is not None:
        explicit_values = _ensure_list(env_override)

    explicit = [origin for origin in explicit_values if origin]
    environment = os.getenv(
        "ENVIRONMENT",
        _unwrap_scalar(getattr(config, "ENVIRONMENT", "development"), "development"),
    )
    if environment.lower() == "production" and not explicit:
        raise RuntimeError(
            "FIXOPS_ALLOWED_ORIGINS must be configured for production deployments"
        )
    cors_origins = _ensure_list(getattr(config, "CORS_ORIGINS", []))
    return explicit or cors_origins


def _unwrap_scalar(value: Union[str, FieldInfo, None], default: str) -> str:
    if isinstance(value, FieldInfo):
        candidate = value.default
    else:
        candidate = value
    if candidate is None:
        return default
    return str(candidate)


@lru_cache()
def get_settings() -> Settings:
    """Get cached application settings"""
    return Settings()
