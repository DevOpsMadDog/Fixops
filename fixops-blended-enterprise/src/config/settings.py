"""Configuration models for the FixOps blended backend."""

from __future__ import annotations

from functools import lru_cache
from typing import List, Sequence

from pydantic import BaseSettings, Field, validator


class Settings(BaseSettings):
    """Application configuration with sensible defaults for tests."""

    ENVIRONMENT: str = Field("development", description="Runtime environment name")
    FIXOPS_API_KEY: str = Field("local-dev-key", description="Bearer token required for API access")
    FIXOPS_ALLOWED_ORIGINS: List[str] = Field(default_factory=lambda: ["http://localhost"], description="CORS allow-list")
    FIXOPS_MAX_PAYLOAD_BYTES: int = Field(1024 * 1024, description="Maximum accepted payload size in bytes")

    FIXOPS_RL_ENABLED: bool = Field(True, description="Enable rate limiting middleware")
    FIXOPS_RL_REQ_PER_MIN: int = Field(120, description="Requests per minute allowed per client")

    FIXOPS_SCHED_ENABLED: bool = Field(False, description="Enable background scheduler loops")
    FIXOPS_SCHED_INTERVAL_HOURS: int = Field(24, description="Scheduler sleep interval in hours")

    FIXOPS_SIGNING_KEY: str | None = Field(default=None, description="PEM-encoded RSA private key for evidence signing")
    FIXOPS_SIGNING_KID: str | None = Field(default=None, description="Key identifier embedded in signatures")

    class Config:
        env_file = ".env"
        case_sensitive = False

    @validator("FIXOPS_ALLOWED_ORIGINS", pre=True)
    def _coerce_origins(cls, value: Sequence[str] | str | None) -> List[str]:  # type: ignore[override]
        if value is None:
            return []
        if isinstance(value, str):
            items = [item.strip() for item in value.split(",") if item.strip()]
            return items
        return [str(item).strip() for item in value]


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings instance."""

    return Settings()  # type: ignore[call-arg]

