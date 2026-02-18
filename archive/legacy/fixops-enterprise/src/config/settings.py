"""Minimal settings loader without external dependencies."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import List, Sequence


def _coerce_origins(value: Sequence[str] | str | None) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return [str(item).strip() for item in value]


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass
class Settings:
    """Application configuration with environment overrides."""

    ENVIRONMENT: str = "development"
    FIXOPS_API_KEY: str = ""
    FIXOPS_ALLOWED_ORIGINS: List[str] = field(
        default_factory=lambda: ["http://localhost"]
    )
    FIXOPS_MAX_PAYLOAD_BYTES: int = 1024 * 1024

    FIXOPS_RL_ENABLED: bool = True
    FIXOPS_RL_REQ_PER_MIN: int = 120

    FIXOPS_SCHED_ENABLED: bool = False
    FIXOPS_SCHED_INTERVAL_HOURS: int = 24

    FIXOPS_SIGNING_KEY: str | None = None
    FIXOPS_SIGNING_KID: str | None = None

    def __post_init__(self) -> None:
        self.FIXOPS_ALLOWED_ORIGINS = _coerce_origins(self.FIXOPS_ALLOWED_ORIGINS)


@lru_cache()
def get_settings() -> Settings:
    defaults = Settings()
    origins_env = os.environ.get("FIXOPS_ALLOWED_ORIGINS")
    origins = (
        _coerce_origins(origins_env)
        if origins_env is not None
        else defaults.FIXOPS_ALLOWED_ORIGINS
    )
    settings = Settings(
        ENVIRONMENT=os.environ.get("ENVIRONMENT", defaults.ENVIRONMENT),
        FIXOPS_API_KEY=os.environ.get("FIXOPS_API_KEY", defaults.FIXOPS_API_KEY),
        FIXOPS_ALLOWED_ORIGINS=origins,
        FIXOPS_MAX_PAYLOAD_BYTES=_env_int(
            "FIXOPS_MAX_PAYLOAD_BYTES", defaults.FIXOPS_MAX_PAYLOAD_BYTES
        ),
        FIXOPS_RL_ENABLED=_env_bool("FIXOPS_RL_ENABLED", defaults.FIXOPS_RL_ENABLED),
        FIXOPS_RL_REQ_PER_MIN=_env_int(
            "FIXOPS_RL_REQ_PER_MIN", defaults.FIXOPS_RL_REQ_PER_MIN
        ),
        FIXOPS_SCHED_ENABLED=_env_bool(
            "FIXOPS_SCHED_ENABLED", defaults.FIXOPS_SCHED_ENABLED
        ),
        FIXOPS_SCHED_INTERVAL_HOURS=_env_int(
            "FIXOPS_SCHED_INTERVAL_HOURS", defaults.FIXOPS_SCHED_INTERVAL_HOURS
        ),
        FIXOPS_SIGNING_KEY=os.environ.get(
            "FIXOPS_SIGNING_KEY", defaults.FIXOPS_SIGNING_KEY
        ),
        FIXOPS_SIGNING_KID=os.environ.get(
            "FIXOPS_SIGNING_KID", defaults.FIXOPS_SIGNING_KID
        ),
    )
    return settings


def resolve_allowed_origins(config: Settings) -> list[str]:
    if config.ENVIRONMENT.lower() == "production" and not config.FIXOPS_ALLOWED_ORIGINS:
        raise RuntimeError(
            "FIXOPS_ALLOWED_ORIGINS must be configured in production mode"
        )
    return config.FIXOPS_ALLOWED_ORIGINS


__all__ = ["Settings", "get_settings", "resolve_allowed_origins"]
