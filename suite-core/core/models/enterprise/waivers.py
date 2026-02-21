"""Helper utilities for working with KEV waiver models."""

from __future__ import annotations

from functools import lru_cache
from typing import Type

from config.enterprise.settings import get_settings

try:  # pragma: no cover - optional imports based on runtime database
    from core.models.enterprise.security import (
        KevFindingWaiver as PostgresKevFindingWaiver,
    )
except Exception:  # pragma: no cover - fallback for limited runtimes
    PostgresKevFindingWaiver = None  # type: ignore[assignment]

try:  # pragma: no cover - optional imports based on runtime database
    from core.models.enterprise.security_sqlite import (
        KevFindingWaiver as SqliteKevFindingWaiver,
    )
except Exception:  # pragma: no cover - fallback for limited runtimes
    SqliteKevFindingWaiver = None  # type: ignore[assignment]


@lru_cache(maxsize=1)
def get_kev_waiver_model() -> Type:
    """Return the active KEV waiver ORM model for the configured database."""

    settings = get_settings()
    raw_db_url = getattr(settings, "DATABASE_URL", "")
    if not isinstance(raw_db_url, str):
        raw_db_url = str(raw_db_url or "")
    db_url = raw_db_url.lower()
    if "sqlite" in db_url:
        return SqliteKevFindingWaiver or PostgresKevFindingWaiver  # type: ignore[return-value]
    if "postgres" in db_url or "psql" in db_url:
        return PostgresKevFindingWaiver or SqliteKevFindingWaiver  # type: ignore[return-value]
    # Default to SQLite-compatible model when database is unspecified or mocked
    return SqliteKevFindingWaiver or PostgresKevFindingWaiver  # type: ignore[return-value]


__all__ = ["get_kev_waiver_model"]
