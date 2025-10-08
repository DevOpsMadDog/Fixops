from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import asyncio

from src.config.settings import get_settings
from src.core.middleware import RateLimitMiddleware
from src.main import create_app


def test_rate_limit_enforced(monkeypatch: pytest.MonkeyPatch, signing_env: None) -> None:
    monkeypatch.setenv("FIXOPS_RL_REQ_PER_MIN", "1")
    get_settings.cache_clear()
    middleware = RateLimitMiddleware(lambda request: None)

    async def sequence() -> tuple[bool, bool]:
        allowed_first, _ = await middleware._consume_token("127.0.0.1")
        allowed_second, _ = await middleware._consume_token("127.0.0.1")
        return allowed_first, allowed_second

    first_allowed, second_allowed = asyncio.run(sequence())
    assert first_allowed is True
    assert second_allowed is False


def test_production_requires_allowed_origins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("FIXOPS_ALLOWED_ORIGINS", "")
    get_settings.cache_clear()
    with pytest.raises(RuntimeError):
        create_app()
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    get_settings.cache_clear()

