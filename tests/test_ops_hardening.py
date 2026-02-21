from __future__ import annotations

import asyncio

import pytest
from apps.api.app import create_app
from config.enterprise.settings import get_settings
from core.enterprise.middleware import RateLimitMiddleware


def test_rate_limit_enforced(
    monkeypatch: pytest.MonkeyPatch, signing_env: None
) -> None:
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
