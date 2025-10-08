from __future__ import annotations

import asyncio
import importlib

import pytest


@pytest.fixture(name="rate_limiter")
def fixture_rate_limiter(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FIXOPS_RL_ENABLED", "1")
    monkeypatch.setenv("FIXOPS_RL_REQ_PER_MIN", "3")

    from src.config.settings import get_settings

    get_settings.cache_clear()
    middleware = importlib.import_module("src.core.middleware")
    importlib.reload(middleware)

    limiter = middleware.RateLimitMiddleware(lambda scope, receive, send: None)
    return limiter


def test_rate_limit_blocks_after_threshold(rate_limiter) -> None:
    async def run() -> None:
        results = []
        for _ in range(3):
            allowed, retry = await rate_limiter._consume_token("203.0.113.10")  # type: ignore[attr-defined]
            results.append(allowed)
        assert all(results)

        allowed, retry = await rate_limiter._consume_token("203.0.113.10")  # type: ignore[attr-defined]
        assert not allowed
        assert retry >= 1

    asyncio.run(run())
