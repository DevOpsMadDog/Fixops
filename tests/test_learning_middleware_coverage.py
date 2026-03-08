"""Tests for core.learning_middleware — API traffic learning middleware."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.learning_middleware import LearningMiddleware, _SKIP_PREFIXES


# ── Constants ────────────────────────────────────────────────────────

class TestSkipPrefixes:
    def test_health_skipped(self):
        assert any(p.startswith("/health") for p in _SKIP_PREFIXES)

    def test_docs_skipped(self):
        assert any(p.startswith("/docs") for p in _SKIP_PREFIXES)

    def test_openapi_skipped(self):
        assert any(p.startswith("/openapi") for p in _SKIP_PREFIXES)

    def test_redoc_skipped(self):
        assert any(p.startswith("/redoc") for p in _SKIP_PREFIXES)

    def test_static_skipped(self):
        assert any(p.startswith("/static") for p in _SKIP_PREFIXES)

    def test_favicon_skipped(self):
        assert any(p.startswith("/favicon") for p in _SKIP_PREFIXES)


# ── LearningMiddleware Init ─────────────────────────────────────────

class TestLearningMiddlewareInit:
    def test_enabled_by_default(self):
        # We need a minimal ASGI app to init the middleware
        async def dummy_app(scope, receive, send):
            pass

        middleware = LearningMiddleware(dummy_app)
        assert middleware._enabled is True
        assert middleware._store is None  # Lazy init

    def test_disabled(self):
        async def dummy_app(scope, receive, send):
            pass

        middleware = LearningMiddleware(dummy_app, enabled=False)
        assert middleware._enabled is False
