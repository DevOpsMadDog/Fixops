"""Tests for detailed_logging.py structured observability enhancements.

Covers:
- request_id and org_id captured in log records
- slow requests (>500 ms) emit structlog WARNING
- /api/v1/system/logs/recent returns last 100 entries from ring buffer

Usage:
    pytest tests/test_detailed_logging.py -v --timeout=10
"""
from __future__ import annotations

import json
import sys
import uuid
from collections import deque
from threading import Lock
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, "suite-api")
sys.path.insert(0, "suite-core")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ring(entries: list) -> tuple:
    """Return a (ring, lock) pair pre-populated with *entries*."""
    ring: deque = deque(maxlen=500)
    lock = Lock()
    for e in reversed(entries):  # appendleft reverses, so feed reversed
        ring.appendleft(e)
    return ring, lock


def _sample_record(
    *,
    request_id: str = "",
    org_id: str = "acme",
    duration_ms: float = 10.0,
    status_code: int = 200,
) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "ts": "2026-04-17T00:00:00+00:00",
        "method": "GET",
        "path": "/api/v1/findings",
        "query_params": "",
        "status_code": status_code,
        "duration_ms": duration_ms,
        "client_ip": "127.0.0.1",
        "user_agent": "pytest",
        "correlation_id": "corr-123",
        "request_id": request_id or str(uuid.uuid4()),
        "org_id": org_id,
        "req_headers": {},
        "req_body": "",
        "resp_headers": {},
        "resp_body": "",
        "req_size": 0,
        "resp_size": 42,
        "error": None,
        "error_type": None,
        "level": "info" if status_code < 400 else "warn",
    }


# ---------------------------------------------------------------------------
# 1. DetailedLogStore — new fields persisted
# ---------------------------------------------------------------------------

class TestDetailedLogStoreNewFields:
    """Verify request_id and org_id are stored and retrieved."""

    def test_insert_and_retrieve_request_id_org_id(self, tmp_path):
        """request_id and org_id round-trip through SQLite correctly."""
        from apps.api.detailed_logging import DetailedLogStore

        store = DetailedLogStore(db_path=str(tmp_path / "test.db"))
        rec = _sample_record(request_id="req-abc-123", org_id="tenant-x")
        store.insert(rec)

        rows = store.query(limit=10)
        assert len(rows) == 1
        assert rows[0]["request_id"] == "req-abc-123"
        assert rows[0]["org_id"] == "tenant-x"

    def test_missing_request_id_defaults_to_empty(self, tmp_path):
        """Records without request_id are inserted with empty string (no crash)."""
        from apps.api.detailed_logging import DetailedLogStore

        store = DetailedLogStore(db_path=str(tmp_path / "test2.db"))
        rec = _sample_record()
        rec.pop("request_id")  # simulate pre-existing record without field
        store.insert(rec)

        rows = store.query(limit=10)
        assert len(rows) == 1
        # org_id should still be present
        assert rows[0]["org_id"] == "acme"

    def test_org_id_defaults_to_default(self, tmp_path):
        """Records without org_id fall back to 'default'."""
        from apps.api.detailed_logging import DetailedLogStore

        store = DetailedLogStore(db_path=str(tmp_path / "test3.db"))
        rec = _sample_record()
        rec.pop("org_id")
        store.insert(rec)

        rows = store.query(limit=10)
        assert rows[0]["org_id"] == "default"


# ---------------------------------------------------------------------------
# 2. Middleware — request_id / org_id extraction + slow-request WARNING
# ---------------------------------------------------------------------------

class TestMiddlewareObservability:
    """Verify the middleware extracts request_id, org_id, and warns on slow requests."""

    def _build_mock_request(
        self,
        *,
        path: str = "/api/v1/findings",
        headers: dict | None = None,
        org_id_state: str | None = None,
    ) -> MagicMock:
        req = MagicMock()
        req.method = "GET"
        req.url.path = path
        req.client.host = "127.0.0.1"
        req.query_params = {}

        # FakeHeaders: dict-like but with case-insensitive .get() so it works
        # both as dict(request.headers) and request.headers.get(key, default).
        class FakeHeaders(dict):
            def get(self, key, default=""):  # type: ignore[override]
                return super().get(key.lower(), default)

        hdr = FakeHeaders({k.lower(): v for k, v in (headers or {}).items()})
        req.headers = hdr

        # Simulate request.state.org_id set by OrgIdMiddleware
        state = MagicMock()
        state.org_id = org_id_state
        req.state = state

        return req

    @pytest.mark.asyncio
    async def test_request_id_from_header(self, tmp_path):
        """X-Request-ID header is used as request_id."""
        from apps.api.detailed_logging import DetailedLoggingMiddleware, DetailedLogStore

        store = DetailedLogStore(db_path=str(tmp_path / "mw1.db"))

        app_mock = MagicMock()
        mw = DetailedLoggingMiddleware(app_mock)
        mw._enabled = True
        mw._store = store

        req = self._build_mock_request(
            headers={"x-request-id": "custom-req-id-999"},
            org_id_state="org-test",
        )

        async def fake_body():
            return b""

        req.body = fake_body

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.media_type = "application/json"

        async def body_iter():
            yield b'{"ok": true}'

        mock_response.body_iterator = body_iter()

        call_next = AsyncMock(return_value=mock_response)

        await mw.dispatch(req, call_next)

        rows = store.query(limit=5)
        assert rows, "Expected at least one log row"
        assert rows[0]["request_id"] == "custom-req-id-999"
        assert rows[0]["org_id"] == "org-test"

    @pytest.mark.asyncio
    async def test_slow_request_emits_warning(self, tmp_path):
        """Requests slower than SLOW_REQUEST_MS emit structlog at WARNING level."""
        import apps.api.detailed_logging as dl_module

        store = dl_module.DetailedLogStore(db_path=str(tmp_path / "mw2.db"))

        app_mock = MagicMock()
        mw = dl_module.DetailedLoggingMiddleware(app_mock)
        mw._enabled = True
        mw._store = store

        req = self._build_mock_request(org_id_state="slow-org")

        async def fake_body():
            return b""

        req.body = fake_body

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.media_type = "application/json"

        async def body_iter():
            yield b"{}"

        mock_response.body_iterator = body_iter()

        call_next = AsyncMock(return_value=mock_response)

        warning_calls: list[dict] = []

        original_slog = dl_module._slog

        class CapturingSlog:
            def warning(self, event, **kw):
                warning_calls.append({"event": event, **kw})

            def info(self, event, **kw):
                pass

            def error(self, event, **kw):
                pass

        dl_module._slog = CapturingSlog()

        # Simulate 600 ms elapsed by patching time.perf_counter
        import time as _time_mod
        _orig_perf = _time_mod.perf_counter
        call_count = [0]

        def fake_perf():
            call_count[0] += 1
            # First call (start): 0.0; second call (after response): 0.6
            return 0.0 if call_count[0] == 1 else 0.6

        with patch.object(_time_mod, "perf_counter", side_effect=fake_perf):
            await mw.dispatch(req, call_next)

        dl_module._slog = original_slog

        assert warning_calls, "Expected a WARNING log for slow request"
        assert warning_calls[0]["event"] == "request.completed"
        assert warning_calls[0].get("slow") is True
        assert warning_calls[0]["duration_ms"] == pytest.approx(600.0, abs=1)

    @pytest.mark.asyncio
    async def test_generated_request_id_is_uuid(self, tmp_path):
        """When no X-Request-ID header is present, a UUID is generated."""
        from apps.api.detailed_logging import DetailedLoggingMiddleware, DetailedLogStore

        store = DetailedLogStore(db_path=str(tmp_path / "mw3.db"))

        app_mock = MagicMock()
        mw = DetailedLoggingMiddleware(app_mock)
        mw._enabled = True
        mw._store = store

        req = self._build_mock_request(org_id_state=None)  # no org set

        async def fake_body():
            return b""

        req.body = fake_body

        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.headers = {}
        mock_response.media_type = "application/json"

        async def body_iter():
            yield b'{"created": true}'

        mock_response.body_iterator = body_iter()

        call_next = AsyncMock(return_value=mock_response)
        await mw.dispatch(req, call_next)

        rows = store.query(limit=5)
        assert rows
        req_id = rows[0]["request_id"]
        # Must be a valid UUID
        uuid.UUID(req_id)  # raises if not valid


# ---------------------------------------------------------------------------
# 3. GET /api/v1/system/logs/recent
# ---------------------------------------------------------------------------

class TestSystemLogsRecentEndpoint:
    """Verify system_router exposes /api/v1/system/logs/recent correctly."""

    @pytest.mark.asyncio
    async def test_returns_recent_from_ring_buffer(self):
        """Endpoint returns entries from the ring buffer, up to limit."""
        entries = [_sample_record(org_id=f"org-{i}") for i in range(10)]
        ring, lock = _make_ring(entries)

        with patch("apps.api.detailed_logging._log_ring", ring), \
             patch("apps.api.detailed_logging._ring_lock", lock):
            from apps.api.system_router import system_logs_recent

            result = await system_logs_recent(limit=5)

        assert result["count"] == 5
        assert len(result["logs"]) == 5

    @pytest.mark.asyncio
    async def test_limit_capped_at_500(self):
        """Limit > 500 is silently capped to 500."""
        entries = [_sample_record() for _ in range(10)]
        ring, lock = _make_ring(entries)

        with patch("apps.api.detailed_logging._log_ring", ring), \
             patch("apps.api.detailed_logging._ring_lock", lock):
            from apps.api.system_router import system_logs_recent

            result = await system_logs_recent(limit=9999)

        # Only 10 entries exist, so count = 10 (not 9999 or error)
        assert result["count"] == 10

    @pytest.mark.asyncio
    async def test_empty_ring_returns_empty_list(self):
        """Empty ring buffer returns count=0 and empty logs list."""
        ring: deque = deque(maxlen=500)
        lock = Lock()

        with patch("apps.api.detailed_logging._log_ring", ring), \
             patch("apps.api.detailed_logging._ring_ring_lock", lock, create=True):
            from apps.api.system_router import system_logs_recent

            # Patch at module level so the import inside the function resolves correctly
            with patch("apps.api.detailed_logging._ring_lock", lock):
                result = await system_logs_recent(limit=100)

        assert result["count"] == 0
        assert result["logs"] == []

    @pytest.mark.asyncio
    async def test_import_error_returns_graceful_empty(self):
        """If detailed_logging is not importable, endpoint returns empty list (no crash)."""
        import builtins
        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "apps.api.detailed_logging":
                raise ImportError("not available")
            return real_import(name, *args, **kwargs)

        # Remove cached module so our mock_import fires
        import sys as _sys
        cached = _sys.modules.pop("apps.api.detailed_logging", None)
        # Also remove system_router cache to force re-evaluation of the function body
        # (the function uses a local import, so we just need to intercept builtins)

        try:
            with patch.object(builtins, "__import__", side_effect=mock_import):
                from apps.api.system_router import system_logs_recent
                result = await system_logs_recent(limit=100)
            assert result["count"] == 0
            assert result["logs"] == []
        finally:
            if cached is not None:
                _sys.modules["apps.api.detailed_logging"] = cached
