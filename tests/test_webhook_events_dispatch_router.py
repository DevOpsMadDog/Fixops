"""Tests for POST /api/v1/events/dispatch — webhook fan-out endpoint.

Coverage:
- Valid dispatch returns 202 with delivery summary
- Invalid event_type returns 422
- Unknown severity falls back to INFO without error
- No matching webhooks returns 202 with webhooks_matched=0
- Emitter failure surfaces as 500
- correlation_id is present and a valid UUID
- Partial failure (some webhooks fail) counted correctly
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

# Ensure suite paths are importable
for _p in [
    Path(__file__).parent.parent / "suite-core",
    Path(__file__).parent.parent / "suite-api",
]:
    _s = str(_p)
    if _s not in sys.path:
        sys.path.insert(0, _s)


# ---------------------------------------------------------------------------
# Client factory — clears router-level auth deps for unit tests
# ---------------------------------------------------------------------------


def _build_client() -> TestClient:
    import apps.api.webhook_events_router as wer
    from apps.api.auth_deps import api_key_auth

    # Save and clear module-level require_role guard
    saved = list(wer.router.dependencies)
    wer.router.dependencies.clear()

    app = FastAPI()
    app.include_router(wer.router)

    # Override api_key_auth so the inner _check dep sees role="admin"
    async def _fake_auth(request: Request) -> None:  # pragma: no cover
        request.state.user_role = "admin"

    app.dependency_overrides[api_key_auth] = _fake_auth

    client = TestClient(app, raise_server_exceptions=False)

    # Restore router deps (doesn't affect already-built app)
    wer.router.dependencies.extend(saved)
    return client


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_result(status: str = "success") -> dict:
    return {
        "webhook_id": str(uuid.uuid4()),
        "status": status,
        "response_code": 200 if status == "success" else 500,
        "error": None if status == "success" else "HTTP 500",
        "attempts": 1,
    }


DISPATCH_URL = "/api/v1/events/dispatch"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestDispatchEndpoint:
    def setup_method(self):
        self.c = _build_client()

    def test_valid_dispatch_returns_202(self):
        with patch("apps.api.webhook_events_router._emitter") as mock_emitter:
            mock_emitter.emit.return_value = [_mock_result("success")]
            resp = self.c.post(
                DISPATCH_URL,
                json={
                    "event_type": "finding.created",
                    "source": "test-scanner",
                    "severity": "high",
                    "payload": {"id": "F-42"},
                },
            )
        assert resp.status_code == 202
        body = resp.json()
        assert body["webhooks_matched"] == 1
        assert body["delivered"] == 1
        assert body["failed"] == 0
        assert body["event_type"] == "finding.created"

    def test_correlation_id_is_valid_uuid(self):
        with patch("apps.api.webhook_events_router._emitter") as mock_emitter:
            mock_emitter.emit.return_value = []
            resp = self.c.post(
                DISPATCH_URL,
                json={"event_type": "risk.changed", "payload": {}},
            )
        assert resp.status_code == 202
        cid = resp.json()["correlation_id"]
        parsed = uuid.UUID(cid, version=4)
        assert str(parsed) == cid

    def test_invalid_event_type_returns_422(self):
        resp = self.c.post(
            DISPATCH_URL,
            json={"event_type": "not.a.real.type", "payload": {}},
        )
        assert resp.status_code == 422
        assert "Invalid event_type" in resp.json()["detail"]

    def test_unknown_severity_falls_back_silently(self):
        with patch("apps.api.webhook_events_router._emitter") as mock_emitter:
            mock_emitter.emit.return_value = []
            resp = self.c.post(
                DISPATCH_URL,
                json={"event_type": "sla.breach", "severity": "BOGUS", "payload": {}},
            )
        # Falls back to INFO — no 422
        assert resp.status_code == 202

    def test_no_matching_webhooks_returns_zero_counts(self):
        with patch("apps.api.webhook_events_router._emitter") as mock_emitter:
            mock_emitter.emit.return_value = []
            resp = self.c.post(
                DISPATCH_URL,
                json={"event_type": "compliance.gap", "payload": {"rule": "CIS-1.1"}},
            )
        assert resp.status_code == 202
        body = resp.json()
        assert body["webhooks_matched"] == 0
        assert body["delivered"] == 0
        assert body["failed"] == 0
        assert body["results"] == []

    def test_partial_failure_counted_correctly(self):
        results = [_mock_result("success"), _mock_result("failed"), _mock_result("success")]
        with patch("apps.api.webhook_events_router._emitter") as mock_emitter:
            mock_emitter.emit.return_value = results
            resp = self.c.post(
                DISPATCH_URL,
                json={"event_type": "pipeline.completed", "payload": {}},
            )
        assert resp.status_code == 202
        body = resp.json()
        assert body["webhooks_matched"] == 3
        assert body["delivered"] == 2
        assert body["failed"] == 1

    def test_emitter_exception_returns_500(self):
        with patch("apps.api.webhook_events_router._emitter") as mock_emitter:
            mock_emitter.emit.side_effect = RuntimeError("db exploded")
            resp = self.c.post(
                DISPATCH_URL,
                json={"event_type": "policy.violation", "payload": {}},
            )
        assert resp.status_code == 500
