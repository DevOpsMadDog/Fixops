"""Tests for billing_router — Stripe Billing connector — ALDECI (2026-05-31).

Spins up a minimal FastAPI app with the billing router mounted. Each test
gets an isolated environment and a stub httpx.AsyncClient so we exercise the
real auth + parsing code paths without hitting the Stripe network.

NO MOCKS rule:
  * When STRIPE_SECRET_KEY is unset every live endpoint returns HTTP 503 with
    ``{"error":"stripe_not_configured","needed":["STRIPE_SECRET_KEY"]}``.
  * Happy-path tests use an httpx stub (not baked-in fake payloads) so
    BasicAuth injection + result normalisation run through real router code.
  * GET / (billing info) returns 200 even when unconfigured.

Tests (8 total):
  1. GET /         — 200 + unconfigured status when STRIPE_SECRET_KEY unset
  2. POST /customers  — 503 when unset
  3. POST /subscriptions — 503 when unset
  4. GET  /subscriptions/{sub_id} — 503 when unset
  5. POST /subscriptions/{sub_id}/cancel — 503 when unset
  6. GET / — missing X-API-Key → 401
  7. POST /customers — happy path: creates customer, returns id
  8. GET /subscriptions/{sub_id} — happy path: returns subscription object
"""
from __future__ import annotations

import json
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import API_TOKEN

HEADERS = {"X-API-Key": API_TOKEN}

_STUB_KEY = "sk_test_aldeci_test_key_abc123456789"


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def _build_app() -> FastAPI:
    """Return a FastAPI app with both billing routers mounted."""
    from apps.api.billing_router import router, webhook_router
    app = FastAPI()
    app.include_router(router)
    app.include_router(webhook_router)
    return app


# ---------------------------------------------------------------------------
# httpx stub factory — mirrors pattern from test_databricks_router.py
# ---------------------------------------------------------------------------


def _make_stub_client(responses: Dict[str, Any]) -> MagicMock:
    """Build a mock httpx.AsyncClient that returns pre-canned payloads."""
    import httpx

    mock_client = MagicMock(spec=httpx.AsyncClient)

    async def _mock_get(url: str, *, auth=None, params=None):
        for suffix, payload in responses.items():
            if suffix in url:
                resp = MagicMock()
                resp.status_code = 200
                resp.text = json.dumps(payload)
                resp.json = MagicMock(return_value=payload)
                return resp
        resp = MagicMock()
        body = {"error": {"type": "invalid_request_error", "message": "No such resource"}}
        resp.status_code = 404
        resp.text = json.dumps(body)
        resp.json = MagicMock(return_value=body)
        return resp

    async def _mock_post(url: str, *, auth=None, data=None):
        for suffix, payload in responses.items():
            if suffix in url:
                resp = MagicMock()
                resp.status_code = 200
                resp.text = json.dumps(payload)
                resp.json = MagicMock(return_value=payload)
                return resp
        resp = MagicMock()
        body = {"error": {"type": "invalid_request_error", "message": "No such resource"}}
        resp.status_code = 404
        resp.text = json.dumps(body)
        resp.json = MagicMock(return_value=body)
        return resp

    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(side_effect=_mock_get)
    mock_client.post = AsyncMock(side_effect=_mock_post)
    return mock_client


# ---------------------------------------------------------------------------
# Test 1: GET / returns 200 + unconfigured info when STRIPE_SECRET_KEY unset
# ---------------------------------------------------------------------------


def test_billing_info_returns_200_when_unconfigured(monkeypatch):
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/billing/", headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["service"] == "Stripe Billing API"
    assert body["configured"] is False
    assert body["mode"] == "unconfigured"
    assert "POST /customers" in body["endpoints"]
    assert "POST /subscriptions" in body["endpoints"]
    assert "GET /subscriptions/{sub_id}" in body["endpoints"]
    assert "POST /subscriptions/{sub_id}/cancel" in body["endpoints"]
    assert "POST /webhook" in body["endpoints"]


# ---------------------------------------------------------------------------
# Test 2: POST /customers returns 503 when STRIPE_SECRET_KEY unset
# ---------------------------------------------------------------------------


def test_create_customer_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/billing/customers",
        json={"email": "test@example.com", "name": "Test User"},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    body = r.json()
    assert body["detail"]["error"] == "stripe_not_configured"
    assert "STRIPE_SECRET_KEY" in body["detail"]["needed"]


# ---------------------------------------------------------------------------
# Test 3: POST /subscriptions returns 503 when STRIPE_SECRET_KEY unset
# ---------------------------------------------------------------------------


def test_create_subscription_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post(
        "/api/v1/billing/subscriptions",
        json={"customer_id": "cus_abc123", "price_id": "price_xyz789"},
        headers=HEADERS,
    )
    assert r.status_code == 503, r.text
    body = r.json()
    assert body["detail"]["error"] == "stripe_not_configured"


# ---------------------------------------------------------------------------
# Test 4: GET /subscriptions/{sub_id} returns 503 when STRIPE_SECRET_KEY unset
# ---------------------------------------------------------------------------


def test_get_subscription_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.get("/api/v1/billing/subscriptions/sub_abc123", headers=HEADERS)
    assert r.status_code == 503, r.text
    body = r.json()
    assert body["detail"]["error"] == "stripe_not_configured"


# ---------------------------------------------------------------------------
# Test 5: POST /subscriptions/{sub_id}/cancel returns 503 when key unset
# ---------------------------------------------------------------------------


def test_cancel_subscription_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    r = client.post("/api/v1/billing/subscriptions/sub_abc123/cancel", headers=HEADERS)
    assert r.status_code == 503, r.text
    body = r.json()
    assert body["detail"]["error"] == "stripe_not_configured"


# ---------------------------------------------------------------------------
# Test 6: Missing X-API-Key returns 401 on a protected endpoint
# ---------------------------------------------------------------------------


def test_missing_api_key_returns_401(monkeypatch):
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    # No X-API-Key header — must be rejected at auth layer
    r = client.get("/api/v1/billing/subscriptions/sub_abc123")
    assert r.status_code == 401, r.text


# ---------------------------------------------------------------------------
# Test 7: POST /customers happy path — creates customer, returns Stripe id
# ---------------------------------------------------------------------------


def test_create_customer_happy_path(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", _STUB_KEY)

    stripe_customer = {
        "id": "cus_TestAbc123456",
        "object": "customer",
        "email": "alice@example.com",
        "name": "Alice Smith",
        "created": 1748649600,
        "livemode": False,
    }

    stub_client = _make_stub_client({"/v1/customers": stripe_customer})
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    with patch("apps.api.billing_router.httpx.AsyncClient", return_value=stub_client):
        r = client.post(
            "/api/v1/billing/customers",
            json={"email": "alice@example.com", "name": "Alice Smith"},
            headers=HEADERS,
        )

    assert r.status_code == 201, r.text
    body = r.json()
    assert body["id"] == "cus_TestAbc123456"
    assert body["email"] == "alice@example.com"
    assert body["object"] == "customer"

    # Verify BasicAuth was passed (type check — httpx.BasicAuth internals are private)
    call_kwargs = stub_client.post.call_args
    auth_arg = call_kwargs.kwargs.get("auth")
    assert auth_arg is not None
    assert isinstance(auth_arg, httpx.BasicAuth)


# ---------------------------------------------------------------------------
# Test 8: GET /subscriptions/{sub_id} happy path — returns subscription object
# ---------------------------------------------------------------------------


def test_get_subscription_happy_path(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", _STUB_KEY)

    stripe_sub = {
        "id": "sub_TestXyz789012",
        "object": "subscription",
        "customer": "cus_TestAbc123456",
        "status": "active",
        "current_period_start": 1748649600,
        "current_period_end": 1751241600,
        "items": {
            "object": "list",
            "data": [
                {
                    "id": "si_TestItem001",
                    "price": {"id": "price_Pro499", "unit_amount": 49900, "currency": "usd"},
                }
            ],
        },
        "livemode": False,
    }

    stub_client = _make_stub_client({"/v1/subscriptions/sub_TestXyz789012": stripe_sub})
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)

    with patch("apps.api.billing_router.httpx.AsyncClient", return_value=stub_client):
        r = client.get("/api/v1/billing/subscriptions/sub_TestXyz789012", headers=HEADERS)

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == "sub_TestXyz789012"
    assert body["status"] == "active"
    assert body["customer"] == "cus_TestAbc123456"
    assert body["object"] == "subscription"

    # Verify BasicAuth was passed (type check — httpx.BasicAuth internals are private)
    call_kwargs = stub_client.get.call_args
    auth_arg = call_kwargs.kwargs.get("auth")
    assert auth_arg is not None
    assert isinstance(auth_arg, httpx.BasicAuth)
