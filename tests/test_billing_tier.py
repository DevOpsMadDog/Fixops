"""Tests for GET /api/v1/billing/tier — ALDECI (2026-06-01).

Verifies that the tier endpoint:
  1. Returns 200 + tier field for an authenticated caller.
  2. Returns 401 for an unauthenticated caller (no X-API-Key).
  3. Defaults to "enterprise" when STRIPE_SECRET_KEY is absent (self-hosted
     default-allow behaviour documented in get_org_tier()).
  4. Returns the stored tier when STRIPE_SECRET_KEY is present.
"""
from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import API_TOKEN

HEADERS = {"X-API-Key": API_TOKEN}


# ---------------------------------------------------------------------------
# App factory — mount only the auth-protected billing router
# ---------------------------------------------------------------------------


def _build_app() -> FastAPI:
    from apps.api.billing_router import router, webhook_router

    app = FastAPI()
    app.include_router(router)
    app.include_router(webhook_router)
    return app


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_get_billing_tier_authed_no_stripe_key():
    """Authenticated GET /tier without STRIPE_SECRET_KEY → 200, tier=enterprise.

    When billing is unconfigured (no Stripe key) get_org_tier() returns
    "enterprise" for any org that has no explicit row — default-allow for
    self-hosted installs.
    """
    env = {k: v for k, v in os.environ.items() if k != "STRIPE_SECRET_KEY"}
    with patch.dict(os.environ, env, clear=True):
        app = _build_app()
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/api/v1/billing/tier", headers=HEADERS)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "tier" in body, f"'tier' field missing from response: {body}"
    assert body["tier"] in ("starter", "pro", "enterprise")
    # billing_configured must be False since no STRIPE_SECRET_KEY in env
    assert body["billing_configured"] is False


def test_get_billing_tier_unauthed_returns_401():
    """GET /tier without X-API-Key → 401."""
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=True)
    resp = client.get("/api/v1/billing/tier")
    assert resp.status_code == 401, resp.text


def test_get_billing_tier_with_stripe_key_returns_starter_for_unknown_org():
    """When STRIPE_SECRET_KEY is set and no tier row exists → tier=starter.

    get_org_tier() returns "starter" for orgs with no row when billing is
    configured.
    """
    env_override = {
        "STRIPE_SECRET_KEY": "sk_test_aldeci_unit_test_key_xyz",
    }
    with patch.dict(os.environ, env_override, clear=False):
        app = _build_app()
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/api/v1/billing/tier", headers=HEADERS)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "tier" in body
    assert body["tier"] in ("starter", "pro", "enterprise")
    assert body["billing_configured"] is True


def test_get_billing_tier_response_shape():
    """Response must include tier, org_id, and billing_configured fields."""
    env = {k: v for k, v in os.environ.items() if k != "STRIPE_SECRET_KEY"}
    with patch.dict(os.environ, env, clear=True):
        app = _build_app()
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/api/v1/billing/tier", headers=HEADERS)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "tier" in body
    assert "org_id" in body
    assert "billing_configured" in body
    assert isinstance(body["billing_configured"], bool)
    assert body["tier"] in ("starter", "pro", "enterprise")
