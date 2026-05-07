"""
Smoke tests — Real Stripe SDK integration (Multica #4119).

Covers:
1. POST /api/v1/billing/upgrade calls stripe.checkout.Session.create() and returns session.url
2. POST /api/v1/billing/stripe-webhook validates signature via stripe.Webhook.construct_event()
3. Webhook with invalid signature returns 400
4. Webhook subscription.created upgrades org tier
5. Webhook subscription.deleted downgrades org to starter

All stripe SDK calls are mocked — no real Stripe network calls.
phase4 (test_phase4_integration.py) is unaffected (different module).
"""
from __future__ import annotations

import json
import os
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (
    os.path.join(_ROOT, "suite-api"),
    os.path.join(_ROOT, "suite-core"),
):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Build a minimal FastAPI app with both routers mounted
# ---------------------------------------------------------------------------

def _build_app():
    from fastapi import FastAPI
    from apps.api.billing_router import router as billing_router
    from apps.api.stripe_webhook_router import router as stripe_webhook_router

    app = FastAPI()

    # billing router gets a dummy auth header dependency removed for testing
    app.include_router(billing_router)
    # stripe webhook is intentionally unauthenticated (Stripe calls it directly)
    app.include_router(stripe_webhook_router)
    return app


@pytest.fixture(scope="module")
def app():
    return _build_app()


@pytest.fixture(scope="module")
def client(app):
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ORG_HDR = {"X-Org-ID": "stripe-smoke-org-4119"}


# ---------------------------------------------------------------------------
# 1. POST /upgrade calls stripe.checkout.Session.create() and returns session.url
# ---------------------------------------------------------------------------

def test_upgrade_calls_stripe_checkout_session_create(client, monkeypatch):
    """When FIXOPS_STRIPE_SECRET_KEY is set, upgrade must delegate to stripe SDK."""
    monkeypatch.setenv("FIXOPS_STRIPE_SECRET_KEY", "sk_test_fake")
    monkeypatch.setenv("FIXOPS_STRIPE_PRICE_ID_PRO", "price_pro_monthly_test")

    mock_session = MagicMock()
    mock_session.url = "https://checkout.stripe.com/pay/cs_test_abc123"

    with patch("stripe.checkout.Session.create", return_value=mock_session) as mock_create:
        resp = client.post(
            "/api/v1/billing/upgrade",
            json={"target_tier": "pro", "seats": 1},
            headers=_ORG_HDR,
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["checkout_url"] == "https://checkout.stripe.com/pay/cs_test_abc123"
    assert body["target_tier"] == "pro"
    assert body["status"] == "intent_recorded"

    # Verify stripe.checkout.Session.create was called with correct args
    mock_create.assert_called_once()
    call_kwargs = mock_create.call_args[1]
    assert call_kwargs["mode"] == "subscription"
    assert call_kwargs["line_items"][0]["price"] == "price_pro_monthly_test"
    assert call_kwargs["metadata"]["org_id"] is not None
    assert call_kwargs["metadata"]["target_tier"] == "pro"


# ---------------------------------------------------------------------------
# 2. POST /upgrade falls back to aldeci.ai URL when no stripe key is set
# ---------------------------------------------------------------------------

def test_upgrade_fallback_url_when_no_stripe_key(client, monkeypatch):
    """When FIXOPS_STRIPE_SECRET_KEY is absent, return branded fallback URL."""
    monkeypatch.delenv("FIXOPS_STRIPE_SECRET_KEY", raising=False)

    resp = client.post(
        "/api/v1/billing/upgrade",
        json={"target_tier": "enterprise", "seats": 5},
        headers=_ORG_HDR,
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "aldeci.ai/billing/checkout" in body["checkout_url"]
    assert "enterprise" in body["checkout_url"]


# ---------------------------------------------------------------------------
# 3. Stripe webhook — valid signature accepted via stripe.Webhook.construct_event
# ---------------------------------------------------------------------------

def test_webhook_valid_signature_accepted(client, monkeypatch):
    """construct_event succeeds → event is processed, returns 200."""
    monkeypatch.setenv("FIXOPS_STRIPE_WEBHOOK_SECRET", "whsec_test_secret")
    monkeypatch.setenv("FIXOPS_STRIPE_SECRET_KEY", "sk_test_fake")

    event_payload = json.dumps({
        "id": "evt_test_001",
        "type": "customer.subscription.created",
        "data": {
            "object": {
                "metadata": {"org_id": "webhook-smoke-org-001"},
                "items": {
                    "data": [
                        {
                            "plan": {"id": "price_pro", "nickname": "Pro"},
                            "price": {"id": "price_pro"},
                        }
                    ]
                },
            }
        },
    }).encode()

    # Mock construct_event to succeed (return value unused — we re-parse raw JSON)
    with patch("stripe.Webhook.construct_event", return_value=MagicMock()):
        resp = client.post(
            "/api/v1/billing/stripe-webhook",
            content=event_payload,
            headers={
                "stripe-signature": "t=1234,v1=fakesig",
                "content-type": "application/json",
            },
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["received"] is True
    assert body["action"] == "tier_set"
    assert body["tier"] == "pro"


# ---------------------------------------------------------------------------
# 4. Stripe webhook — invalid signature returns 400
# ---------------------------------------------------------------------------

def test_webhook_invalid_signature_rejected(client, monkeypatch):
    """construct_event raises SignatureVerificationError → 400 returned."""
    monkeypatch.setenv("FIXOPS_STRIPE_WEBHOOK_SECRET", "whsec_test_secret")
    monkeypatch.setenv("FIXOPS_STRIPE_SECRET_KEY", "sk_test_fake")

    import stripe as _stripe

    with patch(
        "stripe.Webhook.construct_event",
        side_effect=_stripe.error.SignatureVerificationError("bad sig", "t=1,v1=bad"),
    ):
        resp = client.post(
            "/api/v1/billing/stripe-webhook",
            content=b'{"type":"customer.subscription.created"}',
            headers={
                "stripe-signature": "t=1,v1=badsig",
                "content-type": "application/json",
            },
        )

    assert resp.status_code == 400
    assert "signature" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 5. Webhook subscription.deleted downgrades to starter
# ---------------------------------------------------------------------------

def test_webhook_subscription_deleted_downgrades(client, monkeypatch):
    """subscription.deleted event → org tier set back to starter."""
    monkeypatch.delenv("FIXOPS_STRIPE_WEBHOOK_SECRET", raising=False)

    from apps.api.billing_router import set_org_tier, get_org_tier

    test_org = "webhook-smoke-org-downgrade-005"
    set_org_tier(test_org, "enterprise")
    assert get_org_tier(test_org) == "enterprise"

    event_payload = json.dumps({
        "id": "evt_test_002",
        "type": "customer.subscription.deleted",
        "data": {
            "object": {
                "metadata": {"org_id": test_org},
                "items": {"data": []},
            }
        },
    }).encode()

    resp = client.post(
        "/api/v1/billing/stripe-webhook",
        content=event_payload,
        headers={"content-type": "application/json"},
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["action"] == "downgraded_to_starter"
    assert get_org_tier(test_org) == "starter"
