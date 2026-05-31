"""Stripe Billing Router — ALDECI (2026-05-31).

Wraps the Stripe REST API (v1) with live httpx calls for customer management,
subscription lifecycle, and webhook event handling.

Prefix: /api/v1/billing
Auth:   api_key_auth dependency (read:scans scope at registration)

Routes:
  GET  /api/v1/billing/                              info + configured status + mode
  POST /api/v1/billing/customers                     create Stripe customer
  POST /api/v1/billing/subscriptions                 create subscription
  GET  /api/v1/billing/subscriptions/{sub_id}        retrieve subscription
  POST /api/v1/billing/subscriptions/{sub_id}/cancel cancel subscription
  POST /api/v1/billing/webhook                       Stripe-signature-verified webhook

NO MOCKS rule: when STRIPE_SECRET_KEY is missing every live endpoint returns
HTTP 503 with ``{"error":"stripe_not_configured","needed":["STRIPE_SECRET_KEY"]}``.
We do not fabricate customer IDs, subscription objects, or billing data ever.

Credentials
-----------
  STRIPE_SECRET_KEY     — Stripe API key (sk_live_... or sk_test_...).
                          Mode is inferred from the key prefix:
                            sk_live_  -> live
                            sk_test_  -> test
                            other     -> unknown
  STRIPE_WEBHOOK_SECRET — (optional) Stripe webhook signing secret (whsec_...).
                          When set, stripe-signature header is verified.
                          When unset, signature verification is skipped with a
                          warning (development/test only).

Implementation note: the ``stripe`` Python SDK is not installed in this
environment. All calls use direct httpx requests to api.stripe.com using
HTTP Basic Auth (API key as username, empty password), matching the Stripe
REST API v1 specification.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

import httpx
from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, Header, HTTPException, Path, Request
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

_STRIPE_BASE_URL = "https://api.stripe.com/v1"
_TIMEOUT = 15.0  # seconds — Stripe can be slow on first call
_NOT_CONFIGURED_ERROR = "stripe_not_configured"
_NEEDED_VARS = ["STRIPE_SECRET_KEY"]

# Auth-protected endpoints (api_key_auth required)
router = APIRouter(
    prefix="/api/v1/billing",
    tags=["Billing"],
    dependencies=[Depends(api_key_auth)],
)

# Webhook endpoint (no api_key_auth — Stripe signs the payload instead)
webhook_router = APIRouter(
    prefix="/api/v1/billing",
    tags=["Billing"],
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_key() -> Optional[str]:
    """Return the Stripe secret key or None if unset/blank."""
    key = os.environ.get("STRIPE_SECRET_KEY", "").strip()
    return key if key else None


def _require_key() -> str:
    """Return the Stripe secret key or raise HTTP 503 not_configured."""
    key = _get_key()
    if key is None:
        raise HTTPException(
            status_code=503,
            detail={
                "error": _NOT_CONFIGURED_ERROR,
                "needed": _NEEDED_VARS,
            },
        )
    return key


def _mode(key: str) -> str:
    """Infer Stripe mode from key prefix."""
    if key.startswith("sk_live_"):
        return "live"
    if key.startswith("sk_test_"):
        return "test"
    return "unknown"


def _auth(key: str) -> httpx.BasicAuth:
    """Return httpx BasicAuth for Stripe (key as username, empty password)."""
    return httpx.BasicAuth(username=key, password="")


async def _stripe_post(key: str, path: str, data: Dict[str, Any]) -> Any:
    """POST form-encoded data to Stripe API. Returns parsed JSON or raises HTTPException."""
    url = f"{_STRIPE_BASE_URL}{path}"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(url, auth=_auth(key), data=data)
    except httpx.TimeoutException as exc:
        _logger.warning("stripe_timeout path=%s exc=%s", path, exc)
        raise HTTPException(
            status_code=504,
            detail={"error": "stripe_timeout", "path": path},
        ) from exc
    except httpx.HTTPError as exc:
        _logger.warning("stripe_http_error path=%s exc=%s", path, exc)
        raise HTTPException(
            status_code=502,
            detail={"error": "stripe_upstream_error", "path": path},
        ) from exc

    try:
        body = resp.json()
    except Exception:
        body = {"error": "stripe_invalid_json", "status": resp.status_code}

    if resp.status_code >= 400:
        _logger.warning(
            "stripe_upstream_error path=%s status=%d body=%.300s",
            path, resp.status_code, resp.text,
        )
        raise HTTPException(status_code=resp.status_code, detail=body)

    return body


async def _stripe_get(key: str, path: str) -> Any:
    """GET from Stripe API. Returns parsed JSON or raises HTTPException."""
    url = f"{_STRIPE_BASE_URL}{path}"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(url, auth=_auth(key))
    except httpx.TimeoutException as exc:
        _logger.warning("stripe_timeout path=%s exc=%s", path, exc)
        raise HTTPException(
            status_code=504,
            detail={"error": "stripe_timeout", "path": path},
        ) from exc
    except httpx.HTTPError as exc:
        _logger.warning("stripe_http_error path=%s exc=%s", path, exc)
        raise HTTPException(
            status_code=502,
            detail={"error": "stripe_upstream_error", "path": path},
        ) from exc

    try:
        body = resp.json()
    except Exception:
        body = {"error": "stripe_invalid_json", "status": resp.status_code}

    if resp.status_code >= 400:
        _logger.warning(
            "stripe_upstream_error path=%s status=%d body=%.300s",
            path, resp.status_code, resp.text,
        )
        raise HTTPException(status_code=resp.status_code, detail=body)

    return body


def _verify_stripe_signature(
    payload: bytes,
    sig_header: str,
    secret: str,
    tolerance_seconds: int = 300,
) -> bool:
    """Verify Stripe-Signature header using HMAC-SHA256.

    Returns True if valid, raises HTTPException 400 on any mismatch.
    See: https://stripe.com/docs/webhooks/signatures
    """
    try:
        parts = {
            p.split("=", 1)[0]: p.split("=", 1)[1]
            for p in sig_header.split(",")
            if "=" in p
        }
        timestamp = int(parts.get("t", "0"))
        signatures = [v for k, v in parts.items() if k == "v1"]
    except (ValueError, KeyError) as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": "stripe_signature_malformed"},
        ) from exc

    if not timestamp or not signatures:
        raise HTTPException(
            status_code=400,
            detail={"error": "stripe_signature_missing_fields"},
        )

    # Replay-attack guard
    if abs(time.time() - timestamp) > tolerance_seconds:
        raise HTTPException(
            status_code=400,
            detail={"error": "stripe_signature_expired"},
        )

    signed_payload = f"{timestamp}.".encode() + payload
    expected = hmac.new(
        secret.encode("utf-8"),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()

    if not any(hmac.compare_digest(expected, sig) for sig in signatures):
        raise HTTPException(
            status_code=400,
            detail={"error": "stripe_signature_invalid"},
        )

    return True


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class BillingInfoResponse(BaseModel):
    service: str = "Stripe Billing API"
    version: str = "v1"
    endpoints: List[str]
    configured: bool
    mode: str  # test | live | unknown | unconfigured


class CreateCustomerRequest(BaseModel):
    email: str = Field(..., description="Customer email address")
    name: Optional[str] = Field(None, description="Customer full name")


class CustomerResponse(BaseModel):
    model_config = {"extra": "allow"}


class CreateSubscriptionRequest(BaseModel):
    customer_id: str = Field(..., description="Stripe customer ID (cus_...)")
    price_id: str = Field(..., description="Stripe price ID (price_...)")


class SubscriptionResponse(BaseModel):
    model_config = {"extra": "allow"}


class WebhookResponse(BaseModel):
    received: bool = True
    event_type: Optional[str] = None


# ---------------------------------------------------------------------------
# GET / — billing info (always returns 200, no creds required beyond api_key)
# ---------------------------------------------------------------------------


@router.get("/", response_model=BillingInfoResponse)
async def billing_info() -> BillingInfoResponse:
    """Billing connector capability summary — safe to call without Stripe credentials.

    Returns configured-status and mode (test vs live) so the UI can surface
    actionable setup guidance without requiring a live Stripe account.
    """
    key = _get_key()
    configured = key is not None
    mode = _mode(key) if configured else "unconfigured"

    _logger.info("billing_info configured=%s mode=%s", configured, mode)
    return BillingInfoResponse(
        endpoints=[
            "POST /customers",
            "POST /subscriptions",
            "GET /subscriptions/{sub_id}",
            "POST /subscriptions/{sub_id}/cancel",
            "POST /webhook",
        ],
        configured=configured,
        mode=mode,
    )


# ---------------------------------------------------------------------------
# POST /customers — create Stripe customer
# ---------------------------------------------------------------------------


@router.post("/customers", response_model=CustomerResponse, status_code=201)
async def create_customer(body: CreateCustomerRequest) -> CustomerResponse:
    """Create a new Stripe customer.

    Upstream: POST /v1/customers
    Returns 503 when STRIPE_SECRET_KEY is unset.
    Returns 201 with the created Customer object on success.
    """
    key = _require_key()
    data: Dict[str, Any] = {"email": body.email}
    if body.name:
        data["name"] = body.name

    result = await _stripe_post(key, "/customers", data)
    _logger.info("billing_create_customer id=%s email=%s", result.get("id"), body.email)
    return CustomerResponse(**result)


# ---------------------------------------------------------------------------
# POST /subscriptions — create subscription
# ---------------------------------------------------------------------------


@router.post("/subscriptions", response_model=SubscriptionResponse, status_code=201)
async def create_subscription(body: CreateSubscriptionRequest) -> SubscriptionResponse:
    """Create a new Stripe subscription.

    Upstream: POST /v1/subscriptions
    Returns 503 when STRIPE_SECRET_KEY is unset.
    Returns 201 with the created Subscription object on success.
    """
    key = _require_key()
    data: Dict[str, Any] = {
        "customer": body.customer_id,
        "items[0][price]": body.price_id,
    }

    result = await _stripe_post(key, "/subscriptions", data)
    _logger.info(
        "billing_create_subscription id=%s customer=%s price=%s status=%s",
        result.get("id"), body.customer_id, body.price_id, result.get("status"),
    )
    return SubscriptionResponse(**result)


# ---------------------------------------------------------------------------
# GET /subscriptions/{sub_id} — retrieve subscription
# ---------------------------------------------------------------------------


@router.get("/subscriptions/{sub_id}", response_model=SubscriptionResponse)
async def get_subscription(
    sub_id: str = Path(..., min_length=1, max_length=255, description="Stripe subscription ID (sub_...)"),
) -> SubscriptionResponse:
    """Retrieve a Stripe subscription by ID.

    Upstream: GET /v1/subscriptions/{sub_id}
    Returns 503 when STRIPE_SECRET_KEY is unset.
    """
    key = _require_key()
    result = await _stripe_get(key, f"/subscriptions/{sub_id}")
    _logger.info(
        "billing_get_subscription id=%s status=%s",
        result.get("id"), result.get("status"),
    )
    return SubscriptionResponse(**result)


# ---------------------------------------------------------------------------
# POST /subscriptions/{sub_id}/cancel — cancel subscription
# ---------------------------------------------------------------------------


@router.post("/subscriptions/{sub_id}/cancel", response_model=SubscriptionResponse)
async def cancel_subscription(
    sub_id: str = Path(..., min_length=1, max_length=255, description="Stripe subscription ID (sub_...)"),
) -> SubscriptionResponse:
    """Cancel a Stripe subscription immediately.

    Upstream: POST /v1/subscriptions/{sub_id}/cancel  (empty body)
    Returns 503 when STRIPE_SECRET_KEY is unset.
    """
    key = _require_key()
    result = await _stripe_post(key, f"/subscriptions/{sub_id}/cancel", {})
    _logger.info(
        "billing_cancel_subscription id=%s status=%s",
        result.get("id"), result.get("status"),
    )
    return SubscriptionResponse(**result)


# ---------------------------------------------------------------------------
# POST /webhook — Stripe webhook receiver (no api_key_auth — uses sig verify)
# Registered on webhook_router (separate router, no Depends(api_key_auth)).
# ---------------------------------------------------------------------------


@webhook_router.post("/webhook", response_model=WebhookResponse)
async def stripe_webhook(
    request: Request,
    stripe_signature: Optional[str] = Header(None, alias="stripe-signature"),
) -> WebhookResponse:
    """Handle Stripe webhook events with optional signature verification.

    Supported events:
      - customer.subscription.deleted
      - invoice.payment_failed

    Signature is verified against STRIPE_WEBHOOK_SECRET when set.
    When STRIPE_WEBHOOK_SECRET is unset, verification is skipped with a warning
    (suitable for development/test; always set in production).

    Always returns 200 so Stripe does not retry events we explicitly handle.
    """
    raw_body = await request.body()
    webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "").strip()

    if webhook_secret:
        if not stripe_signature:
            _logger.warning("stripe_webhook_missing_signature")
            raise HTTPException(
                status_code=400,
                detail={"error": "stripe_signature_required"},
            )
        _verify_stripe_signature(raw_body, stripe_signature, webhook_secret)
    else:
        _logger.warning(
            "stripe_webhook_no_secret_configured — skipping signature verification "
            "(set STRIPE_WEBHOOK_SECRET in production)"
        )

    try:
        event = json.loads(raw_body)
    except Exception as exc:
        _logger.warning("stripe_webhook_invalid_json exc=%s", exc)
        raise HTTPException(status_code=400, detail={"error": "invalid_json"}) from exc

    event_type = event.get("type", "unknown")
    event_id = event.get("id", "unknown")

    if event_type == "customer.subscription.deleted":
        obj = event.get("data", {}).get("object", {})
        sub_id = obj.get("id", "unknown")
        customer_id = obj.get("customer", "unknown")
        _logger.info(
            "stripe_webhook event=%s id=%s sub=%s customer=%s",
            event_type, event_id, sub_id, customer_id,
        )

    elif event_type == "invoice.payment_failed":
        obj = event.get("data", {}).get("object", {})
        invoice_id = obj.get("id", "unknown")
        customer_id = obj.get("customer", "unknown")
        amount_due = obj.get("amount_due", 0)
        _logger.warning(
            "stripe_webhook event=%s id=%s invoice=%s customer=%s amount_due=%d",
            event_type, event_id, invoice_id, customer_id, amount_due,
        )

    else:
        _logger.info(
            "stripe_webhook event=%s id=%s (unhandled — acknowledged)",
            event_type, event_id,
        )

    return WebhookResponse(received=True, event_type=event_type)


__all__ = ["router", "webhook_router"]
