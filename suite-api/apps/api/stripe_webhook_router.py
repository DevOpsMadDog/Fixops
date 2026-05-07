"""
Stripe Webhook Handler — ALDECI Commercial P2.

Endpoint:
    POST /api/v1/billing/stripe-webhook

Processes Stripe event types:
    customer.subscription.created  → upgrade org tier
    customer.subscription.updated  → update org tier
    customer.subscription.deleted  → downgrade org to Starter

Signature verification: stripe.Webhook.construct_event() when FIXOPS_STRIPE_WEBHOOK_SECRET
is set; falls back to raw JSON parse in dev mode (no secret configured).
Auth: exempt from API key check (Stripe calls this endpoint directly).
All events logged via AuditLogger.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from core.audit_logger import AuditEvent, create_audit_logger

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/billing", tags=["billing-webhook"])

_audit = create_audit_logger()

# Stripe plan → ALDECI tier mapping
_PLAN_TO_TIER: Dict[str, str] = {
    "starter": "starter",
    "pro": "pro",
    "enterprise": "enterprise",
    # price IDs (set these in Stripe dashboard to match)
    "price_starter": "starter",
    "price_pro": "pro",
    "price_enterprise": "enterprise",
}


def _extract_tier_from_subscription(subscription: Dict[str, Any]) -> str:
    """Derive ALDECI tier from Stripe subscription object."""
    items = subscription.get("items", {}).get("data", [])
    for item in items:
        plan_id = item.get("plan", {}).get("id", "").lower()
        price_id = item.get("price", {}).get("id", "").lower()
        nickname = item.get("plan", {}).get("nickname", "").lower()
        for key in (plan_id, price_id, nickname):
            for fragment, tier in _PLAN_TO_TIER.items():
                if fragment in key:
                    return tier
    return "starter"


@router.post(
    "/stripe-webhook",
    summary="Stripe webhook receiver",
    response_class=JSONResponse,
    include_in_schema=True,
)
async def stripe_webhook(request: Request):
    """
    Receive and process Stripe webhook events.
    When FIXOPS_STRIPE_WEBHOOK_SECRET is set, signature is validated via
    stripe.Webhook.construct_event() — cryptographically sound, replay-safe.
    In dev mode (no secret), raw JSON is accepted without verification.
    """
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")
    secret = os.getenv("FIXOPS_STRIPE_WEBHOOK_SECRET", "")

    if secret:
        try:
            import stripe as _stripe  # type: ignore

            _stripe.api_key = os.getenv("FIXOPS_STRIPE_SECRET_KEY", "")
            event_obj = _stripe.Webhook.construct_event(payload, sig_header, secret)
            # construct_event returns a stripe.Event object; convert to plain dict
            event: Dict[str, Any] = json.loads(payload)
        except Exception as exc:
            logger.warning("stripe_webhook: signature verification failed: %s", exc)
            raise HTTPException(status_code=400, detail="Invalid Stripe signature")
    else:
        logger.warning("stripe_webhook: FIXOPS_STRIPE_WEBHOOK_SECRET not set — skipping sig check")
        try:
            event = json.loads(payload)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON payload")

    event_type: str = event.get("type", "")
    event_id: str = event.get("id", "unknown")
    data_obj: Dict[str, Any] = event.get("data", {}).get("object", {})

    # Extract org_id from Stripe metadata (set when creating the subscription)
    org_id: str = (
        data_obj.get("metadata", {}).get("org_id")
        or data_obj.get("customer", "unknown")
    )

    logger.info("stripe_webhook: received event_type=%s event_id=%s org=%s", event_type, event_id, org_id)

    # Lazy import to avoid circular dependency at module load
    from apps.api.billing_router import set_org_tier, get_org_tier

    if event_type == "customer.subscription.created":
        new_tier = _extract_tier_from_subscription(data_obj)
        set_org_tier(org_id, new_tier)
        _audit.log(AuditEvent(
            actor_id="stripe",
            action="billing.subscription_created",
            resource_type="billing",
            resource_id=event_id,
            org_id=org_id,
            result="success",
            details={"new_tier": new_tier, "stripe_event_id": event_id},
        ))
        return {"received": True, "action": "tier_set", "tier": new_tier}

    elif event_type == "customer.subscription.updated":
        new_tier = _extract_tier_from_subscription(data_obj)
        old_tier = get_org_tier(org_id)
        set_org_tier(org_id, new_tier)
        _audit.log(AuditEvent(
            actor_id="stripe",
            action="billing.subscription_updated",
            resource_type="billing",
            resource_id=event_id,
            org_id=org_id,
            result="success",
            details={"old_tier": old_tier, "new_tier": new_tier, "stripe_event_id": event_id},
        ))
        return {"received": True, "action": "tier_updated", "old_tier": old_tier, "new_tier": new_tier}

    elif event_type == "customer.subscription.deleted":
        old_tier = get_org_tier(org_id)
        set_org_tier(org_id, "starter")
        _audit.log(AuditEvent(
            actor_id="stripe",
            action="billing.subscription_deleted",
            resource_type="billing",
            resource_id=event_id,
            org_id=org_id,
            result="success",
            details={"downgraded_from": old_tier, "stripe_event_id": event_id},
        ))
        return {"received": True, "action": "downgraded_to_starter", "previous_tier": old_tier}

    else:
        # Acknowledge all other events without processing
        _audit.log(AuditEvent(
            actor_id="stripe",
            action=f"billing.webhook_ignored.{event_type}",
            resource_type="billing",
            resource_id=event_id,
            org_id=org_id,
            result="success",
            details={"stripe_event_id": event_id},
        ))
        return {"received": True, "action": "ignored", "event_type": event_type}
