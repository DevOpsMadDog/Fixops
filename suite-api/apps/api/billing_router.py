"""
Billing Tier API — ALDECI Commercial P2.

Endpoints (all under /api/v1/billing):
    GET  /tier        — current org billing tier (Starter / Pro / Enterprise)
    POST /upgrade     — initiate Stripe Checkout Session, return session.url

Tier hierarchy (lowest → highest):
    starter < pro < enterprise

The ``requires_tier`` dependency returns HTTP 402 Payment Required when the
org's current tier is below the required tier.  Applied to high-value endpoints
in executive_reporting_router, risk_quantifier_router, and remediation_board_router.

Auth: inherited from app.py (_verify_api_key applied globally).
Stripe SDK (stripe-python >=7) is used when FIXOPS_STRIPE_SECRET_KEY is set.
"""
from __future__ import annotations

import logging
import os
import sqlite3
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from apps.api.dependencies import get_org_id
from core.audit_logger import AuditEvent, create_audit_logger

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/billing", tags=["billing"])

_audit = create_audit_logger()

# ---------------------------------------------------------------------------
# Tier ordering — integer rank for comparison
# ---------------------------------------------------------------------------

_TIER_RANK: Dict[str, int] = {
    "starter": 0,
    "pro": 1,
    "enterprise": 2,
}

_DEFAULT_TIER = "starter"

# ---------------------------------------------------------------------------
# Tier store — lightweight SQLite keyed by org_id
# ---------------------------------------------------------------------------

_DB_PATH = Path(os.getenv("FIXOPS_BILLING_DB", "data/billing.db"))


def _get_conn() -> sqlite3.Connection:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS org_tiers "
        "(org_id TEXT PRIMARY KEY, tier TEXT NOT NULL DEFAULT 'starter')"
    )
    conn.commit()
    return conn


def get_org_tier(org_id: str) -> str:
    """Return current tier for org (defaults to 'starter')."""
    try:
        with _get_conn() as conn:
            row = conn.execute(
                "SELECT tier FROM org_tiers WHERE org_id = ?", (org_id,)
            ).fetchone()
            return row[0] if row else _DEFAULT_TIER
    except Exception:
        logger.warning("billing: could not read tier for org %s, defaulting to starter", org_id)
        return _DEFAULT_TIER


def set_org_tier(org_id: str, tier: str) -> None:
    """Upsert tier for org."""
    tier = tier.lower()
    if tier not in _TIER_RANK:
        raise ValueError(f"Unknown tier: {tier}")
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO org_tiers (org_id, tier) VALUES (?, ?) "
            "ON CONFLICT(org_id) DO UPDATE SET tier=excluded.tier",
            (org_id, tier),
        )
        conn.commit()


# ---------------------------------------------------------------------------
# Tier-gate dependency
# ---------------------------------------------------------------------------

def requires_tier(minimum: str):
    """
    FastAPI dependency factory.  Returns HTTP 402 if org tier is below ``minimum``.

    Usage::

        @router.get("/premium-report")
        async def premium(org_id: str = Depends(requires_tier("enterprise"))):
            ...
    """
    minimum_lower = minimum.lower()
    if minimum_lower not in _TIER_RANK:
        raise ValueError(f"requires_tier: unknown tier '{minimum}'")

    async def _dep(org_id: str = Depends(get_org_id)) -> str:
        current = get_org_tier(org_id)
        if _TIER_RANK.get(current, 0) < _TIER_RANK[minimum_lower]:
            raise HTTPException(
                status_code=402,
                detail={
                    "error": "tier_required",
                    "required": minimum_lower,
                    "current": current,
                    "upgrade_url": "/api/v1/billing/upgrade",
                    "message": (
                        f"This feature requires the {minimum_lower.capitalize()} plan. "
                        f"Your org is on the {current.capitalize()} plan."
                    ),
                },
            )
        return org_id

    return _dep


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class TierResponse(BaseModel):
    org_id: str
    tier: str
    tier_rank: int
    features: Dict[str, Any]


class UpgradeRequest(BaseModel):
    target_tier: str = Field(..., description="pro | enterprise")
    seats: int = Field(default=1, ge=1, le=10000)


class UpgradeResponse(BaseModel):
    status: str
    checkout_url: str
    target_tier: str
    message: str


# ---------------------------------------------------------------------------
# Tier feature map (informational — returned in /tier response)
# ---------------------------------------------------------------------------

_TIER_FEATURES: Dict[str, Dict[str, Any]] = {
    "starter": {
        "price_usd_month": 199,
        "scans_per_month": 100,
        "exec_reporting": False,
        "risk_quantification": False,
        "board_presentations": False,
        "api_access": True,
        "support": "community",
    },
    "pro": {
        "price_usd_month": 499,
        "scans_per_month": 1000,
        "exec_reporting": True,
        "risk_quantification": True,
        "board_presentations": False,
        "api_access": True,
        "support": "email",
    },
    "enterprise": {
        "price_usd_month": 1499,
        "scans_per_month": -1,  # unlimited
        "exec_reporting": True,
        "risk_quantification": True,
        "board_presentations": True,
        "api_access": True,
        "support": "dedicated",
    },
}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/tier", response_model=TierResponse, summary="Get current billing tier")
async def get_tier(org_id: str = Depends(get_org_id)):
    """Return the current billing tier for the authenticated org."""
    tier = get_org_tier(org_id)
    return TierResponse(
        org_id=org_id,
        tier=tier,
        tier_rank=_TIER_RANK.get(tier, 0),
        features=_TIER_FEATURES.get(tier, {}),
    )


@router.post("/upgrade", response_model=UpgradeResponse, summary="Initiate tier upgrade")
async def initiate_upgrade(body: UpgradeRequest, org_id: str = Depends(get_org_id)):
    """
    Record upgrade intent and return a Stripe checkout URL placeholder.
    Real Stripe integration is wired when FIXOPS_STRIPE_SECRET_KEY is set.
    """
    target = body.target_tier.lower()
    if target not in _TIER_RANK:
        raise HTTPException(status_code=400, detail=f"Unknown tier: {body.target_tier}")

    current = get_org_tier(org_id)
    if _TIER_RANK.get(target, 0) <= _TIER_RANK.get(current, 0):
        raise HTTPException(
            status_code=400,
            detail=f"Target tier '{target}' is not higher than current tier '{current}'.",
        )

    _audit.log(AuditEvent(
        actor_id=org_id,
        action="billing.upgrade_intent",
        resource_type="billing",
        resource_id=org_id,
        org_id=org_id,
        result="success",
        details={"target_tier": target, "current_tier": current, "seats": body.seats},
    ))

    stripe_key = os.getenv("FIXOPS_STRIPE_SECRET_KEY", "")
    if stripe_key:
        try:
            import stripe as _stripe  # type: ignore

            _stripe.api_key = stripe_key

            # Resolve Stripe Price ID for the target tier
            price_id_env = f"FIXOPS_STRIPE_PRICE_ID_{target.upper()}"
            price_id = os.getenv(price_id_env, "")
            if not price_id:
                raise HTTPException(
                    status_code=500,
                    detail=f"Stripe price ID not configured: set {price_id_env}",
                )

            session = _stripe.checkout.Session.create(
                mode="subscription",
                line_items=[{"price": price_id, "quantity": body.seats}],
                success_url="https://aldeci.ai/billing/success?session_id={CHECKOUT_SESSION_ID}",
                cancel_url="https://aldeci.ai/billing/cancel",
                metadata={"org_id": org_id, "target_tier": target},
            )
            checkout_url = session.url or ""
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("stripe checkout session creation failed: %s", exc)
            raise HTTPException(status_code=502, detail="Stripe checkout session creation failed")
    else:
        checkout_url = (
            f"https://aldeci.ai/billing/checkout?org={org_id}&tier={target}&seats={body.seats}"
        )

    return UpgradeResponse(
        status="intent_recorded",
        checkout_url=checkout_url,
        target_tier=target,
        message=(
            f"Upgrade intent recorded. Complete checkout at the URL to activate {target} tier."
        ),
    )
