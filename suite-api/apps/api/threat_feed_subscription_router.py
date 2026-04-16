"""Threat Feed Subscription API Router — ALDECI.

Endpoints (all under /api/v1/feed-subscriptions):

  Subscriptions:
    POST   /subscriptions                          — create subscription
    GET    /subscriptions                          — list subscriptions
    GET    /subscriptions/{id}                     — get subscription + logs
    PATCH  /subscriptions/{id}/status              — update status
    POST   /subscriptions/{id}/ingestion           — record ingestion run

  Deliveries:
    POST   /subscriptions/{id}/deliveries          — create delivery channel
    POST   /subscriptions/{id}/deliveries/{d_id}/record — record delivery

  Due / Stats:
    GET    /due                                    — get subscriptions due for fetch
    GET    /stats                                  — ingestion statistics

Auth: _verify_api_key
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/feed-subscriptions", tags=["feed-subscriptions"])

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.threat_feed_subscription_engine import ThreatFeedSubscriptionEngine
        _engine = ThreatFeedSubscriptionEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateSubscriptionRequest(BaseModel):
    feed_name: str = Field(..., min_length=1)
    feed_type: str = Field(default="osint")
    feed_url: str = Field(default="")
    api_key: str = Field(default="")
    refresh_interval_minutes: int = Field(default=60, ge=1)


class UpdateStatusRequest(BaseModel):
    status: str = Field(...)


class RecordIngestionRequest(BaseModel):
    iocs_fetched: int = Field(default=0, ge=0)
    iocs_new: int = Field(default=0, ge=0)
    iocs_updated: int = Field(default=0, ge=0)
    status: str = Field(default="success")
    error_message: str = Field(default="")


class CreateDeliveryRequest(BaseModel):
    delivery_type: str = Field(...)
    endpoint: str = Field(default="")
    filter_severity: str = Field(default="all")
    filter_categories: List[str] = Field(default_factory=list)


class RecordDeliveryRequest(BaseModel):
    count: int = Field(default=1, ge=1)


# ---------------------------------------------------------------------------
# Subscriptions
# ---------------------------------------------------------------------------

@router.post("/subscriptions", summary="Create a feed subscription")
def create_subscription(req: CreateSubscriptionRequest, org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().create_subscription(
            org_id=org_id,
            feed_name=req.feed_name,
            feed_type=req.feed_type,
            feed_url=req.feed_url,
            api_key=req.api_key,
            refresh_interval_minutes=req.refresh_interval_minutes,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/subscriptions", summary="List feed subscriptions")
def list_subscriptions(
    status: Optional[str] = Query(None),
    feed_type: Optional[str] = Query(None),
    org_id: str = Query(default="default"),
) -> List[Dict[str, Any]]:
    return _get_engine().list_subscriptions(org_id, status=status, feed_type=feed_type)


@router.get("/subscriptions/{subscription_id}", summary="Get subscription with ingestion logs")
def get_subscription(subscription_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    result = _get_engine().get_subscription(subscription_id, org_id)
    if not result:
        raise HTTPException(status_code=404, detail="Subscription not found")
    return result


@router.patch("/subscriptions/{subscription_id}/status", summary="Update subscription status")
def update_status(subscription_id: str, req: UpdateStatusRequest, org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().update_subscription_status(subscription_id, org_id, req.status)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/subscriptions/{subscription_id}/ingestion", summary="Record an ingestion run")
def record_ingestion(subscription_id: str, req: RecordIngestionRequest, org_id: str = Query(default="default")) -> Dict[str, Any]:
    return _get_engine().record_ingestion(
        subscription_id=subscription_id,
        org_id=org_id,
        iocs_fetched=req.iocs_fetched,
        iocs_new=req.iocs_new,
        iocs_updated=req.iocs_updated,
        status=req.status,
        error_message=req.error_message,
    )


# ---------------------------------------------------------------------------
# Deliveries
# ---------------------------------------------------------------------------

@router.post("/subscriptions/{subscription_id}/deliveries", summary="Create delivery channel")
def create_delivery(subscription_id: str, req: CreateDeliveryRequest, org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().create_delivery(
            subscription_id=subscription_id,
            org_id=org_id,
            delivery_type=req.delivery_type,
            endpoint=req.endpoint,
            filter_severity=req.filter_severity,
            filter_categories=req.filter_categories,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post(
    "/subscriptions/{subscription_id}/deliveries/{delivery_id}/record",
    summary="Record a delivery",
)
def record_delivery(
    subscription_id: str, delivery_id: str, req: RecordDeliveryRequest, org_id: str = Query(default="default")
) -> Dict[str, Any]:
    try:
        return _get_engine().record_delivery(delivery_id, org_id, req.count)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ---------------------------------------------------------------------------
# Due / Stats
# ---------------------------------------------------------------------------

@router.get("/due", summary="Get subscriptions due for fetch")
def get_due(org_id: str = Query(default="default")) -> List[Dict[str, Any]]:
    return _get_engine().get_due_subscriptions(org_id)


@router.get("/stats", summary="Ingestion statistics")
def get_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    return _get_engine().get_ingestion_stats(org_id)
