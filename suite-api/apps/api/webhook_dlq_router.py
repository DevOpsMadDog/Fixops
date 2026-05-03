"""Webhook DLQ Router — dead letter queue management for failed webhook deliveries.

12 endpoints at /api/v1/webhooks/dlq/*:
    GET    /api/v1/webhooks/dlq/                          -- list deliveries (org-scoped)
    POST   /api/v1/webhooks/dlq/enqueue                   -- manually enqueue a delivery
    GET    /api/v1/webhooks/dlq/pending                   -- list ready-for-retry deliveries
    GET    /api/v1/webhooks/dlq/dead-letters              -- list dead-lettered deliveries
    GET    /api/v1/webhooks/dlq/stats                     -- DLQ status counts
    GET    /api/v1/webhooks/dlq/analytics                 -- failure analytics
    GET    /api/v1/webhooks/dlq/{delivery_id}             -- fetch single delivery
    POST   /api/v1/webhooks/dlq/{delivery_id}/replay      -- manual replay single delivery
    POST   /api/v1/webhooks/dlq/replay-batch              -- bulk replay
    POST   /api/v1/webhooks/dlq/replay-by-event           -- replay all deliveries for an event_id
    DELETE /api/v1/webhooks/dlq/purge/delivered           -- purge old delivered records
    DELETE /api/v1/webhooks/dlq/purge/dead-letters        -- purge dead letters for org
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.webhook_dlq import DeliveryStatus, WebhookDelivery, WebhookDLQ
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/webhooks/dlq", tags=["webhook-dlq"])

_dlq = WebhookDLQ()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class EnqueueRequest(BaseModel):
    webhook_id: str = Field(..., max_length=256)
    event_id: str = Field(..., max_length=256)
    payload: Dict[str, Any] = Field(default_factory=dict)
    url: str = Field(..., max_length=2048)


class ReplayBatchRequest(BaseModel):
    delivery_ids: List[str] = Field(..., min_length=1, max_length=100)


class ReplayByEventRequest(BaseModel):
    event_id: str = Field(..., max_length=256, description="Replay all deliveries for this event_id")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _delivery_to_dict(d: WebhookDelivery) -> Dict[str, Any]:
    data = d.model_dump()
    # Convert datetime fields to ISO strings for JSON serialisation
    for field in ("next_retry_at", "created_at", "completed_at"):
        if data.get(field) is not None:
            val = data[field]
            data[field] = val.isoformat() if hasattr(val, "isoformat") else str(val)
    return data


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/")
async def list_deliveries(
    status: Optional[str] = Query(default=None, description="Filter by status"),
    webhook_id: Optional[str] = Query(default=None, description="Filter by webhook_id"),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """List webhook deliveries for the current organization, with optional filters."""
    # Validate status if provided
    valid_statuses = {s.value for s in DeliveryStatus}
    if status and status not in valid_statuses:
        raise HTTPException(422, f"Invalid status. Valid values: {sorted(valid_statuses)}")
    try:
        deliveries = _dlq.list_deliveries(org_id, status_filter=status, webhook_id=webhook_id)
    except RuntimeError as exc:
        logger.error("list_deliveries failed: %s", exc)
        raise HTTPException(500, "Internal DLQ error") from exc
    return [_delivery_to_dict(d) for d in deliveries]


@router.post("/enqueue", status_code=201)
async def enqueue_delivery(
    req: EnqueueRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Manually enqueue a webhook delivery into the DLQ."""
    try:
        delivery = _dlq.enqueue(
            webhook_id=req.webhook_id,
            event_id=req.event_id,
            payload=req.payload,
            url=req.url,
            org_id=org_id,
        )
    except RuntimeError as exc:
        logger.error("enqueue failed: %s", exc)
        raise HTTPException(500, "Failed to enqueue delivery") from exc
    return _delivery_to_dict(delivery)


@router.get("/pending")
async def list_pending(
    limit: int = Query(default=100, ge=1, le=1000),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """Return deliveries ready for retry (next_retry_at <= now)."""
    try:
        deliveries = _dlq.get_pending(limit=limit)
    except RuntimeError as exc:
        logger.error("get_pending failed: %s", exc)
        raise HTTPException(500, "Internal DLQ error") from exc
    return [_delivery_to_dict(d) for d in deliveries]


@router.get("/dead-letters")
async def list_dead_letters(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return all dead-lettered deliveries for the current organization."""
    try:
        deliveries = _dlq.get_dead_letters(org_id)
    except RuntimeError as exc:
        logger.error("get_dead_letters failed: %s", exc)
        raise HTTPException(500, "Internal DLQ error") from exc
    return {"dead_letters": [_delivery_to_dict(d) for d in deliveries], "count": len(deliveries)}


@router.get("/stats")
async def dlq_stats(org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Return DLQ status counts (pending, retrying, delivered, dead) for the org."""
    try:
        return _dlq.get_dlq_stats(org_id)
    except RuntimeError as exc:
        logger.error("get_dlq_stats failed: %s", exc)
        raise HTTPException(500, "Internal DLQ error") from exc


@router.get("/analytics")
async def failure_analytics(org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Return failure analytics: failure rate by webhook, top errors, avg retries."""
    try:
        return _dlq.get_failure_analytics(org_id)
    except RuntimeError as exc:
        logger.error("get_failure_analytics failed: %s", exc)
        raise HTTPException(500, "Internal DLQ error") from exc


@router.get("/{delivery_id}")
async def get_delivery(
    delivery_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Fetch a single webhook delivery by ID (org-scoped)."""
    try:
        delivery = _dlq.get_delivery(delivery_id)
    except ValueError:
        raise HTTPException(404, f"Delivery {delivery_id} not found")
    except RuntimeError as exc:
        logger.error("get_delivery failed for %s: %s", delivery_id, exc)
        raise HTTPException(500, "Internal DLQ error") from exc

    if delivery.org_id != org_id:
        raise HTTPException(403, "Delivery does not belong to this organization")

    return _delivery_to_dict(delivery)


@router.post("/replay-by-event")
async def replay_by_event(
    req: ReplayByEventRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Reset all deliveries for a given event_id for manual replay (org-scoped).

    Useful for replaying an entire event fan-out when the upstream event
    must be re-delivered to all matching webhooks.
    Returns the count of deliveries reset to PENDING.
    """
    try:
        count = _dlq.replay_by_event_id(event_id=req.event_id, org_id=org_id)
    except RuntimeError as exc:
        logger.error("replay_by_event failed for event_id=%s: %s", req.event_id, exc)
        raise HTTPException(500, "Failed to replay event deliveries") from exc

    return {
        "event_id": req.event_id,
        "replayed": count,
        "message": f"{count} delivery/deliveries queued for replay",
    }


@router.post("/{delivery_id}/replay")
async def replay_delivery(
    delivery_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Reset a dead-lettered delivery for manual replay."""
    # Verify ownership before replay
    try:
        delivery = _dlq.get_delivery(delivery_id)
    except ValueError:
        raise HTTPException(404, f"Delivery {delivery_id} not found")
    except RuntimeError as exc:
        raise HTTPException(500, "Internal DLQ error") from exc

    if delivery.org_id != org_id:
        raise HTTPException(403, "Delivery does not belong to this organization")

    try:
        replayed = _dlq.replay(delivery_id)
    except RuntimeError as exc:
        logger.error("replay failed for %s: %s", delivery_id, exc)
        raise HTTPException(500, "Failed to replay delivery") from exc

    return {"message": "Delivery queued for replay", "delivery": _delivery_to_dict(replayed)}


@router.post("/replay-batch")
async def replay_batch(
    req: ReplayBatchRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Bulk reset deliveries for manual replay.

    Returns the count of deliveries successfully reset.
    """
    # Filter to only delivery_ids owned by this org
    try:
        owned_ids: List[str] = []
        for did in req.delivery_ids:
            try:
                d = _dlq.get_delivery(did)
                if d.org_id == org_id:
                    owned_ids.append(did)
            except ValueError:
                pass  # skip missing deliveries

        count = _dlq.replay_batch(owned_ids)
    except RuntimeError as exc:
        logger.error("replay_batch failed: %s", exc)
        raise HTTPException(500, "Failed to replay batch") from exc

    return {"replayed": count, "requested": len(req.delivery_ids)}


@router.delete("/purge/delivered")
async def purge_delivered(
    days: int = Query(default=30, ge=1, le=365),
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Delete delivered records older than `days` days."""
    try:
        count = _dlq.purge_delivered(days=days)
    except RuntimeError as exc:
        logger.error("purge_delivered failed: %s", exc)
        raise HTTPException(500, "Failed to purge delivered records") from exc
    return {"purged": count, "days": days}


@router.delete("/purge/dead-letters")
async def purge_dead_letters(org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Delete all dead-lettered deliveries for the current organization."""
    try:
        count = _dlq.purge_dead_letters(org_id)
    except RuntimeError as exc:
        logger.error("purge_dead_letters failed: %s", exc)
        raise HTTPException(500, "Failed to purge dead letters") from exc
    return {"purged": count, "org_id": org_id}
