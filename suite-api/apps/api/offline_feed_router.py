"""Offline Feed Router — GAP-002.

Exposes air-gapped threat-intel bundle ingestion plus offline-mode toggle for
existing feed subscriptions. Uses the already-landed
`threat_intel_fusion_engine.ingest_offline_bundle()` method and the new
`threat_feed_subscription_engine.enable_offline_mode()` /
`disable_offline_mode()` methods.

Endpoints (all under /api/v1/offline-feed):

  POST /api/v1/offline-feed/ingest   — ingest a tar.gz bundle by path
  POST /api/v1/offline-feed/enable   — flip org's subscriptions to offline mode
  POST /api/v1/offline-feed/disable  — flip back to online mode
  GET  /api/v1/offline-feed/bundles  — list discovered bundles + offline subs

Auth: `api_key_auth` via `dependencies=[Depends(api_key_auth)]`.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/offline-feed", tags=["offline-feed"])


# ---------------------------------------------------------------------------
# Lazy engine loaders — never crash router import when an engine is offline.
# ---------------------------------------------------------------------------

_fusion_engine = None
_feed_engine = None


def _get_fusion_engine():
    global _fusion_engine
    if _fusion_engine is None:
        from core.threat_intel_fusion_engine import (
            ThreatIntelFusionEngine,  # type: ignore
        )

        _fusion_engine = ThreatIntelFusionEngine()
    return _fusion_engine


def _get_feed_engine():
    global _feed_engine
    if _feed_engine is None:
        from core.threat_feed_subscription_engine import (
            ThreatFeedSubscriptionEngine,  # type: ignore
        )

        _feed_engine = ThreatFeedSubscriptionEngine()
    return _feed_engine


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class IngestRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=128)
    bundle_path: str = Field(..., min_length=1, max_length=2048)
    verify: bool = Field(default=True)


class EnableOfflineRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=128)
    bundle_source_path: str = Field(..., min_length=1, max_length=2048)
    subscription_id: Optional[str] = Field(default=None, max_length=128)


class DisableOfflineRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=128)
    subscription_id: Optional[str] = Field(default=None, max_length=128)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/ingest")
def ingest_offline_bundle(req: IngestRequest) -> Dict[str, Any]:
    """Ingest an air-gapped threat-intel bundle (.tar.gz).

    Delegates to `ThreatIntelFusionEngine.ingest_offline_bundle()`, which
    verifies sha256 hashes in MANIFEST.json and applies TI entries as
    fusion indicators.
    """
    # Basic path traversal guard — refuse bundles containing '..'
    if ".." in req.bundle_path.split("/"):
        raise HTTPException(status_code=400, detail="invalid bundle_path")
    try:
        engine = _get_fusion_engine()
    except ImportError as exc:  # pragma: no cover
        raise HTTPException(status_code=503, detail=f"fusion engine unavailable: {exc}")

    try:
        result = engine.ingest_offline_bundle(
            org_id=req.org_id,
            bundle_path=req.bundle_path,
            verify=req.verify,
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # pragma: no cover
        logger.exception("offline_feed.ingest failed")
        raise HTTPException(status_code=500, detail=f"ingest error: {exc}")
    return result


@router.post("/enable")
def enable_offline_mode(req: EnableOfflineRequest) -> Dict[str, Any]:
    """Flip feed subscriptions into offline mode for an org."""
    try:
        engine = _get_feed_engine()
    except ImportError as exc:  # pragma: no cover
        raise HTTPException(status_code=503, detail=f"feed engine unavailable: {exc}")
    try:
        return engine.enable_offline_mode(
            req.org_id, req.bundle_source_path, subscription_id=req.subscription_id
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/disable")
def disable_offline_mode(req: DisableOfflineRequest) -> Dict[str, Any]:
    """Return feed subscriptions to online mode for an org."""
    try:
        engine = _get_feed_engine()
    except ImportError as exc:  # pragma: no cover
        raise HTTPException(status_code=503, detail=f"feed engine unavailable: {exc}")
    try:
        return engine.disable_offline_mode(
            req.org_id, subscription_id=req.subscription_id
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/bundles")
def list_bundles(org_id: str = Query(default="default", min_length=1)) -> Dict[str, Any]:
    """List discovered air-gapped bundles + currently offline subscriptions."""
    try:
        fusion = _get_fusion_engine()
    except ImportError as exc:  # pragma: no cover
        raise HTTPException(status_code=503, detail=f"fusion engine unavailable: {exc}")
    try:
        feed = _get_feed_engine()
    except ImportError as exc:  # pragma: no cover
        raise HTTPException(status_code=503, detail=f"feed engine unavailable: {exc}")

    bundles: List[Dict[str, Any]] = []
    try:
        if hasattr(fusion, "list_offline_bundles"):
            bundles = fusion.list_offline_bundles(org_id)
    except Exception as exc:  # pragma: no cover
        logger.warning("list_offline_bundles failed: %s", exc)

    offline_subs: List[Dict[str, Any]] = []
    try:
        offline_subs = feed.list_offline_subscriptions(org_id)
    except Exception as exc:  # pragma: no cover
        logger.warning("list_offline_subscriptions failed: %s", exc)

    return {
        "org_id": org_id,
        "bundles": bundles,
        "bundles_count": len(bundles),
        "offline_subscriptions": offline_subs,
        "offline_subscriptions_count": len(offline_subs),
    }
