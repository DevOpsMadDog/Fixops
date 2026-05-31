"""Peer Insights Router — ALDECI.

Prefix: /api/v1/peer-insights
Auth:   api_key_auth dependency

Routes:
  GET  /api/v1/peer-insights/trends   peer_trends   (501 — no peer feed)
  GET  /api/v1/peer-insights/status   peer_status

NOTE: Peer-insights trend data requires an external industry-data feed
subscription that is not bundled with this product.  Until a real feed is
configured and ingested, all peer-trend endpoints return HTTP 501 with a clear
``configured: false`` signal.  No fabricated trend data is ever returned.
"""

from __future__ import annotations

import logging

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/peer-insights",
    tags=["Peer Insights"],
)

_NOT_CONFIGURED_DETAIL = (
    "Peer insights require an external industry peer-data feed which is not "
    "configured.  Contact your ALDECI account team to enable this feature."
)


@router.get("/trends", dependencies=[Depends(api_key_auth)])
def peer_trends():
    """Return industry peer-trend data.

    Returns HTTP 501 until an external peer-data feed is configured and
    ingested.  Never returns fabricated trend values.
    """
    raise HTTPException(
        status_code=501,
        detail={
            "detail": _NOT_CONFIGURED_DETAIL,
            "configured": False,
            "feature": "peer_insights_trends",
            "action_required": "configure_peer_data_feed",
        },
    )


@router.get("/status", dependencies=[Depends(api_key_auth)])
def peer_status():
    """Return the configuration status of the peer-insights feature."""
    return {
        "configured": False,
        "feature": "peer_insights_trends",
        "detail": _NOT_CONFIGURED_DETAIL,
    }
