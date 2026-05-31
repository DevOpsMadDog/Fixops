"""Industry Benchmarking Router — ALDECI.

Prefix: /api/v1/benchmarking
Auth:   api_key_auth dependency

Routes:
  GET  /api/v1/benchmarking/industry   industry_benchmarking  (501 — no peer feed)
  GET  /api/v1/benchmarking/status     benchmarking_status

NOTE: Industry peer benchmarking requires an external peer-data feed subscription
that is not bundled with this product.  Until a real feed is configured and
ingested, all peer-percentile endpoints return HTTP 501 with a clear
``configured: false`` signal.  No fabricated percentiles are ever returned.
"""

from __future__ import annotations

import logging

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/benchmarking",
    tags=["Benchmarking"],
)

_NOT_CONFIGURED_DETAIL = (
    "Industry benchmarking requires an external peer-data feed which is not "
    "configured.  Contact your ALDECI account team to enable this feature."
)


@router.get("/industry", dependencies=[Depends(api_key_auth)])
def industry_benchmarking():
    """Return industry peer-benchmarking percentiles.

    Returns HTTP 501 until an external peer-data feed is configured and
    ingested.  Never returns fabricated percentile values.
    """
    raise HTTPException(
        status_code=501,
        detail={
            "detail": _NOT_CONFIGURED_DETAIL,
            "configured": False,
            "feature": "industry_benchmarking",
            "action_required": "configure_peer_data_feed",
        },
    )


@router.get("/status", dependencies=[Depends(api_key_auth)])
def benchmarking_status():
    """Return the configuration status of the benchmarking feature."""
    return {
        "configured": False,
        "feature": "industry_benchmarking",
        "detail": _NOT_CONFIGURED_DETAIL,
    }
