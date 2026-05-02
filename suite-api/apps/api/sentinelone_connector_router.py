"""SentinelOne Singularity XDR Connector Router.

Prefix: /api/v1/connectors/sentinelone
Auth:   api_key_auth (token or JWT)

Routes:
  POST /api/v1/connectors/sentinelone/ingest         - Ingest a SentinelOne API
                                                        /threats dump (JSON wrapper
                                                        ``{data: [...]}`` or list)
  POST /api/v1/connectors/sentinelone/ingest/sample  - Ingest the embedded fallback
                                                        sample (offline demo mode)
  GET  /api/v1/connectors/sentinelone/health         - Connector health probe
  GET  /api/v1/connectors/sentinelone/status         - Status alias of /health
  GET  /api/v1/connectors/sentinelone/sample         - Return embedded SentinelOne
                                                        sample threats (no DB writes)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/connectors/sentinelone",
    tags=["SentinelOne Connector"],
)


def _conn():
    from connectors.sentinelone_connector import get_sentinelone_connector
    return get_sentinelone_connector()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------
class IngestRequest(BaseModel):
    """Ingest a SentinelOne /threats dump.

    ``payload`` accepts:
      - the API canonical wrapper ``{"data": [Threat, ...], "pagination": {...}}``
      - a list of Threat dicts
      - a single Threat dict
    """
    org_id: str = Field(default="default", min_length=1, max_length=128)
    payload: Union[Dict[str, Any], List[Dict[str, Any]]] = Field(
        ...,
        description="SentinelOne /threats response: dict with 'data' list, list, or single Threat",
    )
    scan_id: Optional[str] = Field(default=None, max_length=128)


class IngestRawRequest(BaseModel):
    """Ingest a raw JSON-encoded dump (string body).

    Useful for clients that already have the raw API response and don't want
    to re-parse it client-side.
    """
    org_id: str = Field(default="default", min_length=1, max_length=128)
    raw_json: str = Field(..., min_length=1, max_length=10_485_760)  # 10 MB
    scan_id: Optional[str] = Field(default=None, max_length=128)


class SampleIngestRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=128)
    max_events: int = Field(default=10, ge=1, le=10)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@router.get("/health", dependencies=[Depends(api_key_auth)])
def health() -> Dict[str, Any]:
    try:
        conn = _conn()
        from connectors.sentinelone_connector import _S1_FALLBACK_THREATS
        return {
            "status": "ok",
            "service": "sentinelone-connector",
            "fallback_samples": len(_S1_FALLBACK_THREATS),
            "correlation_enabled": conn._correlation is not None,
        }
    except (ImportError, RuntimeError, OSError) as exc:
        _logger.exception("sentinelone connector health failed")
        raise HTTPException(status_code=503, detail=f"connector unavailable: {exc}") from exc


@router.get("/status", dependencies=[Depends(api_key_auth)])
def status() -> Dict[str, Any]:
    """Status alias of /health (Demo-001 contract)."""
    return health()


# ---------------------------------------------------------------------------
# Sample inspection (no DB writes)
# ---------------------------------------------------------------------------
@router.get("/sample", dependencies=[Depends(api_key_auth)])
def sample(
    limit: int = Query(default=10, ge=1, le=10),
) -> Dict[str, Any]:
    """Return the embedded SentinelOne fallback sample (no DB writes)."""
    from connectors.sentinelone_connector import _S1_FALLBACK_THREATS
    return {
        "service": "sentinelone-connector",
        "count": min(limit, len(_S1_FALLBACK_THREATS)),
        "data": _S1_FALLBACK_THREATS[:limit],
    }


# ---------------------------------------------------------------------------
# Ingest
# ---------------------------------------------------------------------------
@router.post("/ingest", dependencies=[Depends(api_key_auth)])
def ingest(req: IngestRequest) -> Dict[str, Any]:
    """Ingest a SentinelOne API /threats response payload."""
    try:
        return _conn().ingest_s1_dump(
            json_dump=req.payload,
            org_id=req.org_id,
            scan_id=req.scan_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (RuntimeError, OSError, TypeError) as exc:
        _logger.exception("sentinelone ingest failed")
        raise HTTPException(status_code=500, detail=f"ingest failed: {exc}") from exc


@router.post("/ingest/raw", dependencies=[Depends(api_key_auth)])
def ingest_raw(req: IngestRawRequest) -> Dict[str, Any]:
    """Ingest a raw JSON-encoded SentinelOne /threats dump (string body)."""
    try:
        return _conn().ingest_s1_dump(
            json_dump=req.raw_json,
            org_id=req.org_id,
            scan_id=req.scan_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (RuntimeError, OSError, TypeError) as exc:
        _logger.exception("sentinelone raw ingest failed")
        raise HTTPException(status_code=500, detail=f"ingest failed: {exc}") from exc


@router.post("/ingest/sample", dependencies=[Depends(api_key_auth)])
def ingest_sample(req: SampleIngestRequest) -> Dict[str, Any]:
    """Ingest the embedded SentinelOne fallback sample (offline demo)."""
    try:
        return _conn().ingest_fallback(org_id=req.org_id, max_events=req.max_events)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (RuntimeError, OSError, TypeError) as exc:
        _logger.exception("sentinelone sample ingest failed")
        raise HTTPException(status_code=500, detail=f"sample ingest failed: {exc}") from exc
