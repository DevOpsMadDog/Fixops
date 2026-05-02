"""Microsoft Defender XDR (Sentinel-XDR) Connector Router.

Prefix: /api/v1/connectors/defender-xdr
Auth:   api_key_auth dependency

Routes:
  GET  /api/v1/connectors/defender-xdr/health   — connector health probe
  GET  /api/v1/connectors/defender-xdr/status   — alias of /health (Demo-001 contract)
  POST /api/v1/connectors/defender-xdr/ingest   — ingest a Defender XDR JSON dump
  POST /api/v1/connectors/defender-xdr/ingest/alert  — ingest a single alert
  POST /api/v1/connectors/defender-xdr/parse    — parse-only (no DB write)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/connectors/defender-xdr",
    tags=["Defender XDR Connector"],
)


def _conn():
    from connectors.defender_xdr_connector import get_defender_xdr_connector
    return get_defender_xdr_connector()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------
class IngestDumpRequest(BaseModel):
    org_id:         str = Field(default="default", min_length=1, max_length=128)
    dump_file:      Optional[str] = Field(default=None, max_length=2048)
    max_alerts:     int = Field(default=50, ge=1, le=1000)
    force_fallback: bool = Field(default=False)


class IngestAlertRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=128)
    alert:  Dict[str, Any] = Field(..., description="Raw Defender XDR alert JSON object")


class ParseAlertsRequest(BaseModel):
    alerts: List[Dict[str, Any]] = Field(..., min_length=1, max_length=1000)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@router.get("/health", dependencies=[Depends(api_key_auth)])
def health() -> Dict[str, Any]:
    """Health probe for the Defender XDR connector."""
    try:
        from connectors.defender_xdr_connector import (
            _DEFENDER_CATEGORY_MAP,
            _DEFENDER_FALLBACK_ALERTS,
            _DEFENDER_SEVERITY_MAP,
        )
        # Touch the singleton to verify wiring
        _conn()
        return {
            "status":               "ok",
            "service":              "defender-xdr-connector",
            "source_tool":          "defender_xdr",
            "fallback_alert_count": len(_DEFENDER_FALLBACK_ALERTS),
            "severity_map_size":    len(_DEFENDER_SEVERITY_MAP),
            "category_map_size":    len(_DEFENDER_CATEGORY_MAP),
        }
    except (ImportError, RuntimeError, OSError) as exc:
        _logger.exception("defender-xdr connector health failed")
        raise HTTPException(status_code=503, detail=f"connector unavailable: {exc}") from exc


@router.get("/status", dependencies=[Depends(api_key_auth)])
def status() -> Dict[str, Any]:
    """Status alias of /health (Demo-001 contract)."""
    return health()


@router.post("/ingest", dependencies=[Depends(api_key_auth)])
def ingest(req: IngestDumpRequest) -> Dict[str, Any]:
    """Ingest a Defender XDR JSON dump file (or fallback samples)."""
    try:
        return _conn().ingest_defender_dump(
            org_id=req.org_id,
            dump_file=req.dump_file,
            max_alerts=req.max_alerts,
            force_fallback=req.force_fallback,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (RuntimeError, OSError, TypeError) as exc:
        _logger.exception("defender-xdr ingest failed")
        raise HTTPException(status_code=500, detail=f"ingest failed: {exc}") from exc


@router.post("/ingest/alert", dependencies=[Depends(api_key_auth)])
def ingest_alert(req: IngestAlertRequest) -> Dict[str, Any]:
    """Ingest a single Defender XDR alert (JSON object) into findings."""
    try:
        rec = _conn().ingest_alert(org_id=req.org_id, alert=req.alert)
        if not rec:
            raise HTTPException(status_code=500, detail="finding was not recorded")
        return {"status": "ok", "finding": rec}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (RuntimeError, OSError, TypeError, KeyError) as exc:
        _logger.exception("defender-xdr single alert ingest failed")
        raise HTTPException(status_code=500, detail=f"ingest failed: {exc}") from exc


@router.post("/parse", dependencies=[Depends(api_key_auth)])
def parse(req: ParseAlertsRequest) -> Dict[str, Any]:
    """Parse-only endpoint — normalize alerts but do NOT write to DB.

    Useful for quick sanity-check of upstream KQL output before ingesting.
    """
    try:
        out = _conn().parse_alerts(req.alerts)
        return {
            "input_count":   len(req.alerts),
            "parsed_count":  len(out),
            "skipped_count": len(req.alerts) - len(out),
            "alerts":        out,
        }
    except (RuntimeError, OSError, TypeError) as exc:
        _logger.exception("defender-xdr parse failed")
        raise HTTPException(status_code=500, detail=f"parse failed: {exc}") from exc
