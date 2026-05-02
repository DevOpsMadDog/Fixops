"""CrowdStrike Falcon Connector Router.

Exposes ingest endpoints for the real Falcon Detection.Created format
parser implemented in ``connectors.crowdstrike_falcon_connector``. Closes
1 of 11 substitute-only gaps from the 2026-04-26 commercial-vendor audit
(`raw/competitive/gap-matrix-2026-04-26.md`).

Prefix: /api/v1/connectors/falcon
Auth:   api_key_auth dependency

Routes:
  GET  /api/v1/connectors/falcon/health             — connector health
  GET  /api/v1/connectors/falcon/status             — alias of /health (Demo-001)
  POST /api/v1/connectors/falcon/ingest             — ingest a Falcon JSON dump
  POST /api/v1/connectors/falcon/ingest/sample      — ingest the embedded 10-event sample
  GET  /api/v1/connectors/falcon/sample             — return the embedded sample (no DB writes)
  GET  /api/v1/connectors/falcon/mappings/severity  — show the Falcon severity → ALDECI map
  GET  /api/v1/connectors/falcon/mappings/technique — show the technique → MITRE map (truncated)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/connectors/falcon",
    tags=["CrowdStrike Falcon Connector"],
)


def _conn():
    from connectors.crowdstrike_falcon_connector import get_falcon_connector
    return get_falcon_connector()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------
class FalconIngestRequest(BaseModel):
    """Ingest a Falcon Detection.Created dump.

    Exactly one of ``events`` (a list of detection dicts) or ``json_text``
    (raw JSON / NDJSON string) must be supplied. ``org_id`` selects the
    target ALDECI tenant for isolation.
    """

    org_id: str = Field(default="default", min_length=1, max_length=128)
    events: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="List of Falcon Detection.Created event dicts.",
    )
    json_text: Optional[str] = Field(
        default=None,
        description="Raw JSON string (array, single object, or NDJSON).",
        max_length=10 * 1024 * 1024,  # 10 MB cap to prevent memory abuse
    )
    max_events: Optional[int] = Field(
        default=None,
        ge=0,
        le=100_000,
        description="Optional cap on number of events to process.",
    )


class SampleIngestRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=128)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@router.get("/health", dependencies=[Depends(api_key_auth)])
def health() -> Dict[str, Any]:
    """Health probe — returns the connector wiring state."""
    try:
        from connectors.crowdstrike_falcon_connector import (
            _FALCON_TACTIC_TO_MITRE,
            _FALCON_TECHNIQUE_TO_MITRE,
            FALCON_SAMPLE_DETECTIONS,
        )
        conn = _conn()
        return {
            "status":              "ok",
            "service":             "crowdstrike-falcon-connector",
            "vendor":              "CrowdStrike",
            "product":             "Falcon",
            "format":              "Detection.Created (Streaming API + Insight export)",
            "edr_engine_wired":    conn._edr is not None,
            "findings_engine_wired": conn._findings is not None,
            "correlation_engine_wired": conn._correlation is not None,
            "sample_size":         len(FALCON_SAMPLE_DETECTIONS),
            "technique_mappings":  len(_FALCON_TECHNIQUE_TO_MITRE),
            "tactic_mappings":     len(_FALCON_TACTIC_TO_MITRE),
        }
    except (ImportError, RuntimeError, OSError) as exc:
        _logger.exception("falcon connector health failed")
        raise HTTPException(status_code=503, detail=f"connector unavailable: {exc}") from exc


@router.get("/status", dependencies=[Depends(api_key_auth)])
def status() -> Dict[str, Any]:
    """Alias of /health (Demo-001 status/health contract)."""
    return health()


@router.post("/ingest", dependencies=[Depends(api_key_auth)])
def ingest(req: FalconIngestRequest) -> Dict[str, Any]:
    """Ingest a Falcon Detection.Created JSON dump.

    Provide either ``events`` (parsed list) or ``json_text`` (raw text).
    Returns counts (ingested/failed/findings_recorded/edr_events/
    correlation_events) and the list of detection_ids absorbed.
    """
    if not req.events and not req.json_text:
        raise HTTPException(
            status_code=400,
            detail="Either 'events' (list) or 'json_text' (string) must be provided.",
        )
    if req.events and req.json_text:
        raise HTTPException(
            status_code=400,
            detail="Provide only one of 'events' or 'json_text', not both.",
        )
    payload: Union[List[Dict[str, Any]], str] = req.events if req.events is not None else req.json_text  # type: ignore[assignment]
    try:
        return _conn().ingest_falcon_dump(
            json_dump=payload,
            org_id=req.org_id,
            max_events=req.max_events,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (RuntimeError, OSError) as exc:
        _logger.exception("falcon ingest failed")
        raise HTTPException(status_code=500, detail=f"ingest failed: {exc}") from exc


@router.post("/ingest/sample", dependencies=[Depends(api_key_auth)])
def ingest_sample(req: SampleIngestRequest) -> Dict[str, Any]:
    """Ingest the embedded 10-detection sample for an org. Used by demos
    and the integration smoke test.
    """
    try:
        return _conn().ingest_sample(org_id=req.org_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (RuntimeError, OSError) as exc:
        _logger.exception("falcon sample ingest failed")
        raise HTTPException(status_code=500, detail=f"ingest failed: {exc}") from exc


@router.get("/sample", dependencies=[Depends(api_key_auth)])
def get_sample() -> Dict[str, Any]:
    """Return the embedded 10-detection sample WITHOUT writing to any DB.

    Useful for clients that want to inspect the canonical Falcon
    Detection.Created shape this connector accepts.
    """
    from connectors.crowdstrike_falcon_connector import FALCON_SAMPLE_DETECTIONS
    return {"count": len(FALCON_SAMPLE_DETECTIONS), "events": FALCON_SAMPLE_DETECTIONS}


@router.get("/mappings/severity", dependencies=[Depends(api_key_auth)])
def get_severity_mappings() -> Dict[str, Any]:
    """Return the Falcon score (1-100) → ALDECI severity bucket map."""
    return {
        "scale": "Falcon Severity Score (1-100)",
        "buckets": [
            {"score_range": "90-100", "aldeci_severity": "critical"},
            {"score_range": "70-89",  "aldeci_severity": "high"},
            {"score_range": "50-69",  "aldeci_severity": "medium"},
            {"score_range": "30-49",  "aldeci_severity": "low"},
            {"score_range": "1-29",   "aldeci_severity": "informational"},
        ],
    }


@router.get("/mappings/technique", dependencies=[Depends(api_key_auth)])
def get_technique_mappings() -> Dict[str, Any]:
    """Return the Falcon technique label → MITRE T-code map."""
    from connectors.crowdstrike_falcon_connector import (
        _FALCON_TACTIC_TO_MITRE,
        _FALCON_TECHNIQUE_TO_MITRE,
    )
    return {
        "technique_count": len(_FALCON_TECHNIQUE_TO_MITRE),
        "tactic_count":    len(_FALCON_TACTIC_TO_MITRE),
        "techniques":      _FALCON_TECHNIQUE_TO_MITRE,
        "tactics":         _FALCON_TACTIC_TO_MITRE,
    }
