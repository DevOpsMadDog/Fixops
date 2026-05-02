"""Universal Ingest Router — ALDECI (GAP-034 + GAP-035).

Unified surface for registering heterogeneous source schemas, ingesting
records through JSONPath field-mappings, and forwarding events to
third-party SIEMs (Chronicle, Datadog, Splunk, QRadar, Elastic, Sentinel).

Prefix: /api/v1/ingest
Auth:   api_key_auth (all endpoints)

Routes:
  POST  /api/v1/ingest/source          register (or update) a source + mapping
  POST  /api/v1/ingest/record          apply mapping and persist a raw record
  GET   /api/v1/ingest/sources         list registered sources for an org
  POST  /api/v1/ingest/siem-forward    forward a normalized event via SIEM adapter
  GET   /api/v1/ingest/stats           ingestion counters + available adapters
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/ingest",
    tags=["Universal Ingest"],
)


# ---------------------------------------------------------------------------
# Lazy singletons (avoid import cycles at module load)
# ---------------------------------------------------------------------------

_pipeline_engine = None


def _get_pipeline():
    global _pipeline_engine
    if _pipeline_engine is None:
        from core.security_data_pipeline_engine import SecurityDataPipelineEngine

        _pipeline_engine = SecurityDataPipelineEngine()
    return _pipeline_engine


def _get_siem_adapters() -> Dict[str, type]:
    from core.siem_integration_engine import SIEM_ADAPTERS

    return SIEM_ADAPTERS


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class RegisterSourceRequest(BaseModel):
    org_id: str = Field(..., min_length=1)
    source_name: str = Field(..., min_length=1, max_length=200)
    schema_mapping: Dict[str, str] = Field(
        default_factory=dict,
        description="Dict of {target_field: source_jsonpath}",
    )
    enabled: bool = True


class IngestRecordRequest(BaseModel):
    org_id: str = Field(..., min_length=1)
    source_name: str = Field(..., min_length=1, max_length=200)
    raw_record: Dict[str, Any] = Field(default_factory=dict)


class SIEMForwardRequest(BaseModel):
    adapter: str = Field(..., min_length=1, max_length=50)
    event: Dict[str, Any] = Field(default_factory=dict)
    config: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/source", dependencies=[Depends(api_key_auth)], status_code=201)
def register_source(req: RegisterSourceRequest) -> Dict[str, Any]:
    """Register (or idempotently update) a universal-ingest source mapping."""
    try:
        return _get_pipeline().register_source(
            org_id=req.org_id,
            source_name=req.source_name,
            schema_mapping=req.schema_mapping,
            enabled=req.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        _logger.exception("register_source failed")
        raise HTTPException(status_code=500, detail=f"internal error: {exc}")


@router.post("/record", dependencies=[Depends(api_key_auth)], status_code=201)
def ingest_record(req: IngestRecordRequest) -> Dict[str, Any]:
    """Apply the source mapping to a raw record and persist the result."""
    try:
        return _get_pipeline().ingest_record(
            org_id=req.org_id,
            source_name=req.source_name,
            raw_record=req.raw_record,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        _logger.exception("ingest_record failed")
        raise HTTPException(status_code=500, detail=f"internal error: {exc}")


@router.get("/sources", dependencies=[Depends(api_key_auth)])
def list_sources(
    org_id: str = Query(..., min_length=1),
) -> Dict[str, Any]:
    """List all universal-ingest sources registered for an org."""
    try:
        items = _get_pipeline().list_sources(org_id)
        return {"org_id": org_id, "count": len(items), "sources": items}
    except Exception as exc:  # noqa: BLE001
        _logger.exception("list_sources failed")
        raise HTTPException(status_code=500, detail=f"internal error: {exc}")


@router.post("/siem-forward", dependencies=[Depends(api_key_auth)])
def siem_forward(req: SIEMForwardRequest) -> Dict[str, Any]:
    """Forward a normalized event to the named SIEM adapter (mocked HTTP)."""
    adapters = _get_siem_adapters()
    key = (req.adapter or "").strip().lower()
    cls = adapters.get(key)
    if cls is None:
        raise HTTPException(
            status_code=400,
            detail={
                "error": f"unknown adapter '{req.adapter}'",
                "available": sorted(adapters.keys()),
            },
        )
    try:
        instance = cls(req.config or {})
        result = instance.forward_event(req.event or {})
        return result
    except Exception as exc:  # noqa: BLE001
        _logger.exception("siem_forward failed")
        raise HTTPException(status_code=500, detail=f"forward failed: {exc}")


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def stats(
    org_id: str = Query(..., min_length=1),
) -> Dict[str, Any]:
    """Ingestion counters + available SIEM adapters for this org."""
    try:
        engine = _get_pipeline()
        sources = engine.list_sources(org_id)
        total_records = engine.count_records(org_id)
        per_source: List[Dict[str, Any]] = []
        for s in sources:
            per_source.append(
                {
                    "source_name": s["source_name"],
                    "enabled": s["enabled"],
                    "record_count": engine.count_records(org_id, s["source_name"]),
                }
            )
        adapters = _get_siem_adapters()
        return {
            "org_id": org_id,
            "total_sources": len(sources),
            "enabled_sources": sum(1 for s in sources if s["enabled"]),
            "total_records_ingested": total_records,
            "per_source": per_source,
            "available_siem_adapters": sorted(adapters.keys()),
        }
    except Exception as exc:  # noqa: BLE001
        _logger.exception("stats failed")
        raise HTTPException(status_code=500, detail=f"internal error: {exc}")
