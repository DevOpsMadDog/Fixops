"""ALDECI Commercial DAST Connector API Routers.

Exposes the three commercial DAST format parsers (Veracode DAST, Invicti /
Netsparker, Acunetix) as REST endpoints. Each ingests a vendor JSON dump
and mirrors findings into ``SecurityFindingsEngine`` with a vendor-tagged
``source_tool``.

Prefixes:
  /api/v1/connectors/veracode-dast
  /api/v1/connectors/invicti
  /api/v1/connectors/acunetix

Auth: api_key_auth dependency (mounted in app.py with scope guards too).

Routes per vendor:
  GET   /status                — connector availability + sample size
  POST  /ingest                — ingest a JSON dump into SecurityFindingsEngine
  GET   /sample                — return the embedded sample (5+ records)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from connectors.commercial_dast_parsers import (
    ACUNETIX_SAMPLE,
    INVICTI_SAMPLE,
    VERACODE_DAST_SAMPLE,
    ingest_acunetix_dump,
    ingest_invicti_dump,
    ingest_veracode_dast_dump,
)
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class IngestDumpRequest(BaseModel):
    """Request body for ingesting a vendor JSON dump."""

    org_id: str = Field("default", description="Organization id for ingestion")
    scan_id: Optional[str] = Field(None, description="Scan id to bind for lifecycle reconciliation")
    dump: Optional[Dict[str, Any]] = Field(
        None,
        description="Raw vendor JSON dump. If null/empty and use_fallback=true, the embedded sample is used.",
    )
    use_fallback_if_empty: bool = Field(
        True,
        description="If true and dump is empty, ingest from embedded sample (air-gap mode)",
    )


class IngestDumpResponse(BaseModel):
    """Response describing what was ingested."""

    vendor: str
    source_tool: str
    org_id: str
    records_seen: int
    records_ingested: int
    used_fallback: bool
    errors: List[str] = []
    sample_findings: List[Dict[str, Any]] = []


# ---------------------------------------------------------------------------
# Veracode DAST router
# ---------------------------------------------------------------------------

veracode_dast_router = APIRouter(
    prefix="/api/v1/connectors/veracode-dast",
    tags=["connectors", "dast", "veracode"],
    dependencies=[Depends(api_key_auth)],
)


@veracode_dast_router.get("/status")
def veracode_status() -> Dict[str, Any]:
    flaws = VERACODE_DAST_SAMPLE.get("_embed", {}).get("flaws", [])
    return {
        "connector": "veracode-dast",
        "vendor": "Veracode",
        "source_tool": "dast_via_veracode",
        "format": "Veracode REST findings export (flaws[])",
        "embedded_sample_count": len(flaws),
        "fallback_available": True,
    }


@veracode_dast_router.get("/sample")
def veracode_sample() -> Dict[str, Any]:
    """Return the embedded Veracode DAST sample (5+ records)."""
    return VERACODE_DAST_SAMPLE


@veracode_dast_router.post("/ingest", response_model=IngestDumpResponse)
def veracode_ingest(req: IngestDumpRequest) -> IngestDumpResponse:
    if not req.org_id or not req.org_id.strip():
        raise HTTPException(status_code=422, detail="org_id required")
    try:
        result = ingest_veracode_dast_dump(
            dump=req.dump,
            org_id=req.org_id,
            scan_id=req.scan_id,
            use_fallback_if_empty=req.use_fallback_if_empty,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return IngestDumpResponse(
        vendor=result.vendor,
        source_tool=result.source_tool,
        org_id=result.org_id,
        records_seen=result.records_seen,
        records_ingested=result.records_ingested,
        used_fallback=result.used_fallback,
        errors=result.errors,
        sample_findings=[
            {k: f.get(k) for k in ("id", "title", "severity", "asset_id",
                                   "source_tool", "occurrence_count")}
            for f in result.findings[:10]
        ],
    )


# ---------------------------------------------------------------------------
# Invicti / Netsparker router
# ---------------------------------------------------------------------------

invicti_router = APIRouter(
    prefix="/api/v1/connectors/invicti",
    tags=["connectors", "dast", "invicti"],
    dependencies=[Depends(api_key_auth)],
)


@invicti_router.get("/status")
def invicti_status() -> Dict[str, Any]:
    vulns = INVICTI_SAMPLE.get("Vulnerabilities", [])
    return {
        "connector": "invicti",
        "vendor": "Invicti / Netsparker",
        "source_tool": "dast_via_invicti",
        "format": "Invicti REST scan result (Vulnerabilities[])",
        "embedded_sample_count": len(vulns),
        "fallback_available": True,
    }


@invicti_router.get("/sample")
def invicti_sample() -> Dict[str, Any]:
    return INVICTI_SAMPLE


@invicti_router.post("/ingest", response_model=IngestDumpResponse)
def invicti_ingest(req: IngestDumpRequest) -> IngestDumpResponse:
    if not req.org_id or not req.org_id.strip():
        raise HTTPException(status_code=422, detail="org_id required")
    try:
        result = ingest_invicti_dump(
            dump=req.dump,
            org_id=req.org_id,
            scan_id=req.scan_id,
            use_fallback_if_empty=req.use_fallback_if_empty,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return IngestDumpResponse(
        vendor=result.vendor,
        source_tool=result.source_tool,
        org_id=result.org_id,
        records_seen=result.records_seen,
        records_ingested=result.records_ingested,
        used_fallback=result.used_fallback,
        errors=result.errors,
        sample_findings=[
            {k: f.get(k) for k in ("id", "title", "severity", "asset_id",
                                   "source_tool", "occurrence_count")}
            for f in result.findings[:10]
        ],
    )


# ---------------------------------------------------------------------------
# Acunetix router
# ---------------------------------------------------------------------------

acunetix_router = APIRouter(
    prefix="/api/v1/connectors/acunetix",
    tags=["connectors", "dast", "acunetix"],
    dependencies=[Depends(api_key_auth)],
)


@acunetix_router.get("/status")
def acunetix_status() -> Dict[str, Any]:
    vulns = ACUNETIX_SAMPLE.get("vulnerabilities", [])
    return {
        "connector": "acunetix",
        "vendor": "Acunetix Premium",
        "source_tool": "dast_via_acunetix",
        "format": "Acunetix REST vulnerability export (vulnerabilities[])",
        "embedded_sample_count": len(vulns),
        "fallback_available": True,
    }


@acunetix_router.get("/sample")
def acunetix_sample() -> Dict[str, Any]:
    return ACUNETIX_SAMPLE


@acunetix_router.post("/ingest", response_model=IngestDumpResponse)
def acunetix_ingest(req: IngestDumpRequest) -> IngestDumpResponse:
    if not req.org_id or not req.org_id.strip():
        raise HTTPException(status_code=422, detail="org_id required")
    try:
        result = ingest_acunetix_dump(
            dump=req.dump,
            org_id=req.org_id,
            scan_id=req.scan_id,
            use_fallback_if_empty=req.use_fallback_if_empty,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return IngestDumpResponse(
        vendor=result.vendor,
        source_tool=result.source_tool,
        org_id=result.org_id,
        records_seen=result.records_seen,
        records_ingested=result.records_ingested,
        used_fallback=result.used_fallback,
        errors=result.errors,
        sample_findings=[
            {k: f.get(k) for k in ("id", "title", "severity", "asset_id",
                                   "source_tool", "occurrence_count")}
            for f in result.findings[:10]
        ],
    )


__all__ = ["veracode_dast_router", "invicti_router", "acunetix_router"]
