"""SIEM Connector Router — universal multi-format SIEM ingest API.

Endpoints (all under /api/v1/connectors/siem):

  GET  /adapters                  — list supported adapter keys
  POST /detect                    — auto-detect format of a payload
  POST /ingest                    — parse + mirror to all 3 engines
  POST /generate                  — generate fixture events (no ingest)
  POST /generate-and-ingest       — generate fixture events and ingest

Auth: api_key_auth injected via Depends at app mount.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from connectors import siem_connector

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/connectors/siem", tags=["siem-connector"])


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class IngestRequest(BaseModel):
    org_id: str = Field("default", description="Tenant identifier")
    payload: Any = Field(..., description="Raw SIEM payload (str, dict, or list)")
    format: str = Field(
        "auto",
        description=(
            "Adapter key — one of: splunk_hec | datadog | sentinel_kql | "
            "elk_bulk | wazuh_alert | suricata_eve | cef | syslog | "
            "json_lines | auto"
        ),
    )
    source_id: Optional[str] = Field(None, description="Optional SIEM source ID")


class DetectRequest(BaseModel):
    payload: Any = Field(..., description="Raw payload to detect format of")


class GenerateRequest(BaseModel):
    tenants: int = Field(15, ge=1, le=100, description="Number of tenants to generate for")
    events_per_tenant: int = Field(14, ge=1, le=100, description="Events per tenant (10-20 typical)")
    seed: int = Field(1337, description="RNG seed for deterministic output")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/adapters")
def list_adapters() -> Dict[str, Any]:
    """List all supported SIEM adapter keys."""
    adapters = siem_connector.list_adapters()
    return {
        "adapters": adapters,
        "total": len(adapters),
        "aliases": {
            "splunk_hec": "splunk",
            "sentinel_kql": "sentinel",
            "elk_bulk": "elastic",
            "wazuh_alert": "wazuh",
            "suricata_eve": "suricata",
            "cef": "qradar",
        },
    }


@router.post("/detect")
def detect_format(body: DetectRequest) -> Dict[str, Any]:
    """Auto-detect the SIEM format of a payload."""
    fmt = siem_connector.detect_format(body.payload)
    return {"format": fmt}


@router.post("/ingest")
def ingest(body: IngestRequest) -> Dict[str, Any]:
    """Parse a SIEM payload and mirror to SIEM, correlation, and findings engines.

    Accepts:
    - Splunk HEC envelope (single or NDJSON batch)
    - Datadog Logs API JSON
    - Microsoft Sentinel KQL JSON result
    - Elasticsearch _bulk NDJSON
    - Wazuh alerts.json record(s)
    - Suricata eve.json record(s)
    - CEF lines (used by QRadar, ArcSight)
    - RFC 3164/5424 syslog lines
    - Generic JSON-Lines

    With format=auto (default), the adapter is auto-detected.
    """
    try:
        result = siem_connector.ingest(
            body.org_id,
            body.payload,
            fmt=body.format,
            source_id=body.source_id,
        )
        return {"status": "ingested", **result}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("siem_connector ingest failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/generate")
def generate(body: GenerateRequest) -> Dict[str, Any]:
    """Generate realistic SIEM fixture events without ingesting them.

    Returns ``tenants * events_per_tenant`` synthetic SIEM payloads spanning
    Splunk HEC, Datadog, Sentinel KQL, ELK, Wazuh, CEF, syslog, Suricata.
    Useful for connector smoke testing without DB writes.
    """
    triples = siem_connector.generate_events(
        tenants=body.tenants,
        events_per_tenant=body.events_per_tenant,
        seed=body.seed,
    )
    by_format: Dict[str, int] = {}
    by_tenant: Dict[str, int] = {}
    for tenant, fmt, _ in triples:
        by_format[fmt] = by_format.get(fmt, 0) + 1
        by_tenant[tenant] = by_tenant.get(tenant, 0) + 1
    return {
        "total": len(triples),
        "tenants": body.tenants,
        "events_per_tenant": body.events_per_tenant,
        "by_format": by_format,
        "by_tenant": by_tenant,
        "sample": [
            {"tenant": t, "format": f, "payload": p}
            for t, f, p in triples[:3]
        ],
    }


@router.post("/generate-and-ingest")
def generate_and_ingest(body: GenerateRequest) -> Dict[str, Any]:
    """Generate fixture events and ingest them into all three engines.

    Used by E2E pipeline tests to seed realistic, multi-tenant, multi-format
    SIEM data. Returns per-format and per-tenant counts plus aggregate totals.
    """
    try:
        result = siem_connector.generate_and_ingest(
            tenants=body.tenants,
            events_per_tenant=body.events_per_tenant,
            seed=body.seed,
        )
        return {"status": "ingested", **result}
    except Exception as exc:  # noqa: BLE001
        logger.exception("siem_connector generate_and_ingest failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
