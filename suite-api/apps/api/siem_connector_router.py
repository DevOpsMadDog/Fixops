"""SIEM Connector Router — universal multi-format SIEM ingest API.

Endpoints (all under /api/v1/connectors/siem):

  GET  /adapters                  — list supported adapter keys
  POST /detect                    — auto-detect format of a payload
  POST /ingest                    — parse + mirror to all 3 engines
  POST /tail                      — tail real log files on disk (incremental)
  POST /generate                  — generate fixture events (no ingest)
  POST /generate-and-ingest       — generate fixture events and ingest

Auth: api_key_auth injected via Depends at app mount.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from connectors import siem_connector
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

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


class TailRequest(BaseModel):
    org_id: str = Field("default", description="Tenant identifier", max_length=128)
    file_paths: List[str] = Field(
        ...,
        description="Absolute paths to log files to tail (e.g. /var/log/system.log).",
        max_length=20,
    )
    format: str = Field(
        "auto",
        description=(
            "Adapter key per file (auto picks json_lines for JSON-leading lines, "
            "syslog otherwise)."
        ),
    )
    max_bytes_per_file: int = Field(1_048_576, ge=1024, le=64 * 1_048_576)
    max_lines_per_file: int = Field(5000, ge=1, le=100_000)


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


@router.post("/tail")
def tail_logs(body: TailRequest) -> Dict[str, Any]:
    """Tail real log files on disk and ingest new bytes since last call.

    Designed for /var/log/system.log, ALDECI's own structlog JSON output,
    or any other newline-delimited log file. Per-file byte cursors persist
    in ``.aldeci/siem_tail_cursors.json`` so subsequent calls only ingest
    *new* content (real incremental log tailing, not re-ingest).

    Each file's content is auto-detected (JSON-leading → json_lines,
    else syslog), parsed by the matching adapter, and mirrored into the
    SIEM, correlation, and findings engines.
    """
    try:
        result = siem_connector.tail_log_files(
            org_id=body.org_id,
            file_paths=body.file_paths,
            fmt=body.format,
            max_bytes_per_file=body.max_bytes_per_file,
            max_lines_per_file=body.max_lines_per_file,
        )
        return {"status": "tailed", **result}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("siem_connector tail failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


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
