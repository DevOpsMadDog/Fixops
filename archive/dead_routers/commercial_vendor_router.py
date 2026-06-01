"""ALDECI Commercial Vendor Connector Router.

Exposes parsers for four commercial security vendors that ALDECI previously
only had stubbed/substitute integrations for:

  * Lacework            — POST /api/v1/connectors/lacework/ingest
  * Sysdig Secure       — POST /api/v1/connectors/sysdig/ingest
  * Recorded Future     — POST /api/v1/connectors/recorded-future/ingest
  * Mandiant Threat Intel — POST /api/v1/connectors/mandiant/ingest

Each `/ingest` endpoint accepts the vendor's native JSON dump shape (or omits
``dump`` entirely to ingest the deterministic embedded sample). Findings flow
to ``SecurityFindingsEngine``; IOCs flow to ``ThreatIntelFusionEngine``.

All routes auth-gated via ``api_key_auth`` dependency.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)


# =============================================================================
# Single router with prefix /api/v1/connectors — sub-paths per vendor
# =============================================================================

router = APIRouter(
    prefix="/api/v1/connectors",
    tags=["connectors", "commercial-vendors"],
    dependencies=[Depends(api_key_auth)],
)


# ---- lazy connector accessor -----------------------------------------------

def _connector():
    from connectors.commercial_vendor_parsers import get_default_connector
    return get_default_connector()


# ---- request models ---------------------------------------------------------

class IngestRequest(BaseModel):
    """Common ingest body — vendor-native JSON dump under 'dump' key.

    Pass ``dump=None`` (or omit) to ingest the embedded sample dataset.
    """
    org_id: str = Field("default",
                        description="Organization id for ingestion")
    dump: Optional[Dict[str, Any]] = Field(
        None,
        description="Vendor-native JSON export. Omit to use embedded sample.",
    )


# =============================================================================
# Lacework
# =============================================================================

@router.post("/lacework/ingest")
def lacework_ingest(body: IngestRequest) -> Dict[str, Any]:
    """Ingest Lacework Compliance Event JSON dump.

    Schema (per record):
      ``host``, ``account``, ``event_type``, ``severity``, ``rule_id``,
      ``title``, ``description``, ``first_seen``
    """
    return _connector().ingest_lacework_dump(
        org_id=body.org_id, dump=body.dump,
    ).to_dict()


@router.get("/lacework/sample")
def lacework_sample() -> Dict[str, Any]:
    """Return the embedded Lacework sample dataset."""
    from connectors.commercial_vendor_parsers import LACEWORK_SAMPLE
    return {"vendor": "lacework", "sample": LACEWORK_SAMPLE}


# =============================================================================
# Sysdig Secure
# =============================================================================

@router.post("/sysdig/ingest")
def sysdig_ingest(body: IngestRequest) -> Dict[str, Any]:
    """Ingest Sysdig Secure runtime alert JSON dump.

    Schema (per alert):
      ``id``, ``rule``, ``severity`` (1-7), ``container_name``,
      ``container_id``, ``host_id``, ``policy``, ``description``, ``timestamp``
    """
    return _connector().ingest_sysdig_dump(
        org_id=body.org_id, dump=body.dump,
    ).to_dict()


@router.get("/sysdig/sample")
def sysdig_sample() -> Dict[str, Any]:
    from connectors.commercial_vendor_parsers import SYSDIG_SAMPLE
    return {"vendor": "sysdig", "sample": SYSDIG_SAMPLE}


# =============================================================================
# Recorded Future
# =============================================================================

@router.post("/recorded-future/ingest")
def recorded_future_ingest(body: IngestRequest) -> Dict[str, Any]:
    """Ingest Recorded Future entity export JSON.

    Schema (per result):
      ``entity.type``, ``entity.name``, ``risk.score`` (0-100), ``risk.level``,
      ``evidenceDetails`` (list of ``{rule, evidenceString}``)
    """
    return _connector().ingest_recorded_future_dump(
        org_id=body.org_id, dump=body.dump,
    ).to_dict()


@router.get("/recorded-future/sample")
def recorded_future_sample() -> Dict[str, Any]:
    from connectors.commercial_vendor_parsers import RECORDED_FUTURE_SAMPLE
    return {"vendor": "recorded_future", "sample": RECORDED_FUTURE_SAMPLE}


# =============================================================================
# Mandiant Threat Intelligence
# =============================================================================

@router.post("/mandiant/ingest")
def mandiant_ingest(body: IngestRequest) -> Dict[str, Any]:
    """Ingest Mandiant Threat Intelligence indicator export.

    Schema (per indicator):
      ``id``, ``indicator_value``, ``type`` (ipv4|fqdn|sha256|md5|url|email),
      ``severity``, ``confidence`` (0-100), ``attribution.actor``,
      ``attribution.motivations``, ``description``, ``first_seen``, ``last_seen``
    """
    return _connector().ingest_mandiant_dump(
        org_id=body.org_id, dump=body.dump,
    ).to_dict()


@router.get("/mandiant/sample")
def mandiant_sample() -> Dict[str, Any]:
    from connectors.commercial_vendor_parsers import MANDIANT_SAMPLE
    return {"vendor": "mandiant", "sample": MANDIANT_SAMPLE}


# =============================================================================
# Status
# =============================================================================

@router.get("/commercial-vendors/status")
def commercial_vendors_status() -> Dict[str, Any]:
    """Report which commercial-vendor parsers are wired."""
    return {
        "vendors": ["lacework", "sysdig", "recorded_future", "mandiant"],
        "endpoints": {
            "lacework":         "POST /api/v1/connectors/lacework/ingest",
            "sysdig":           "POST /api/v1/connectors/sysdig/ingest",
            "recorded_future":  "POST /api/v1/connectors/recorded-future/ingest",
            "mandiant":         "POST /api/v1/connectors/mandiant/ingest",
        },
        "mirrors": {
            "lacework":         ["security_findings_engine"],
            "sysdig":           ["security_findings_engine"],
            "recorded_future":  ["security_findings_engine",
                                 "threat_intel_fusion_engine"],
            "mandiant":         ["security_findings_engine",
                                 "threat_intel_fusion_engine"],
        },
        "closes_substitute_gaps": 4,
    }


__all__ = ["router"]


@router.get("/", summary="Connectors index", tags=["connectors"])
async def connectors_index(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return list of available commercial vendor connectors."""
    vendors = ["lacework", "sysdig", "recorded_future", "mandiant"]
    items = [
        {
            "vendor": v,
            "ingest_endpoint": f"POST /api/v1/connectors/{v.replace('_', '-')}/ingest",
            "sample_endpoint": f"GET /api/v1/connectors/{v.replace('_', '-')}/sample",
        }
        for v in vendors
    ]
    return {"router": "connectors", "org_id": org_id, "items": items, "count": len(items)}
