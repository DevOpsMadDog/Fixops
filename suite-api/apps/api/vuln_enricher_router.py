"""
Vulnerability Enrichment REST API — ALDECI.

Endpoints:
  POST /api/v1/vuln/enrich         -- Enrich a single raw finding
  POST /api/v1/vuln/enrich/batch   -- Enrich multiple findings (deduplicated CVE lookups)
  GET  /api/v1/vuln/cwe-mapping    -- Get CWE→CVE mapping for a given CWE ID

Security: Bearer token / API key required on all endpoints.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    from fastapi import Depends

    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "vuln_enricher_router: auth_deps not available, "
        "relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.vuln_enricher import EnrichedFinding, VulnerabilityEnricher

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/vuln",
    tags=["Vulnerability Enrichment"],
    dependencies=_AUTH_DEP,
)

# Module-level singleton — lightweight (no DB), safe to share across requests
_enricher: Optional[VulnerabilityEnricher] = None


def _get_enricher() -> VulnerabilityEnricher:
    global _enricher
    if _enricher is None:
        _enricher = VulnerabilityEnricher()
    return _enricher


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class EnrichRequest(BaseModel):
    """Request body for enriching a single finding."""

    finding: Dict[str, Any] = Field(
        ...,
        description=(
            "Raw scanner finding dict. Recognized fields: cwe_id, cve_id, severity, "
            "cvss, remediation. All other fields are preserved in original_finding."
        ),
    )


class BatchEnrichRequest(BaseModel):
    """Request body for batch enrichment."""

    findings: List[Dict[str, Any]] = Field(
        ..., min_length=1, max_length=500, description="List of raw scanner findings (max 500)"
    )


class CWEMappingResponse(BaseModel):
    """Response for CWE→CVE mapping lookup."""

    cwe_id: str = Field(..., description="Normalized CWE ID (e.g. CWE-89)")
    cves: List[str] = Field(..., description="Known CVE IDs associated with this CWE")
    count: int = Field(..., description="Number of matched CVEs")


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.post(
    "/enrich",
    response_model=EnrichedFinding,
    summary="Enrich a single raw scanner finding with CVE intel, EPSS, and KEV status",
)
def enrich_finding(body: EnrichRequest) -> EnrichedFinding:
    """
    Enrich a raw SAST/scanner finding with:

    - **CVE mapping**: CWE → known CVEs (top-25 CWE hardcoded + finding CVE fields)
    - **EPSS scores**: Exploitation probability per CVE (FIRST.org API)
    - **KEV status**: Whether any CVE appears in CISA Known Exploited Vulnerabilities
    - **Fix guidance**: CWE-specific remediation guidance + CVE references
    - **Composite risk**: `(CVSS/10 * 40) + (EPSS * 35) + (in_kev * 25)` → 0–100
    """
    try:
        enricher = _get_enricher()
        return enricher.enrich_finding(body.finding)
    except Exception as exc:
        logger.exception("vuln_enrich_error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to enrich finding") from exc


@router.post(
    "/enrich/batch",
    response_model=List[EnrichedFinding],
    summary="Enrich multiple scanner findings with shared CVE deduplication",
)
def enrich_batch(body: BatchEnrichRequest) -> List[EnrichedFinding]:
    """
    Enrich a batch of raw findings.

    CVE lookups are deduplicated across the entire batch — the EPSS API is
    called once per unique CVE regardless of how many findings reference it.
    Supports up to 500 findings per request.
    """
    try:
        enricher = _get_enricher()
        return enricher.enrich_batch(body.findings)
    except Exception as exc:
        logger.exception("vuln_enrich_batch_error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to enrich batch") from exc


@router.get(
    "/cwe-mapping",
    response_model=CWEMappingResponse,
    summary="Get known CVEs for a CWE ID from the hardcoded top-25 CWE cache",
)
def get_cwe_mapping(
    cwe_id: str = Query(
        ...,
        description="CWE ID — accepts 'CWE-89', 'cwe-89', or bare '89'",
        examples={"bare": {"value": "89"}, "prefixed": {"value": "CWE-89"}},
    ),
) -> CWEMappingResponse:
    """
    Return known CVE IDs associated with a CWE from the local hardcoded cache.

    Covers all MITRE CWE Top-25 weaknesses plus common OWASP entries.
    Returns an empty list for CWEs not in the cache (not an error).
    """
    try:
        enricher = _get_enricher()
        cves = enricher.get_cwe_to_cve_mapping(cwe_id)
        normalized = enricher._normalize_cwe(cwe_id)
        return CWEMappingResponse(cwe_id=normalized, cves=cves, count=len(cves))
    except Exception as exc:
        logger.exception("cwe_mapping_error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to fetch CWE mapping") from exc
