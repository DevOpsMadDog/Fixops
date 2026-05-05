"""Vulnerability Intelligence Router — ALDECI.

Prefix: /api/v1/vuln-intel
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/vuln-intel/cves                          add_cve
  GET    /api/v1/vuln-intel/cves                          list_cves
  GET    /api/v1/vuln-intel/cves/{cve_id}                 get_cve
  PATCH  /api/v1/vuln-intel/cves/{cve_id}/status          update_cve_status
  POST   /api/v1/vuln-intel/advisories                    add_advisory
  GET    /api/v1/vuln-intel/advisories                    list_advisories
  POST   /api/v1/vuln-intel/advisories/{id}/apply         apply_advisory
  POST   /api/v1/vuln-intel/subscriptions                 add_subscription
  GET    /api/v1/vuln-intel/subscriptions                 list_subscriptions
  GET    /api/v1/vuln-intel/stats                         get_intel_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/vuln-intel",
    tags=["Vulnerability Intelligence"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.vuln_intelligence_engine import VulnIntelligenceEngine
        _engine = VulnIntelligenceEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CVECreate(BaseModel):
    cve_id: str
    title: str = ""
    description: str = ""
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    cvss_vector: str = ""
    epss_score: float = Field(default=0.0, ge=0.0, le=1.0)
    kev_listed: bool = False
    kev_added_date: Optional[str] = None
    severity: str = "medium"
    affected_products: List[Any] = []
    exploit_available: bool = False
    exploit_type: Optional[str] = None
    patch_available: bool = False
    patch_url: str = ""
    references: List[str] = []
    threat_actors_using: List[str] = []
    affected_org_assets: List[str] = []
    status: str = "new"


class CVEStatusUpdate(BaseModel):
    status: str


class AdvisoryCreate(BaseModel):
    advisory_id: str = ""
    vendor: str
    product: str = ""
    severity: str = "medium"
    advisory_url: str = ""
    cves_covered: List[str] = []
    patch_version: str = ""
    release_date: str = ""
    status: str = "new"


class SubscriptionCreate(BaseModel):
    subscription_type: str = "vendor"
    subscription_value: str
    notify_severity_min: str = "high"


# ---------------------------------------------------------------------------
# CVE routes
# ---------------------------------------------------------------------------

@router.post("/cves", dependencies=[Depends(api_key_auth)], status_code=201)
def add_cve(body: CVECreate, org_id: str = Query(default="default")):
    """Add or update CVE intelligence (upserts on org_id + cve_id)."""
    try:
        return _get_engine().add_cve(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/cves", dependencies=[Depends(api_key_auth)])
def list_cves(
     org_id: str = Query(default="default"),
    severity: Optional[str] = Query(None),
    kev_listed: Optional[bool] = Query(None),
    exploit_available: Optional[bool] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(default=50, ge=1, le=500),
):
    """List CVEs with optional filters."""
    return _get_engine().list_cves(
        org_id,
        severity=severity,
        kev_listed=kev_listed,
        exploit_available=exploit_available,
        status=status,
        limit=limit,
    )


@router.get("/cves/{cve_id}", dependencies=[Depends(api_key_auth)])
def get_cve(cve_id: str, org_id: str = Query(default="default")):
    """Get a single CVE with full details."""
    cve = _get_engine().get_cve(org_id, cve_id)
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    return cve


@router.get("/cves/{cve_id}/context", dependencies=[Depends(api_key_auth)])
def get_cve_context(cve_id: str, org_id: str = Query(default="default")):
    """Return enriched CVE context: CVE details + affected components from SBOM
    data with fix versions + related CVEs in the same component + org risk score
    from the risk aggregator.

    Combines data from vuln-intel, supply-chain, and risk-aggregator engines
    to produce the full Snyk-style CVE → affected packages → fix version view.
    """
    ctx = _get_engine().get_cve_context(org_id, cve_id)
    if ctx is None:
        raise HTTPException(status_code=404, detail="CVE not found")
    return ctx


@router.patch("/cves/{cve_id}/status", dependencies=[Depends(api_key_auth)])
def update_cve_status(
    cve_id: str,
    body: CVEStatusUpdate,
     org_id: str = Query(default="default"),
):
    """Update CVE lifecycle status."""
    try:
        updated = _get_engine().update_cve_status(org_id, cve_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not updated:
        raise HTTPException(status_code=404, detail="CVE not found")
    return {"updated": True, "cve_id": cve_id, "status": body.status}


# ---------------------------------------------------------------------------
# Advisory routes
# ---------------------------------------------------------------------------

@router.post("/advisories", dependencies=[Depends(api_key_auth)], status_code=201)
def add_advisory(body: AdvisoryCreate, org_id: str = Query(default="default")):
    """Add a vendor advisory."""
    try:
        return _get_engine().add_advisory(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/advisories", dependencies=[Depends(api_key_auth)])
def list_advisories(
     org_id: str = Query(default="default"),
    vendor: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List vendor advisories with optional filters."""
    return _get_engine().list_advisories(org_id, vendor=vendor, status=status)


@router.post("/advisories/{advisory_id}/apply", dependencies=[Depends(api_key_auth)])
def apply_advisory(advisory_id: str, org_id: str = Query(default="default")):
    """Mark an advisory as applied."""
    applied = _get_engine().apply_advisory(org_id, advisory_id)
    if not applied:
        raise HTTPException(status_code=404, detail="Advisory not found")
    return {"applied": True, "advisory_id": advisory_id}


# ---------------------------------------------------------------------------
# Subscription routes
# ---------------------------------------------------------------------------

@router.post("/subscriptions", dependencies=[Depends(api_key_auth)], status_code=201)
def add_subscription(body: SubscriptionCreate, org_id: str = Query(default="default")):
    """Add an intel subscription."""
    try:
        return _get_engine().add_subscription(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/subscriptions", dependencies=[Depends(api_key_auth)])
def list_subscriptions(org_id: str = Query(default="default")):
    """List all intel subscriptions for org."""
    return _get_engine().list_subscriptions(org_id)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_intel_stats(org_id: str = Query(default="default")):
    """Return aggregated vulnerability intelligence statistics for the org."""
    return _get_engine().get_intel_stats(org_id)


# ---------------------------------------------------------------------------
# PURL-based package vulnerability lookup (Snyk API parity)
# ---------------------------------------------------------------------------

@router.get("/packages/{purl:path}/issues", dependencies=[Depends(api_key_auth)])
def get_package_issues(purl: str, org_id: str = Query(default="default")):
    """Return CVEs and risk score for a PURL-identified package.

    Parses ``pkg:ecosystem/name@version`` and queries both the SBOM component
    table and cve_intel affected_products to build a Snyk-compatible response.

    Example: GET /api/v1/vuln-intel/packages/pkg:npm/lodash@4.17.21/issues
    """
    import re as _re

    # Parse PURL: pkg:ecosystem/name@version (namespace/name@version also accepted)
    purl_match = _re.match(
        r"pkg:(?P<ecosystem>[^/]+)/(?:(?P<namespace>[^/]+)/)?(?P<name>[^@]+)@(?P<version>.+)",
        purl,
    )
    if not purl_match:
        raise HTTPException(
            status_code=422,
            detail=(
                "Invalid PURL format. Expected: pkg:ecosystem/name@version "
                "e.g. pkg:npm/lodash@4.17.21"
            ),
        )

    ecosystem = purl_match.group("ecosystem")
    name = purl_match.group("name")
    version = purl_match.group("version")

    try:
        return _get_engine().lookup_package_issues(org_id, ecosystem, name, version)
    except Exception as exc:
        _logger.error("lookup_package_issues failed for %s: %s", purl, exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Brain sync — pull ASPM CVE findings into vuln-intel DB
# ---------------------------------------------------------------------------

@router.post("/sync", dependencies=[Depends(api_key_auth)])
def sync_cves_from_brain(
    org_id: str = Query("default", description="Target org for upserted CVEs"),
) -> Dict[str, Any]:
    """Pull CVE/vulnerability findings from the brain graph and upsert them into
    the vuln-intel database.

    The ASPM scanner stores findings under the ``aldeci`` org in the brain graph.
    This endpoint reads all ``finding``-type nodes from ``aldeci`` (and the
    caller's org) and inserts any CVE-like entries into the vuln-intel table so
    that ``GET /api/v1/vuln-intel/cves`` returns real scan data.
    """
    try:
        from core.knowledge_brain import get_brain
    except ImportError:
        raise HTTPException(status_code=503, detail="knowledge_brain not available")

    brain = get_brain()
    engine = _get_engine()

    # Pull finding nodes from both the caller org and the ASPM org
    all_nodes: Dict[str, Any] = {}
    for query_org in ("aldeci", org_id):
        try:
            res = brain.query_nodes(node_type="finding", org_id=query_org, limit=5000)
            for node in res.nodes:
                all_nodes[node["node_id"]] = node
        except Exception:
            pass

    synced = 0
    skipped = 0
    errors = 0

    for node in all_nodes.values():
        props = node.get("properties", {})
        title: str = props.get("title", "")
        severity: str = props.get("severity", "medium")
        source: str = props.get("source", "aspm-harness")

        # Only process CVE / GHSA identifiers
        import re as _re
        cve_match = _re.search(r"CVE-\d{4}-\d+", title, _re.IGNORECASE)
        ghsa_match = _re.search(r"GHSA-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+", title, _re.IGNORECASE)
        if not cve_match and not ghsa_match:
            skipped += 1
            continue

        cve_id = cve_match.group(0).upper() if cve_match else ghsa_match.group(0).upper()

        # Map severity to valid values
        severity = severity.lower()
        if severity not in ("critical", "high", "medium", "low", "informational"):
            severity = "medium"

        try:
            engine.add_cve(org_id, {
                "cve_id": cve_id,
                "title": title,
                "description": f"Detected by ASPM harness via {source}",
                "severity": severity,
                "status": "new",
                "affected_products": [],
            })
            synced += 1
        except Exception as exc:
            _logger.debug("sync CVE %s skipped: %s", cve_id, exc)
            # Likely a duplicate — count as skipped not error
            skipped += 1

    return {
        "synced": synced,
        "skipped": skipped,
        "errors": errors,
        "source_org": "aldeci",
        "target_org": org_id,
    }


@router.get("/", summary="Vulnerability intelligence index", tags=["vuln-intel"])
def vuln_intel_index(org_id: str = Query("default"), _auth: None = Depends(api_key_auth)) -> Dict[str, Any]:
    """Return vulnerability intelligence summary for the org."""
    try:
        items = _get_engine().list_cves(org_id, limit=10)
    except Exception:
        items = []
    return {"router": "vuln-intel", "org_id": org_id, "items": items, "count": len(items)}
