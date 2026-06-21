"""
Supply Chain Security API Router.

8 endpoints:
  POST   /api/v1/supply-chain/sbom/upload       Upload SBOM (CycloneDX or SPDX JSON)
  GET    /api/v1/supply-chain/components         List all tracked components with risk scores
  GET    /api/v1/supply-chain/risks              Supply chain risk dashboard data
  POST   /api/v1/supply-chain/scan               Trigger dependency scan for a repo
  GET    /api/v1/supply-chain/policies           List active policies
  POST   /api/v1/supply-chain/policies           Create/update a policy
  GET    /api/v1/supply-chain/vendors            Vendor risk assessments
  POST   /api/v1/supply-chain/vendors            Create/update a vendor risk assessment
  GET    /api/v1/supply-chain/provenance/{component}  Provenance info for a component

Compliance: NIST SP 800-218 (SSDF), EO 14028, SLSA Framework
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from apps.api.dependencies import get_org_id
from pydantic import BaseModel, Field

# Event bus subscriber — auto-sync component nodes as they arrive in the brain
try:
    from core.event_bus import EventType
    from core.event_bus import get_event_bus as _get_event_bus
    _EVENT_BUS_AVAILABLE = True
except ImportError:
    _EVENT_BUS_AVAILABLE = False

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    from fastapi import Depends
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "supply_chain_router: auth_deps not available, relying on app.py mount-level auth"
    )
    def _api_key_auth_failclosed():
        from fastapi import HTTPException
        raise HTTPException(status_code=503, detail="auth dependency unavailable")
    _AUTH_DEP = [Depends(_api_key_auth_failclosed)]

from core.supply_chain_security import (
    PolicyAction,
    ProvenanceLevel,
    ProvenanceRecord,
    RiskDashboard,
    SupplyChainEngine,
    SupplyChainPolicy,
    VendorRiskAssessment,
    VendorTier,
)

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/supply-chain",
    tags=["Supply Chain Security"],
    dependencies=_AUTH_DEP,
)

# Shared engine singleton (SQLite-backed) — SupplyChainEngine (SBOM/provenance)
_engine: Optional[SupplyChainEngine] = None

# Shared intel singleton — SupplyChainIntel (package risk / alerts)
_intel = None  # type: Optional[Any]


def _get_engine() -> SupplyChainEngine:
    global _engine
    if _engine is None:
        _engine = SupplyChainEngine()
    return _engine


def _get_intel():
    global _intel
    if _intel is None:
        from core.supply_chain_intel import SupplyChainIntel
        _intel = SupplyChainIntel()
    return _intel


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class SBOMUploadRequest(BaseModel):
    """Request body for uploading an SBOM document."""

    sbom: Dict[str, Any] = Field(
        ..., description="Raw CycloneDX or SPDX SBOM as a JSON object"
    )
    org_id: str = Field("default", description="Organisation ID")
    source_repo: Optional[str] = Field(
        None, description="Git repository URL this SBOM was generated from"
    )


class SBOMUploadResponse(BaseModel):
    """Response after SBOM ingestion."""

    sbom_id: str
    format: str
    name: str
    version: str
    component_count: int
    sha256: str
    attack_signals_detected: int
    org_id: str


class ScanRequest(BaseModel):
    """Request body for triggering a repository dependency scan."""

    repo_url: str = Field(..., description="Git repository URL to scan")
    branch: str = Field("main", description="Branch to scan")
    org_id: str = Field("default", description="Organisation ID")


class CreatePolicyRequest(BaseModel):
    """Request body for creating or updating a supply chain policy."""

    name: str = Field(..., description="Policy name")
    description: str = Field("", description="Policy description")
    enabled: bool = Field(True)
    action: PolicyAction = Field(PolicyAction.WARN)
    org_id: str = Field("default")
    blocked_licenses: Optional[List[str]] = Field(
        None,
        description="SPDX license IDs to block. Defaults to GPL-2.0, GPL-3.0, AGPL-3.0, LGPL variants.",
    )
    require_sbom: bool = Field(False)
    max_transitive_depth: Optional[int] = Field(None, ge=0)
    required_provenance_level: ProvenanceLevel = Field(ProvenanceLevel.SLSA_0)
    max_critical_cves: int = Field(0, ge=0)
    max_overall_risk_score: float = Field(80.0, ge=0.0, le=100.0)


class CreateVendorRequest(BaseModel):
    """Request body for creating or updating a vendor risk assessment."""

    vendor_name: str = Field(..., description="Vendor / publisher name")
    vendor_url: Optional[str] = Field(None)
    tier: VendorTier = Field(VendorTier.MEDIUM)
    org_id: str = Field("default")
    security_score: float = Field(50.0, ge=0.0, le=100.0)
    sla_uptime_pct: Optional[float] = Field(None, ge=0.0, le=100.0)
    sla_response_hours: Optional[int] = Field(None, ge=0)
    sla_compliant: bool = Field(True)
    known_breaches: int = Field(0, ge=0)
    breach_details: List[str] = Field(default_factory=list)
    component_count: int = Field(0, ge=0)
    security_contact: Optional[str] = Field(None)
    bug_bounty: bool = Field(False)
    mfa_required: bool = Field(False)
    sbom_provided: bool = Field(False)
    notes: str = Field("")


class ProvenanceQueryResponse(BaseModel):
    """Response for a provenance lookup."""

    found: bool
    component_name: str
    component_version: Optional[str]
    provenance: Optional[ProvenanceRecord]


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.post(
    "/sbom/upload",
    response_model=SBOMUploadResponse,
    status_code=201,
    summary="Upload an SBOM (CycloneDX or SPDX JSON)",
)
def upload_sbom(body: SBOMUploadRequest) -> SBOMUploadResponse:
    """
    Ingest a Software Bill of Materials document.

    Accepts CycloneDX (v1.4-v1.6) or SPDX (v2.2-v2.3) JSON.
    On ingestion the engine:
    - Parses and stores all components
    - Computes dependency risk scores for each component
    - Runs supply chain attack detection (typosquatting, dependency confusion,
      version bump anomalies)

    Returns the SBOM record summary and count of attack signals detected.
    """
    engine = _get_engine()
    try:
        record, components, signals = engine.ingest_sbom(
            raw_payload=body.sbom,
            org_id=body.org_id,
            source_repo=body.source_repo,
        )
        return SBOMUploadResponse(
            sbom_id=record.id,
            format=record.format.value,
            name=record.name,
            version=record.version,
            component_count=record.component_count,
            sha256=record.sha256,
            attack_signals_detected=len(signals),
            org_id=record.org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("SBOM upload failed for org=%s", body.org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/components",
    summary="List all tracked components with risk scores",
)
def list_components(
    org_id: str = Query("default", description="Organisation ID"),
    limit: int = Query(200, ge=1, le=1000, description="Maximum results"),
) -> List[Dict[str, Any]]:
    """
    Return all software components tracked across all uploaded SBOMs.

    Each entry includes the component metadata plus its computed risk score
    (CVE exposure, license risk, maintenance status, transitive depth, etc.).
    """
    engine = _get_engine()
    try:
        return engine.list_components(org_id=org_id, limit=limit)
    except Exception as exc:
        _logger.exception("list_components failed for org=%s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/risks",
    response_model=RiskDashboard,
    summary="Supply chain risk dashboard",
)
def get_risk_dashboard(
    org_id: str = Query("default", description="Organisation ID"),
) -> RiskDashboard:
    """
    Return an aggregated risk dashboard for the organisation's supply chain.

    Includes:
    - Component counts by risk level
    - Recent attack signals
    - Top-10 highest-risk components
    - Vendor risk summary
    - Policy violation counts
    """
    engine = _get_engine()
    try:
        return engine.get_risk_dashboard(org_id=org_id)
    except Exception as exc:
        _logger.exception("get_risk_dashboard failed for org=%s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/scan",
    summary="Trigger a supply chain dependency scan for a repository",
)
def trigger_scan(body: ScanRequest) -> Dict[str, Any]:
    """
    Queue a supply chain scan for a Git repository.

    In production this integrates with pip-audit, npm audit, trivy, and grype
    to produce CVE findings for all dependencies. Returns a scan job record;
    results are available asynchronously.
    """
    engine = _get_engine()
    try:
        return engine.scan_repo(
            repo_url=body.repo_url,
            org_id=body.org_id,
            branch=body.branch,
        )
    except Exception as exc:
        _logger.exception("trigger_scan failed for repo=%s", body.repo_url)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/policies",
    response_model=List[SupplyChainPolicy],
    summary="List active supply chain policies",
)
def list_policies(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[SupplyChainPolicy]:
    """
    Return all supply chain security policies for the organisation.

    Policies control:
    - Which licenses are blocked (e.g. GPL in commercial products)
    - Whether SBOMs are required for all dependencies
    - Maximum transitive dependency depth
    - Required SLSA provenance level
    - CVE and risk score thresholds
    """
    engine = _get_engine()
    try:
        return engine.list_policies(org_id=org_id)
    except Exception as exc:
        _logger.exception("list_policies failed for org=%s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/policies",
    response_model=SupplyChainPolicy,
    status_code=201,
    summary="Create or update a supply chain policy",
)
def create_policy(body: CreatePolicyRequest) -> SupplyChainPolicy:
    """
    Create a new supply chain security policy.

    Policies are evaluated against every component at SBOM ingestion time and
    during continuous monitoring scans. Violations trigger the configured action
    (BLOCK, WARN, or AUDIT).
    """
    engine = _get_engine()
    try:
        kwargs: Dict[str, Any] = body.model_dump()
        if kwargs.get("blocked_licenses") is None:
            del kwargs["blocked_licenses"]
        policy = SupplyChainPolicy(**kwargs)
        return engine.create_policy(policy)
    except Exception as exc:
        _logger.exception("create_policy failed name=%s org=%s", body.name, body.org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/vendors",
    response_model=List[VendorRiskAssessment],
    summary="List vendor risk assessments",
)
def list_vendors(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[VendorRiskAssessment]:
    """
    Return all vendor risk assessments for the organisation.

    Each assessment captures:
    - Security posture score
    - SLA compliance
    - Known breach history
    - Concentration risk (how many components come from this vendor)
    - Bug bounty / MFA / SBOM availability signals
    """
    engine = _get_engine()
    try:
        return engine.list_vendors(org_id=org_id)
    except Exception as exc:
        _logger.exception("list_vendors failed for org=%s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/vendors",
    response_model=VendorRiskAssessment,
    status_code=201,
    summary="Create or update a vendor risk assessment",
)
def upsert_vendor(body: CreateVendorRequest) -> VendorRiskAssessment:
    """
    Create or update a vendor risk assessment.

    Concentration risk is automatically computed from component_count.
    """
    engine = _get_engine()
    try:
        vendor = VendorRiskAssessment(**body.model_dump())
        return engine.upsert_vendor(vendor)
    except Exception as exc:
        _logger.exception("upsert_vendor failed vendor=%s", body.vendor_name)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/provenance/{component_name}",
    response_model=ProvenanceQueryResponse,
    summary="Get provenance information for a component",
)
def get_provenance(
    component_name: str,
    version: Optional[str] = Query(None, description="Specific version to look up"),
) -> ProvenanceQueryResponse:
    """
    Return SLSA provenance and build attestation information for a component.

    Looks up the most recent verified provenance record. Returns SLSA level,
    builder identity, source URI, signature verification status, and any
    verification errors.
    """
    engine = _get_engine()
    try:
        record = engine.get_provenance(component_name=component_name, component_version=version)
        return ProvenanceQueryResponse(
            found=record is not None,
            component_name=component_name,
            component_version=version,
            provenance=record,
        )
    except Exception as exc:
        _logger.exception("get_provenance failed component=%s", component_name)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ============================================================================
# NEW: SBOM Generation, OSV Scanning, License Audit
# ============================================================================


class SBOMGenerateRequest(BaseModel):
    """Request body for generating a CycloneDX SBOM from a local manifest."""

    manifest_path: str = Field(
        ...,
        description="Filesystem path to requirements.txt or package.json",
    )
    project_name: str = Field("unknown", description="Project name for SBOM metadata")
    project_version: str = Field("0.0.0", description="Project version for SBOM metadata")


class OSVScanRequest(BaseModel):
    """Request body for an OSV vulnerability scan of listed packages."""

    packages: List[Dict[str, str]] = Field(
        ...,
        description="List of {name, version, ecosystem} dicts. ecosystem: PyPI|npm|Go|Maven",
    )


class LicenseAuditRequest(BaseModel):
    """Request body for a license audit of a manifest file."""

    manifest_path: str = Field(
        ...,
        description="Filesystem path to requirements.txt or package.json",
    )
    fetch_pypi: bool = Field(
        True,
        description="Fetch live license data from PyPI API for Python packages",
    )


@router.post(
    "/sbom",
    summary="Generate a CycloneDX 1.4 SBOM from a local manifest file",
    status_code=200,
)
def generate_sbom(body: SBOMGenerateRequest) -> Dict[str, Any]:
    """
    Generate a CycloneDX 1.4 SBOM JSON from a requirements.txt or package.json.

    Parses the manifest at the given path and returns the SBOM document.
    Does not persist the SBOM — use /sbom/upload to store it.
    """
    try:
        from core.sbom_generator import SBOMGenerator
    except ImportError as exc:
        raise HTTPException(status_code=500, detail=f"SBOMGenerator not available: {exc}") from exc

    gen = SBOMGenerator(
        project_name=body.project_name,
        project_version=body.project_version,
    )
    path = body.manifest_path
    try:
        if path.endswith("package.json"):
            sbom = gen.generate_from_package_json(path)
        else:
            sbom = gen.generate_from_requirements(path)
        return sbom
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("generate_sbom failed path=%s", path)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/osv-scan",
    summary="Query OSV for vulnerabilities in a list of packages",
    status_code=200,
)
def osv_scan(body: OSVScanRequest) -> List[Dict[str, Any]]:
    """
    Query https://api.osv.dev/v1/querybatch for vulnerabilities.

    Accepts a list of packages with name, version, and ecosystem.
    Returns OSV vulnerability findings mapped to the ALDECI finding schema.
    No authentication required — OSV is a free public API.
    """
    try:
        from core.sbom_generator import SBOMGenerator
    except ImportError as exc:
        raise HTTPException(status_code=500, detail=f"SBOMGenerator not available: {exc}") from exc

    gen = SBOMGenerator()
    try:
        raw = gen.query_osv(body.packages)
        return gen.map_osv_to_findings(raw)
    except Exception as exc:
        _logger.exception("osv_scan failed packages=%s", body.packages)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/sync",
    summary="Sync SBOM components from the brain graph into the supply-chain DB",
    status_code=200,
)
def sync_from_brain(
    org_id: str = Query("default", description="Organisation ID"),
) -> dict:
    """
    Query the KnowledgeBrain for all ``component``-type nodes and upsert them
    into the supply-chain components table.

    - Existing components: brain fields (name, version, ecosystem, purl) are
      refreshed; existing risk scores and metadata are preserved.
    - New components: inserted with a computed risk score.

    After sync, ``GET /api/v1/supply-chain/components`` will reflect the
    125+ SBOM components ingested via ``/api/v1/brain/nodes``.
    """
    engine = _get_engine()
    try:
        result = engine.sync_from_brain(org_id=org_id)
        return result
    except Exception as exc:
        _logger.exception("sync_from_brain failed for org=%s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/license-audit",
    summary="Audit dependency licenses from a manifest file",
    status_code=200,
)
def license_audit(
    manifest_path: str = Query(..., description="Path to requirements.txt or package.json"),
    fetch_pypi: bool = Query(True, description="Fetch live PyPI license data"),
) -> Dict[str, Any]:
    """
    Classify dependency licenses as PERMISSIVE, COPYLEFT, PROPRIETARY, or UNKNOWN.

    Flags COPYLEFT and PROPRIETARY dependencies as HIGH risk for commercial projects.
    For Python packages, optionally enriches license data via the PyPI JSON API.

    Returns a summary dict with per-category counts, risk score, and a list
    of flagged high-risk packages.
    """
    try:
        from core.license_auditor import LicenseAuditor
    except ImportError as exc:
        raise HTTPException(status_code=500, detail=f"LicenseAuditor not available: {exc}") from exc

    auditor = LicenseAuditor(fetch_pypi=fetch_pypi)
    try:
        if manifest_path.endswith("package.json"):
            results = auditor.audit_package_json(manifest_path)
        else:
            results = auditor.audit_requirements(manifest_path)
        summary = auditor.audit_summary(results)
        summary["details"] = [
            {
                "name": r.name,
                "version": r.version,
                "ecosystem": r.ecosystem,
                "license": r.license_id,
                "category": r.category.value,
                "is_high_risk": r.is_high_risk,
                "risk_reason": r.risk_reason,
            }
            for r in results
        ]
        return summary
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("license_audit failed path=%s", manifest_path)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ============================================================================
# SupplyChainIntel endpoints — package risk scoring, alerts, typosquat, etc.
# ============================================================================


class AnalyzePackageRequest(BaseModel):
    package_name: str
    ecosystem: str = "pip"
    version: str = ""
    org_id: str = "default"


class AnalyzeSBOMRequest(BaseModel):
    sbom_id: str
    org_id: str = "default"
    db_path: str = "data/sbom.db"


class TyposquatRequest(BaseModel):
    package_name: str
    ecosystem: str = "pip"


class MaintainerTrustRequest(BaseModel):
    package_name: str
    ecosystem: str = "pip"


def _risk_level(score: float) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score > 0:
        return "low"
    return "safe"


@router.post("/analyze", summary="Analyze a single package for supply chain risks")
def analyze_package(body: AnalyzePackageRequest) -> Dict[str, Any]:
    """
    Fetch real registry metadata (PyPI / npm) and score a package for:
    known malicious code, typosquatting, abandonment, low maintainer count,
    known CVEs (OSV.dev), and dependency confusion.
    """
    from core.supply_chain_intel import SupplyChainIntelError
    intel = _get_intel()
    try:
        result = intel.analyze_package(
            name=body.package_name,
            ecosystem=body.ecosystem,
            version=body.version,
            org_id=body.org_id,
        )
    except SupplyChainIntelError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("analyze_package failed name=%s", body.package_name)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    data = result.model_dump()
    data["risk_level"] = _risk_level(result.risk_score)
    return data


@router.post("/analyze-sbom", summary="Analyze all packages in an SBOM by sbom_id")
def analyze_sbom_intel(body: AnalyzeSBOMRequest) -> Dict[str, Any]:
    """Analyze every component from a stored SBOM and return aggregated risk."""
    from core.supply_chain_intel import SupplyChainIntelError
    intel = _get_intel()
    try:
        results = intel.analyze_sbom(
            sbom_id=body.sbom_id,
            org_id=body.org_id,
            db_path=body.db_path,
        )
    except SupplyChainIntelError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("analyze_sbom failed sbom_id=%s", body.sbom_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {
        "sbom_id": body.sbom_id,
        "org_id": body.org_id,
        "total_components": len(results),
        "results": [r.model_dump() for r in results],
    }


@router.get("/alerts", summary="List supply chain alerts")
def get_intel_alerts(org_id: str = Query("default")) -> Dict[str, Any]:
    intel = _get_intel()
    alerts = intel.get_alerts(org_id=org_id)
    return {"alerts": [a.model_dump() for a in alerts], "total": len(alerts)}


@router.post("/alerts/{alert_id}/resolve", summary="Resolve a supply chain alert")
def resolve_intel_alert(alert_id: str) -> Dict[str, Any]:
    intel = _get_intel()
    resolved = intel.resolve_alert(alert_id)
    if not resolved:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id!r} not found")
    return {"alert_id": alert_id, "resolved": True}


@router.get("/high-risk", summary="List high-risk packages above a score threshold")
def get_high_risk_packages(
    org_id: str = Query("default"),
    threshold: float = Query(70.0, ge=0.0, le=100.0),
) -> Dict[str, Any]:
    intel = _get_intel()
    packages = intel.get_high_risk_packages(org_id=org_id, threshold=threshold)
    return {
        "packages": [p.model_dump() for p in packages],
        "threshold": threshold,
        "total": len(packages),
    }


@router.get("/stats", summary="Supply chain intelligence aggregate statistics")
def get_intel_stats(org_id: str = Query("default")) -> Dict[str, Any]:
    intel = _get_intel()
    return intel.get_supply_chain_stats(org_id=org_id)


@router.post("/typosquat", summary="Check if a package name is a typosquat")
def check_typosquat(body: TyposquatRequest) -> Dict[str, Any]:
    intel = _get_intel()
    hits = intel.detect_typosquat(body.package_name, body.ecosystem)
    return {
        "package_name": body.package_name,
        "ecosystem": body.ecosystem,
        "is_typosquat": len(hits) > 0,
        "similar_packages": hits,
    }


@router.post("/maintainer-trust", summary="Maintainer trust analysis for a package")
def check_maintainer_trust(body: MaintainerTrustRequest) -> Dict[str, Any]:
    from core.supply_chain_intel import SupplyChainIntelError
    intel = _get_intel()
    try:
        return intel.check_maintainer_trust(body.package_name, body.ecosystem)
    except SupplyChainIntelError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/malicious-db", summary="List known-malicious package database")
def get_malicious_db(
    ecosystem: Optional[str] = Query(None, description="Filter by ecosystem: pip, npm, maven"),
) -> Dict[str, Any]:
    from core.supply_chain_intel import _KNOWN_MALICIOUS
    entries = [
        {"package": pkg, **info}
        for pkg, info in _KNOWN_MALICIOUS.items()
        if ecosystem is None or info.get("ecosystem") == ecosystem
    ]
    return {"total": len(entries), "entries": entries}


@router.get("/risk-summary", summary="Risk summary grouped by ecosystem, category, severity")
def get_risk_summary(org_id: str = Query("default")) -> Dict[str, Any]:
    intel = _get_intel()
    return intel.get_risk_summary(org_id=org_id)


# ============================================================================
# BRAIN GRAPH SUBSCRIBER — auto-sync component nodes on ingest
# ============================================================================


def _register_brain_subscriber() -> None:
    """
    Subscribe to GRAPH_UPDATED events. When a ``component`` node is upserted
    into the brain, automatically sync it into the supply-chain DB.

    This is a best-effort background sync — failures are logged, not raised.
    Registration is skipped if the event bus is unavailable.
    """
    if not _EVENT_BUS_AVAILABLE:
        return

    try:
        bus = _get_event_bus()

        async def _on_graph_updated(event: Any) -> None:
            data = event.data if hasattr(event, "data") else {}
            if data.get("node_type") != "component":
                return
            if data.get("action") not in ("upsert_node", "create_node"):
                return
            org_id = getattr(event, "org_id", None) or data.get("org_id") or "default"
            try:
                engine = _get_engine()
                result = engine.sync_from_brain(org_id=org_id)
                _logger.debug(
                    "brain->supply-chain auto-sync: org=%s synced=%d skipped=%d",
                    org_id, result.get("synced", 0), result.get("skipped", 0),
                )
            except Exception as exc:
                _logger.warning("brain->supply-chain auto-sync failed: %s", exc)

        bus.subscribe(EventType.GRAPH_UPDATED, _on_graph_updated)
        _logger.info("supply_chain_router: registered brain GRAPH_UPDATED subscriber")
    except Exception as exc:
        _logger.warning("supply_chain_router: could not register brain subscriber: %s", exc)


_register_brain_subscriber()
