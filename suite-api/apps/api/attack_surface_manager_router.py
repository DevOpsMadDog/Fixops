"""Attack Surface Management (ASM) Router.

REST API for the full-lifecycle ASM engine — asset inventory, scoring,
shadow IT detection, exposure analysis, attack paths, change monitoring,
and certificate health.

Mounted by app.py under read:findings scope.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "attack_surface_manager_router: auth_deps not available, "
        "relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.attack_surface_manager import (
    ASMSurfaceScore,
    AssetCategory,
    AttackPath,
    AttackSurfaceManager,
    CertificateRecord,
    ExposureZone,
    ManagedAsset,
    RiskTier,
    ScanResult,
    ShadowITFinding,
    SurfaceChange,
    get_asm_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/attack-surface",
    tags=["Attack Surface Management"],
    dependencies=_AUTH_DEP,
)


# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------


def _get_engine() -> AttackSurfaceManager:
    return get_asm_engine()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class RegisterAssetRequest(BaseModel):
    name: str = Field(..., description="Asset name or identifier")
    category: AssetCategory = Field(..., description="Asset category")
    exposure_zone: ExposureZone = Field(ExposureZone.INTERNAL, description="Exposure zone")
    org_id: str = Field("default", description="Organisation ID")
    ip_addresses: List[str] = Field(default_factory=list)
    open_ports: List[int] = Field(default_factory=list)
    technologies: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)
    has_waf: bool = False
    has_cdn: bool = False
    tls_grade: Optional[str] = None
    cert_expiry_days: Optional[int] = None
    security_headers_score: float = 0.0
    business_value: float = 50.0
    owner: Optional[str] = None
    is_managed: bool = True


class DiscoverAssetsRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    data: List[Dict[str, Any]] = Field(
        ..., description="Discovery data items (from network scans, DNS, cloud APIs)"
    )


class ShadowITScanRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    cmdb_names: Optional[List[str]] = Field(
        None, description="Approved asset names from CMDB"
    )
    discovered_names: Optional[List[str]] = Field(
        None, description="Extra names from network discovery"
    )


class MapAttackPathRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    entry_asset_id: str = Field(..., description="Internet-facing entry point asset ID")
    target_asset_id: str = Field(..., description="Internal target asset ID")
    hops: Optional[List[str]] = Field(None, description="Intermediate hop asset IDs")
    protocol: str = Field("unknown", description="Network protocol")
    techniques: Optional[List[str]] = Field(None, description="MITRE ATT&CK technique IDs")


class RegisterCertRequest(BaseModel):
    org_id: str = Field("default")
    asset_id: str = Field(..., description="Asset this certificate belongs to")
    asset_name: str
    subject: str
    issuer: str
    valid_from: str
    valid_to: str
    days_until_expiry: int
    san_domains: List[str] = Field(default_factory=list)
    is_expired: bool = False
    is_self_signed: bool = False
    tls_version: str = "TLS 1.2"
    cipher_suite: str = ""
    grade: str = "A"


class TriggerScanRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    discovery_data: Optional[List[Dict[str, Any]]] = Field(
        None, description="Optional discovery data to ingest during scan"
    )
    cmdb_names: Optional[List[str]] = Field(
        None, description="CMDB inventory for shadow IT comparison"
    )


# ---------------------------------------------------------------------------
# 1. Asset inventory — GET /assets
# ---------------------------------------------------------------------------


@router.get("/assets", response_model=List[ManagedAsset], summary="Full attack surface inventory")
def list_assets(
    org_id: str = Query("default", description="Organisation ID"),
    category: Optional[AssetCategory] = Query(None, description="Filter by category"),
    zone: Optional[ExposureZone] = Query(None, description="Filter by exposure zone"),
    tier: Optional[RiskTier] = Query(None, description="Filter by risk tier"),
    engine: AttackSurfaceManager = Depends(_get_engine),
) -> List[ManagedAsset]:
    """Return full attack surface asset inventory with optional filters."""
    return engine.list_assets(org_id, category=category, zone=zone, tier=tier)


@router.post("/assets", response_model=ManagedAsset, summary="Register an asset")
def register_asset(
    req: RegisterAssetRequest,
    engine: AttackSurfaceManager = Depends(_get_engine),
) -> ManagedAsset:
    """Register or update a managed asset in the ASM inventory."""
    asset = ManagedAsset(
        name=req.name,
        category=req.category,
        exposure_zone=req.exposure_zone,
        org_id=req.org_id,
        ip_addresses=req.ip_addresses,
        open_ports=req.open_ports,
        technologies=req.technologies,
        tags=req.tags,
        attributes=req.attributes,
        has_waf=req.has_waf,
        has_cdn=req.has_cdn,
        tls_grade=req.tls_grade,
        cert_expiry_days=req.cert_expiry_days,
        security_headers_score=req.security_headers_score,
        business_value=req.business_value,
        owner=req.owner,
        is_managed=req.is_managed,
    )
    try:
        return engine.register_asset(asset)
    except Exception as exc:
        logger.exception("Failed to register asset: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to register asset: {exc}") from exc


@router.get("/assets/{asset_id}", response_model=ManagedAsset, summary="Get single asset")
def get_asset(
    asset_id: str,
    engine: AttackSurfaceManager = Depends(_get_engine),
) -> ManagedAsset:
    """Retrieve a single managed asset by ID."""
    asset = engine.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")
    return asset


@router.delete("/assets/{asset_id}", summary="Delete an asset")
def delete_asset(
    asset_id: str,
    engine: AttackSurfaceManager = Depends(_get_engine),
) -> Dict[str, Any]:
    """Remove an asset from the ASM inventory."""
    deleted = engine.delete_asset(asset_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found")
    return {"deleted": True, "asset_id": asset_id}


@router.post("/assets/discover", response_model=List[ManagedAsset], summary="Discover assets from raw data")
def discover_assets(
    req: DiscoverAssetsRequest,
    engine: AttackSurfaceManager = Depends(_get_engine),
) -> List[ManagedAsset]:
    """Parse and register assets from network scan / DNS / cloud discovery data."""
    try:
        return engine.discover_assets_from_data(req.data, org_id=req.org_id)
    except Exception as exc:
        logger.exception("Asset discovery failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Discovery failed: {exc}") from exc


# ---------------------------------------------------------------------------
# 2. Overall score — GET /score
# ---------------------------------------------------------------------------


@router.get("/score", response_model=ASMSurfaceScore, summary="Overall attack surface score + breakdown")
def get_surface_score(
    org_id: str = Query("default", description="Organisation ID"),
    engine: AttackSurfaceManager = Depends(_get_engine),
) -> ASMSurfaceScore:
    """Return composite attack surface score with component breakdown."""
    return engine.compute_surface_score(org_id)


# ---------------------------------------------------------------------------
# 3. Internet-exposed assets — GET /exposed
# ---------------------------------------------------------------------------


@router.get("/exposed", response_model=List[ManagedAsset], summary="Internet-exposed assets")
def get_exposed_assets(
    org_id: str = Query("default", description="Organisation ID"),
    engine: AttackSurfaceManager = Depends(_get_engine),
) -> List[ManagedAsset]:
    """Return all internet-facing (INTERNET_FACING zone) assets."""
    return engine.list_assets(org_id, zone=ExposureZone.INTERNET_FACING)


@router.get("/exposed/{asset_id}/analysis", summary="Detailed exposure analysis for an asset")
def get_exposure_analysis(
    asset_id: str,
    engine: AttackSurfaceManager = Depends(_get_engine),
) -> Dict[str, Any]:
    """Return full exposure analysis: ports, TLS, headers, protection controls."""
    result = engine.analyze_exposure(asset_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


# ---------------------------------------------------------------------------
# 4. Shadow IT — GET /shadow-it
# ---------------------------------------------------------------------------


@router.get("/shadow-it", response_model=List[ShadowITFinding], summary="Shadow IT / unmanaged assets")
def list_shadow_it(
    org_id: str = Query("default", description="Organisation ID"),
    engine: AttackSurfaceManager = Depends(_get_engine),
) -> List[ShadowITFinding]:
    """Return previously detected shadow IT findings."""
    return engine.list_shadow_it(org_id)


@router.post("/shadow-it/scan", response_model=List[ShadowITFinding], summary="Run shadow IT detection scan")
def scan_shadow_it(
    req: ShadowITScanRequest,
    engine: AttackSurfaceManager = Depends(_get_engine),
) -> List[ShadowITFinding]:
    """Compare discovered assets against CMDB to detect shadow IT."""
    try:
        return engine.detect_shadow_it(
            req.org_id,
            cmdb_names=req.cmdb_names,
            discovered_names=req.discovered_names,
        )
    except Exception as exc:
        logger.exception("Shadow IT scan failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Shadow IT scan failed: {exc}") from exc


# ---------------------------------------------------------------------------
# 5. Attack paths — GET /paths
# ---------------------------------------------------------------------------


@router.get("/paths", response_model=List[AttackPath], summary="Attack path analysis")
def list_attack_paths(
    org_id: str = Query("default", description="Organisation ID"),
    min_score: float = Query(0.0, ge=0.0, le=1.0, description="Minimum path risk score"),
    choke_points_only: bool = Query(False, description="Return only choke point paths"),
    engine: AttackSurfaceManager = Depends(_get_engine),
) -> List[AttackPath]:
    """Return modelled attack paths, optionally filtered by risk score or choke points."""
    if choke_points_only:
        return engine.get_choke_points(org_id)
    return engine.list_attack_paths(org_id, min_score=min_score)


@router.post("/paths", response_model=AttackPath, summary="Define an attack path")
def map_attack_path(
    req: MapAttackPathRequest,
    engine: AttackSurfaceManager = Depends(_get_engine),
) -> AttackPath:
    """Explicitly define an attack path between an entry and target asset."""
    try:
        return engine.map_attack_path(
            org_id=req.org_id,
            entry_asset_id=req.entry_asset_id,
            target_asset_id=req.target_asset_id,
            hops=req.hops,
            protocol=req.protocol,
            techniques=req.techniques,
        )
    except Exception as exc:
        logger.exception("Attack path mapping failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Path mapping failed: {exc}") from exc


@router.post("/paths/auto-generate", response_model=List[AttackPath], summary="Auto-generate attack paths")
def auto_generate_paths(
    org_id: str = Query("default", description="Organisation ID"),
    engine: AttackSurfaceManager = Depends(_get_engine),
) -> List[AttackPath]:
    """Automatically generate attack paths from internet-facing to internal assets."""
    try:
        return engine.auto_generate_paths(org_id)
    except Exception as exc:
        logger.exception("Auto path generation failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Auto path generation failed: {exc}") from exc


# ---------------------------------------------------------------------------
# 6. Scan trigger — POST /scan
# ---------------------------------------------------------------------------


@router.post("/scan", response_model=ScanResult, summary="Trigger attack surface scan")
def trigger_scan(
    req: TriggerScanRequest,
    engine: AttackSurfaceManager = Depends(_get_engine),
) -> ScanResult:
    """Orchestrate a full ASM scan: discovery → scoring → shadow IT → paths → changes."""
    try:
        return engine.run_scan(
            org_id=req.org_id,
            discovery_data=req.discovery_data,
            cmdb_names=req.cmdb_names,
        )
    except Exception as exc:
        logger.exception("ASM scan failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}") from exc


@router.get("/scan/latest", response_model=Optional[ScanResult], summary="Get latest scan result")
def get_latest_scan(
    org_id: str = Query("default", description="Organisation ID"),
    engine: AttackSurfaceManager = Depends(_get_engine),
) -> Optional[ScanResult]:
    """Return the most recent scan result for an org."""
    return engine.get_latest_scan(org_id)


# ---------------------------------------------------------------------------
# 7. Changes — GET /changes
# ---------------------------------------------------------------------------


@router.get("/changes", response_model=List[SurfaceChange], summary="Recent attack surface changes")
def list_changes(
    org_id: str = Query("default", description="Organisation ID"),
    since: Optional[str] = Query(None, description="ISO timestamp lower bound"),
    engine: AttackSurfaceManager = Depends(_get_engine),
) -> List[SurfaceChange]:
    """Return recent changes: new assets, removed assets, cert alerts, WAF changes."""
    return engine.list_changes(org_id, since=since)


@router.post("/changes/detect", response_model=List[SurfaceChange], summary="Run change detection")
def detect_changes(
    org_id: str = Query("default", description="Organisation ID"),
    lookback_days: int = Query(7, ge=1, le=365, description="Days to look back"),
    engine: AttackSurfaceManager = Depends(_get_engine),
) -> List[SurfaceChange]:
    """Detect new and removed assets, expiring certs over the lookback window."""
    try:
        return engine.detect_changes(org_id, lookback_days=lookback_days)
    except Exception as exc:
        logger.exception("Change detection failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Change detection failed: {exc}") from exc


# ---------------------------------------------------------------------------
# 8. Certificates — GET /certificates
# ---------------------------------------------------------------------------


@router.get("/certificates", response_model=List[CertificateRecord], summary="Certificate inventory + health")
def list_certificates(
    org_id: str = Query("default", description="Organisation ID"),
    expiring_only: bool = Query(False, description="Return only expiring certificates"),
    within_days: int = Query(30, ge=1, le=365, description="Expiry window in days"),
    engine: AttackSurfaceManager = Depends(_get_engine),
) -> List[CertificateRecord]:
    """Return certificate inventory with health status. Filter to expiring-only if needed."""
    if expiring_only:
        return engine.get_expiring_certificates(org_id, within_days=within_days)
    return engine.list_certificates(org_id)


@router.post("/certificates", response_model=CertificateRecord, summary="Register a certificate")
def register_certificate(
    req: RegisterCertRequest,
    engine: AttackSurfaceManager = Depends(_get_engine),
) -> CertificateRecord:
    """Register a TLS certificate and auto-alert if expiring or expired."""
    cert = CertificateRecord(
        org_id=req.org_id,
        asset_id=req.asset_id,
        asset_name=req.asset_name,
        subject=req.subject,
        issuer=req.issuer,
        valid_from=req.valid_from,
        valid_to=req.valid_to,
        days_until_expiry=req.days_until_expiry,
        san_domains=req.san_domains,
        is_expired=req.is_expired,
        is_self_signed=req.is_self_signed,
        tls_version=req.tls_version,
        cipher_suite=req.cipher_suite,
        grade=req.grade,
    )
    try:
        return engine.register_certificate(cert)
    except Exception as exc:
        logger.exception("Certificate registration failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Certificate registration failed: {exc}") from exc


# ---------------------------------------------------------------------------
# 9. Risk prioritization — GET /prioritized
# ---------------------------------------------------------------------------


@router.get("/prioritized", summary="Risk-prioritized asset list")
def get_prioritized_assets(
    org_id: str = Query("default", description="Organisation ID"),
    top_n: int = Query(20, ge=1, le=200, description="Number of top assets to return"),
    engine: AttackSurfaceManager = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    """Return assets ranked by risk = exposure × vulnerability × business value with EPSS stubs."""
    return engine.prioritize_assets(org_id, top_n=top_n)
