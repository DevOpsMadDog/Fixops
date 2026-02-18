"""Vulnerability Intelligence Feeds API endpoints.

Exposes the world-class vulnerability intelligence feed service with 8 categories:
1. Global Authoritative (NVD, CISA KEV, MITRE, CERT/CC)
2. National CERTs (NCSC UK, BSI, ANSSI, JPCERT, etc.)
3. Exploit Intelligence (Exploit-DB, Metasploit, Vulners, etc.)
4. Threat Actor Intelligence (MITRE ATT&CK, AlienVault OTX, etc.)
5. Supply-Chain (OSV, GitHub Advisory, Snyk, deps.dev)
6. Cloud & Runtime (AWS, Azure, GCP bulletins, Kubernetes CVEs)
7. Zero-Day & Early-Signal (vendor blogs, GitHub commits, mailing lists)
8. Internal Enterprise (SAST/DAST/SCA, IaC, runtime detections)
"""

# Direct import — feeds_service.py lives in suite-feeds/ (on sys.path via sitecustomize.py)
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

# Knowledge Brain + Event Bus integration (graceful degradation)
try:
    from core.event_bus import Event, EventType, get_event_bus
    from core.knowledge_brain import get_brain

    _HAS_BRAIN = True
except ImportError:
    _HAS_BRAIN = False

from feeds_service import (
    AUTHORITATIVE_FEEDS,
    CLOUD_RUNTIME_FEEDS,
    EARLY_SIGNAL_FEEDS,
    EXPLOIT_FEEDS,
    NATIONAL_CERT_FEEDS,
    SUPPLY_CHAIN_FEEDS,
    THREAT_ACTOR_FEEDS,
    ExploitIntelligence,
    FeedCategory,
    FeedsService,
    GeoRegion,
    SupplyChainVuln,
    ThreatActorMapping,
)

from apps.api.dependencies import get_org_id

router = APIRouter(prefix="/api/v1/feeds", tags=["feeds"])

# Initialize service with default path
_DATA_DIR = Path("data/feeds")
_feeds_service: Optional[FeedsService] = None
_feeds_service_lock = threading.Lock()
_auto_refresh_done = False


def get_feeds_service() -> FeedsService:
    """Get or create feeds service instance (thread-safe singleton)."""
    global _feeds_service, _auto_refresh_done
    if _feeds_service is None:
        with _feeds_service_lock:
            # Double-check locking pattern
            if _feeds_service is None:
                _feeds_service = FeedsService(_DATA_DIR / "feeds.db")
                # Auto-refresh feeds in background if not done yet
                if not _auto_refresh_done:
                    _auto_refresh_done = True
                    threading.Thread(target=_auto_refresh_feeds, daemon=True).start()
    return _feeds_service


def _auto_refresh_feeds():
    """Automatically refresh EPSS and KEV feeds if empty or stale."""
    import logging

    logger = logging.getLogger(__name__)
    try:
        service = _feeds_service
        if service:
            stats = service.get_feed_stats()
            # get_feed_stats() returns nested: {"epss": {"total_cves": N}, "kev": {"total_cves": N}}
            epss_count = stats.get("epss", {}).get("total_cves", 0)
            kev_count = stats.get("kev", {}).get("total_cves", 0)

            # Refresh EPSS if empty
            if epss_count == 0:
                logger.info("Auto-refreshing EPSS feed (empty)")
                result = service.refresh_epss()
                logger.info(f"EPSS refresh: {result.records_updated} records")

            # Refresh KEV if empty
            if kev_count == 0:
                logger.info("Auto-refreshing KEV feed (empty)")
                result = service.refresh_kev()
                logger.info(f"KEV refresh: {result.records_updated} records")
    except Exception as e:
        logger.warning(f"Auto-refresh failed: {e}")


# =============================================================================
# Request/Response Models
# =============================================================================


class RefreshFeedRequest(BaseModel):
    """Request to refresh a specific feed."""

    force: bool = Field(
        default=False, description="Force refresh even if recently updated"
    )


class EnrichFindingsRequest(BaseModel):
    """Request to enrich findings with vulnerability intelligence."""

    findings: List[Dict[str, Any]]
    target_region: Optional[str] = Field(
        default="global", description="Target region for geo-weighted scoring"
    )


class AddThreatActorMappingRequest(BaseModel):
    """Request to add a threat actor to CVE mapping."""

    cve_id: str
    threat_actor: str
    campaign: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    target_sectors: Optional[List[str]] = None
    target_countries: Optional[List[str]] = None
    ttps: Optional[List[str]] = None
    confidence: str = Field(default="medium", description="low, medium, high")
    source: Optional[str] = None


class AddExploitIntelligenceRequest(BaseModel):
    """Request to add exploit intelligence for a CVE."""

    cve_id: str
    exploit_source: str
    exploit_type: Optional[str] = None
    exploit_url: Optional[str] = None
    exploit_date: Optional[str] = None
    verified: bool = False
    reliability: str = Field(
        default="unknown", description="unknown, low, medium, high"
    )
    metasploit_module: Optional[str] = None
    nuclei_template: Optional[str] = None


class AddSupplyChainVulnRequest(BaseModel):
    """Request to add a supply chain vulnerability."""

    vuln_id: str
    ecosystem: str
    package_name: str
    affected_versions: Optional[str] = None
    patched_versions: Optional[str] = None
    severity: str = Field(default="unknown")
    cvss_score: Optional[float] = None
    reachable: Optional[bool] = None
    transitive: bool = False
    source: Optional[str] = None


# =============================================================================
# EPSS Endpoints
# =============================================================================


@router.get("/epss")
def get_epss_scores(
    cve_ids: Optional[str] = Query(
        default=None, description="Comma-separated CVE IDs to lookup"
    ),
    min_score: float = Query(default=0.0, ge=0.0, le=1.0),
    limit: int = Query(default=100, le=1000),
) -> Dict[str, Any]:
    """Get EPSS scores for CVEs.

    EPSS (Exploit Prediction Scoring System) provides probability scores
    for CVE exploitation in the next 30 days.
    """
    service = get_feeds_service()

    if cve_ids:
        cve_list = [cve.strip() for cve in cve_ids.split(",")]
        scores = []
        for cve_id in cve_list[:limit]:
            score = service.get_epss_score(cve_id)
            if score and score.epss >= min_score:
                scores.append(score.to_dict())
        return {"scores": scores, "count": len(scores)}

    # Return high-risk CVEs if no specific IDs provided
    high_risk = service.get_high_risk_cves(epss_threshold=min_score, limit=limit)
    return {"scores": high_risk, "count": len(high_risk)}


@router.post("/epss/refresh")
async def refresh_epss_feed(request: RefreshFeedRequest) -> Dict[str, Any]:
    """Refresh EPSS feed from FIRST.org.

    Downloads the latest EPSS scores and updates the local database.
    """
    service = get_feeds_service()
    result = service.refresh_epss()

    # Emit EPSS updated event
    if _HAS_BRAIN:
        bus = get_event_bus()
        await bus.emit(
            Event(
                event_type=EventType.EPSS_UPDATED,
                source="feeds_router",
                data={
                    "records_updated": result.records_updated,
                    "success": result.success,
                    "feed_name": result.feed_name,
                },
            )
        )

    return {
        "status": "refreshed" if result.success else "failed",
        "records_updated": result.records_updated,
        "source": result.feed_name,
        "timestamp": result.refreshed_at,
        "error": result.error,
    }


# =============================================================================
# KEV Endpoints
# =============================================================================


@router.get("/kev")
def get_kev_entries(
    cve_ids: Optional[str] = Query(
        default=None, description="Comma-separated CVE IDs to lookup"
    ),
    limit: int = Query(default=100, le=1000),
) -> Dict[str, Any]:
    """Get CISA Known Exploited Vulnerabilities (KEV) entries.

    KEV catalog contains vulnerabilities with confirmed active exploitation.
    """
    service = get_feeds_service()

    if cve_ids:
        cve_list = [cve.strip() for cve in cve_ids.split(",")]
        entries = []
        for cve_id in cve_list[:limit]:
            entry = service.get_kev_entry(cve_id)
            if entry:
                entries.append(entry.to_dict())
        return {"entries": entries, "count": len(entries)}

    # Return all KEV entries with correct nested key access
    stats = service.get_feed_stats()
    return {
        "message": "Use cve_ids parameter to lookup specific CVEs",
        "total_kev_entries": stats.get("kev", {}).get("total_cves", 0),
    }


@router.post("/kev/refresh")
async def refresh_kev_feed(request: RefreshFeedRequest) -> Dict[str, Any]:
    """Refresh KEV feed from CISA.

    Downloads the latest Known Exploited Vulnerabilities catalog.
    """
    service = get_feeds_service()
    result = service.refresh_kev()

    # Emit KEV alert event
    if _HAS_BRAIN:
        bus = get_event_bus()
        await bus.emit(
            Event(
                event_type=EventType.KEV_ALERT,
                source="feeds_router",
                data={
                    "records_updated": result.records_updated,
                    "success": result.success,
                    "feed_name": result.feed_name,
                },
            )
        )

    return {
        "status": "refreshed" if result.success else "failed",
        "records_updated": result.records_updated,
        "source": result.feed_name,
        "timestamp": result.refreshed_at,
        "error": result.error,
    }


# =============================================================================
# NVD CVE Endpoints
# =============================================================================


@router.post("/nvd/refresh")
async def refresh_nvd_feed(
    days: int = Query(default=7, ge=1, le=90),
) -> Dict[str, Any]:
    """Refresh NVD CVE data from NIST NVD 2.0 API.

    Downloads recent CVEs published/modified in the last N days.
    """
    service = get_feeds_service()
    result = service.refresh_nvd(days=days)

    if _HAS_BRAIN:
        bus = get_event_bus()
        await bus.emit(
            Event(
                event_type=EventType.FEED_UPDATED,
                source="feeds_router",
                data={
                    "records_updated": result.records_updated,
                    "success": result.success,
                    "feed_name": "nvd",
                },
            )
        )

    return {
        "status": "refreshed" if result.success else "failed",
        "records_updated": result.records_updated,
        "source": result.feed_name,
        "timestamp": result.refreshed_at,
        "error": result.error,
    }


@router.get("/nvd/recent")
def get_recent_nvd_cves(
    severity: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """Get recent NVD CVEs from local database.

    Optionally filter by severity (CRITICAL, HIGH, MEDIUM, LOW).
    """
    service = get_feeds_service()
    cves = service.get_recent_nvd_cves(severity=severity, limit=limit, offset=offset)
    return {
        "cves": cves,
        "count": len(cves),
        "severity_filter": severity,
    }


@router.get("/nvd/{cve_id}")
def get_nvd_cve(cve_id: str) -> Dict[str, Any]:
    """Get detailed NVD CVE data by CVE ID."""
    service = get_feeds_service()
    cve = service.get_nvd_cve(cve_id)
    if not cve:
        raise HTTPException(
            status_code=404, detail=f"CVE {cve_id} not found in NVD cache"
        )
    return cve


# =============================================================================
# ExploitDB Endpoints
# =============================================================================


@router.post("/exploitdb/refresh")
async def refresh_exploitdb_feed() -> Dict[str, Any]:
    """Refresh ExploitDB from GitLab mirror CSV.

    Downloads the full Exploit-DB database and updates local cache.
    """
    service = get_feeds_service()
    result = service.refresh_exploitdb()

    if _HAS_BRAIN:
        bus = get_event_bus()
        await bus.emit(
            Event(
                event_type=EventType.FEED_UPDATED,
                source="feeds_router",
                data={
                    "records_updated": result.records_updated,
                    "success": result.success,
                    "feed_name": "exploitdb",
                },
            )
        )

    return {
        "status": "refreshed" if result.success else "failed",
        "records_updated": result.records_updated,
        "source": result.feed_name,
        "timestamp": result.refreshed_at,
        "error": result.error,
    }


# =============================================================================
# OSV Endpoints
# =============================================================================


@router.post("/osv/refresh")
async def refresh_osv_feed(
    ecosystems: Optional[str] = Query(
        default=None,
        description="Comma-separated ecosystems (e.g. PyPI,npm,Go). Default: PyPI,npm,Go,Maven,crates.io",
    ),
) -> Dict[str, Any]:
    """Refresh OSV (Open Source Vulnerabilities) data from Google OSV.dev.

    Fetches vulnerability data for specified ecosystems.
    """
    service = get_feeds_service()
    eco_list = ecosystems.split(",") if ecosystems else None
    result = service.refresh_osv(ecosystems=eco_list)

    if _HAS_BRAIN:
        bus = get_event_bus()
        await bus.emit(
            Event(
                event_type=EventType.FEED_UPDATED,
                source="feeds_router",
                data={
                    "records_updated": result.records_updated,
                    "success": result.success,
                    "feed_name": "osv",
                },
            )
        )

    return {
        "status": "refreshed" if result.success else "failed",
        "records_updated": result.records_updated,
        "source": result.feed_name,
        "timestamp": result.refreshed_at,
        "error": result.error,
    }


# =============================================================================
# GitHub Advisory Endpoints
# =============================================================================


@router.post("/github/refresh")
async def refresh_github_advisories_feed() -> Dict[str, Any]:
    """Refresh GitHub Security Advisories from GitHub Advisory Database.

    Fetches the latest reviewed advisories via the REST API.
    """
    service = get_feeds_service()
    result = service.refresh_github_advisories()

    if _HAS_BRAIN:
        bus = get_event_bus()
        await bus.emit(
            Event(
                event_type=EventType.FEED_UPDATED,
                source="feeds_router",
                data={
                    "records_updated": result.records_updated,
                    "success": result.success,
                    "feed_name": "github_advisories",
                },
            )
        )

    return {
        "status": "refreshed" if result.success else "failed",
        "records_updated": result.records_updated,
        "source": result.feed_name,
        "timestamp": result.refreshed_at,
        "error": result.error,
    }


# =============================================================================
# Exploit Intelligence Endpoints
# =============================================================================


@router.get("/exploits")
def list_all_exploits(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List all known exploits in the database.

    Returns exploits from Exploit-DB, Metasploit, Nuclei templates, etc.
    """
    service = get_feeds_service()
    # Get all exploits from the database
    try:
        all_exploits = service.get_all_exploits(limit=limit, offset=offset)
    except AttributeError:
        # Fallback if get_all_exploits not implemented
        all_exploits = []
    return {
        "exploits": all_exploits,
        "count": len(all_exploits),
        "limit": limit,
        "offset": offset,
    }


@router.get("/exploits/{cve_id}")
def get_exploits_for_cve(cve_id: str) -> Dict[str, Any]:
    """Get exploit intelligence for a specific CVE.

    Returns known exploits from Exploit-DB, Metasploit, Nuclei templates, etc.
    """
    service = get_feeds_service()
    exploits = service.get_exploits_for_cve(cve_id)
    return {"cve_id": cve_id, "exploits": exploits, "count": len(exploits)}


@router.post("/exploits")
def add_exploit_intelligence(request: AddExploitIntelligenceRequest) -> Dict[str, Any]:
    """Add exploit intelligence for a CVE."""
    service = get_feeds_service()
    exploit = ExploitIntelligence(
        cve_id=request.cve_id,
        exploit_source=request.exploit_source,
        exploit_type=request.exploit_type,
        exploit_url=request.exploit_url,
        exploit_date=request.exploit_date,
        verified=request.verified,
        reliability=request.reliability,
        metasploit_module=request.metasploit_module,
        nuclei_template=request.nuclei_template,
    )
    service.add_exploit_intelligence(exploit)
    return {"status": "added", "cve_id": request.cve_id}


# =============================================================================
# Threat Actor Endpoints
# =============================================================================


@router.get("/threat-actors")
def list_all_threat_actors(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List all known threat actors in the database.

    Returns threat actors/APT groups with their associated CVEs.
    """
    service = get_feeds_service()
    try:
        all_actors = service.get_all_threat_actors(limit=limit, offset=offset)
    except AttributeError:
        # Fallback if get_all_threat_actors not implemented
        all_actors = []
    return {
        "threat_actors": all_actors,
        "count": len(all_actors),
        "limit": limit,
        "offset": offset,
    }


@router.get("/threat-actors/{cve_id}")
def get_threat_actors_for_cve(cve_id: str) -> Dict[str, Any]:
    """Get threat actor mappings for a specific CVE.

    Returns known threat actors/APT groups that have used this CVE.
    """
    service = get_feeds_service()
    actors = service.get_threat_actors_for_cve(cve_id)
    return {"cve_id": cve_id, "threat_actors": actors, "count": len(actors)}


@router.get("/threat-actors/by-actor/{actor}")
def get_cves_by_threat_actor(actor: str) -> Dict[str, Any]:
    """Get CVEs used by a specific threat actor.

    Reverse lookup to find all CVEs associated with a threat actor/APT group.
    """
    service = get_feeds_service()
    cves = service.get_cves_by_threat_actor(actor)
    return {"threat_actor": actor, "cves": cves, "count": len(cves)}


@router.post("/threat-actors")
def add_threat_actor_mapping(request: AddThreatActorMappingRequest) -> Dict[str, Any]:
    """Add a threat actor to CVE mapping."""
    service = get_feeds_service()
    mapping = ThreatActorMapping(
        cve_id=request.cve_id,
        threat_actor=request.threat_actor,
        campaign=request.campaign,
        first_seen=request.first_seen,
        last_seen=request.last_seen,
        target_sectors=request.target_sectors or [],
        target_countries=request.target_countries or [],
        ttps=request.ttps or [],
        confidence=request.confidence,
        source=request.source,
    )
    service.add_threat_actor_mapping(mapping)
    return {
        "status": "added",
        "cve_id": request.cve_id,
        "threat_actor": request.threat_actor,
    }


# =============================================================================
# Supply Chain Endpoints
# =============================================================================


@router.get("/supply-chain")
def list_supply_chain_vulns(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    ecosystem: Optional[str] = Query(default=None, description="Filter by ecosystem"),
) -> Dict[str, Any]:
    """List all known supply chain vulnerabilities in the database.

    Returns vulnerabilities from OSV, GitHub Advisory, Snyk, etc.
    """
    service = get_feeds_service()
    try:
        all_vulns = service.get_all_supply_chain_vulns(
            limit=limit, offset=offset, ecosystem=ecosystem
        )
    except AttributeError:
        # Fallback if method not implemented
        all_vulns = []
    return {
        "vulnerabilities": all_vulns,
        "count": len(all_vulns),
        "limit": limit,
        "offset": offset,
        "ecosystem": ecosystem,
    }


@router.get("/supply-chain/{package}")
def get_supply_chain_vulns(
    package: str,
    ecosystem: Optional[str] = Query(
        default=None, description="Package ecosystem (npm, pypi, maven, etc.)"
    ),
) -> Dict[str, Any]:
    """Get supply chain vulnerabilities for a package.

    Returns vulnerabilities from OSV, GitHub Advisory, Snyk, etc.
    """
    service = get_feeds_service()
    vulns = service.get_vulns_for_package(package, ecosystem)
    return {
        "package": package,
        "ecosystem": ecosystem,
        "vulnerabilities": vulns,
        "count": len(vulns),
    }


@router.post("/supply-chain")
def add_supply_chain_vuln(request: AddSupplyChainVulnRequest) -> Dict[str, Any]:
    """Add a supply chain vulnerability."""
    service = get_feeds_service()
    vuln = SupplyChainVuln(
        vuln_id=request.vuln_id,
        ecosystem=request.ecosystem,
        package_name=request.package_name,
        affected_versions=request.affected_versions,
        patched_versions=request.patched_versions,
        severity=request.severity,
        cvss_score=request.cvss_score,
        reachable=request.reachable,
        transitive=request.transitive,
        source=request.source,
    )
    service.add_supply_chain_vuln(vuln)
    return {
        "status": "added",
        "vuln_id": request.vuln_id,
        "package": request.package_name,
    }


# =============================================================================
# Exploit Confidence & Geo-Weighted Risk Endpoints
# =============================================================================


@router.get("/exploit-confidence/{cve_id}")
def get_exploit_confidence(cve_id: str) -> Dict[str, Any]:
    """Get exploit confidence score for a CVE.

    Exploit confidence is calculated based on:
    - EPSS score (25%)
    - KEV presence (30%)
    - Exploit availability (15%)
    - Metasploit module (10%)
    - Nuclei template (5%)
    - Verified exploit (5%)
    - Threat actor use (10%)
    """
    service = get_feeds_service()

    # Try to get cached score first
    cached = service.get_exploit_confidence(cve_id)
    if cached:
        # Handle both dict and object returns
        if hasattr(cached, "to_dict"):
            return cached.to_dict()
        return cached

    # Calculate fresh score
    score = service.calculate_exploit_confidence(cve_id)
    if score:
        return score.to_dict()

    return {
        "cve_id": cve_id,
        "confidence_score": 0.0,
        "factors": {},
        "message": "No intelligence data available for this CVE",
    }


@router.get("/geo-risk/{cve_id}")
def get_geo_weighted_risk(
    cve_id: str,
    region: str = Query(
        default="global",
        description="Target region: global, north_america, europe, asia_pacific, middle_east, latin_america",
    ),
) -> Dict[str, Any]:
    """Get geo-weighted risk score for a CVE.

    Risk scores are adjusted based on regional exploitation patterns
    from national CERT advisories.
    """
    service = get_feeds_service()

    # Validate region
    try:
        target_region = GeoRegion(region)
    except ValueError:
        valid_regions = [r.value for r in GeoRegion]
        raise HTTPException(
            status_code=400,
            detail=f"Invalid region. Must be one of: {valid_regions}",
        )

    score = service.calculate_geo_weighted_risk(cve_id, target_region)
    if score:
        return score.to_dict()

    return {
        "cve_id": cve_id,
        "base_score": 0.0,
        "geo_scores": {},
        "cert_mentions": [],
        "message": "No intelligence data available for this CVE",
    }


# =============================================================================
# Enrichment Endpoints
# =============================================================================


@router.post("/enrich")
async def enrich_findings(request: EnrichFindingsRequest) -> Dict[str, Any]:
    """Comprehensive finding enrichment with all intelligence sources.

    Enriches findings with:
    - EPSS scores
    - KEV status
    - Exploit intelligence
    - Threat actor mappings
    - Geo-weighted risk scores
    - Supply chain context
    """
    service = get_feeds_service()

    # Validate region
    try:
        target_region = GeoRegion(request.target_region or "global")
    except ValueError:
        target_region = GeoRegion.GLOBAL

    enriched = service.enrich_findings_comprehensive(request.findings, target_region)

    # Emit feed updated event for enrichment
    if _HAS_BRAIN:
        bus = get_event_bus()
        brain = get_brain()
        await bus.emit(
            Event(
                event_type=EventType.FEED_UPDATED,
                source="feeds_router.enrich",
                data={
                    "findings_enriched": len(enriched),
                    "target_region": target_region.value,
                },
            )
        )
        # Ingest enriched CVEs into brain
        for finding in enriched:
            cve_id = finding.get("cve_id") or finding.get("id")
            if cve_id:
                brain.ingest_cve(
                    cve_id,
                    severity=finding.get("severity", "unknown"),
                    source="feeds_enrichment",
                    epss_score=finding.get("epss_score"),
                )

    return {
        "enriched_findings": enriched,
        "count": len(enriched),
        "target_region": target_region.value,
    }


# =============================================================================
# Statistics & Health Endpoints
# =============================================================================


@router.get("/stats")
def get_feed_stats(org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Get comprehensive statistics across all feed categories.

    Returns both detailed category stats and frontend-friendly summary.
    """
    service = get_feeds_service()
    comp = service.get_comprehensive_stats()
    basic = service.get_feed_stats()

    # Add frontend-friendly top-level fields
    epss_count = basic.get("epss", {}).get("total_cves", 0)
    kev_count = basic.get("kev", {}).get("total_cves", 0)
    total_unique = comp.get("totals", {}).get("unique_cves", 0)
    last_refresh = basic.get("epss", {}).get("last_refresh") or basic.get(
        "kev", {}
    ).get("last_refresh")

    comp["total_cves"] = total_unique or (epss_count + kev_count)
    comp["new_today"] = 0  # Would need date filtering
    comp["sources"] = {
        "EPSS": epss_count,
        "KEV": kev_count,
        "NVD": comp.get("categories", {}).get("authoritative", {}).get("nvd_cves", 0),
        "ExploitDB": comp.get("categories", {})
        .get("exploit", {})
        .get("exploit_intelligence", 0),
        "OSV": comp.get("categories", {})
        .get("supply_chain", {})
        .get("supply_chain_vulns", 0),
    }
    comp["last_refresh"] = last_refresh
    return comp


@router.get("/categories")
def list_feed_categories() -> Dict[str, Any]:
    """List all feed categories and their sources."""
    return {
        "categories": [
            {
                "id": FeedCategory.AUTHORITATIVE.value,
                "name": "Global Authoritative Sources",
                "description": "Ground truth CVE sources (NVD, CISA KEV, MITRE)",
                "sources": list(AUTHORITATIVE_FEEDS.keys()),
            },
            {
                "id": FeedCategory.NATIONAL_CERT.value,
                "name": "National CERTs",
                "description": "Geo-specific exploit intelligence from national CERTs",
                "sources": list(NATIONAL_CERT_FEEDS.keys()),
            },
            {
                "id": FeedCategory.EXPLOIT.value,
                "name": "Exploit & Weaponization Intelligence",
                "description": "Real-world exploit availability and weaponization",
                "sources": list(EXPLOIT_FEEDS.keys()),
            },
            {
                "id": FeedCategory.THREAT_ACTOR.value,
                "name": "Threat Actor Intelligence",
                "description": "APT groups and campaign tracking",
                "sources": list(THREAT_ACTOR_FEEDS.keys()),
            },
            {
                "id": FeedCategory.SUPPLY_CHAIN.value,
                "name": "Supply-Chain & SBOM Intelligence",
                "description": "Open source and dependency vulnerabilities",
                "sources": list(SUPPLY_CHAIN_FEEDS.keys()),
            },
            {
                "id": FeedCategory.CLOUD_RUNTIME.value,
                "name": "Cloud & Runtime Vulnerability Feeds",
                "description": "Cloud provider security bulletins",
                "sources": list(CLOUD_RUNTIME_FEEDS.keys()),
            },
            {
                "id": FeedCategory.EARLY_SIGNAL.value,
                "name": "Zero-Day & Early-Signal Feeds",
                "description": "Pre-CVE and emerging threat signals",
                "sources": list(EARLY_SIGNAL_FEEDS.keys()),
            },
            {
                "id": FeedCategory.ENTERPRISE.value,
                "name": "Internal Enterprise Signals",
                "description": "SAST/DAST/SCA, IaC, runtime detections",
                "sources": ["sast", "dast", "sca", "iac", "runtime", "exposure_graph"],
            },
        ]
    }


@router.get("/sources")
def list_feed_sources() -> Dict[str, Any]:
    """List all configured feed sources with their URLs and refresh intervals."""
    all_sources = {}

    for name, config in AUTHORITATIVE_FEEDS.items():
        all_sources[name] = {**config, "category": FeedCategory.AUTHORITATIVE.value}

    for name, config in NATIONAL_CERT_FEEDS.items():
        all_sources[name] = {**config, "category": FeedCategory.NATIONAL_CERT.value}

    for name, config in EXPLOIT_FEEDS.items():
        all_sources[name] = {**config, "category": FeedCategory.EXPLOIT.value}

    for name, config in THREAT_ACTOR_FEEDS.items():
        all_sources[name] = {**config, "category": FeedCategory.THREAT_ACTOR.value}

    for name, config in SUPPLY_CHAIN_FEEDS.items():
        all_sources[name] = {**config, "category": FeedCategory.SUPPLY_CHAIN.value}

    for name, config in CLOUD_RUNTIME_FEEDS.items():
        all_sources[name] = {**config, "category": FeedCategory.CLOUD_RUNTIME.value}

    for name, config in EARLY_SIGNAL_FEEDS.items():
        all_sources[name] = {**config, "category": FeedCategory.EARLY_SIGNAL.value}

    return {"sources": all_sources, "count": len(all_sources)}


@router.get("/health")
def get_feed_health() -> Dict[str, Any]:
    """Get feed health and freshness status."""
    service = get_feeds_service()
    stats = service.get_feed_stats()

    # get_feed_stats() returns nested structure: {"epss": {"total_cves": N}, "kev": {"total_cves": N}, ...}
    epss_data = stats.get("epss", {})
    kev_data = stats.get("kev", {})

    # Quick lightweight counts instead of expensive get_comprehensive_stats()
    import sqlite3 as _sql

    cats: Dict[str, Any] = {
        "authoritative": {},
        "exploit": {},
        "supply_chain": {},
        "threat_actor": {},
    }
    try:
        conn = _sql.connect(service.db_path)
        cur = conn.cursor()
        for table, cat, key in [
            ("nvd_cves", "authoritative", "nvd_cves"),
            ("exploit_intelligence", "exploit", "exploit_intelligence"),
            ("supply_chain_vulns", "supply_chain", "supply_chain_vulns"),
            ("threat_actor_mappings", "threat_actor", "threat_actor_mappings"),
        ]:
            try:
                cur.execute(f"SELECT COUNT(*) FROM {table}")
                cats[cat][key] = cur.fetchone()[0]
            except _sql.OperationalError:
                cats[cat][key] = 0
        conn.close()
    except Exception:
        pass

    epss_count = epss_data.get("total_cves", 0)
    kev_count = kev_data.get("total_cves", 0)

    # Build per-feed status list for frontend
    feeds_list = [
        {
            "name": "EPSS",
            "status": "healthy" if epss_count > 0 else "stale",
            "total_records": epss_count,
            "new_today": 0,
            "latency_ms": 0,
            "last_update": epss_data.get("last_refresh"),
        },
        {
            "name": "KEV",
            "status": "healthy" if kev_count > 0 else "stale",
            "total_records": kev_count,
            "new_today": 0,
            "latency_ms": 0,
            "last_update": kev_data.get("last_refresh"),
        },
        {
            "name": "NVD",
            "status": "healthy"
            if cats.get("authoritative", {}).get("nvd_cves", 0) > 0
            else "stale",
            "total_records": cats.get("authoritative", {}).get("nvd_cves", 0),
            "new_today": 0,
            "latency_ms": 0,
            "last_update": None,
        },
        {
            "name": "ExploitDB",
            "status": "healthy"
            if cats.get("exploit", {}).get("exploit_intelligence", 0) > 0
            else "stale",
            "total_records": cats.get("exploit", {}).get("exploit_intelligence", 0),
            "new_today": 0,
            "latency_ms": 0,
            "last_update": None,
        },
        {
            "name": "OSV",
            "status": "healthy"
            if cats.get("supply_chain", {}).get("supply_chain_vulns", 0) > 0
            else "stale",
            "total_records": cats.get("supply_chain", {}).get("supply_chain_vulns", 0),
            "new_today": 0,
            "latency_ms": 0,
            "last_update": None,
        },
        {
            "name": "GitHub",
            "status": "healthy"
            if cats.get("supply_chain", {}).get("supply_chain_vulns", 0) > 0
            else "stale",
            "total_records": cats.get("supply_chain", {}).get("supply_chain_vulns", 0),
            "new_today": 0,
            "latency_ms": 0,
            "last_update": None,
        },
    ]

    return {
        "status": "healthy" if (epss_count + kev_count) > 0 else "degraded",
        "feeds": feeds_list,
        "epss": {
            "count": epss_count,
            "last_updated": epss_data.get("last_refresh"),
        },
        "kev": {
            "count": kev_count,
            "last_updated": kev_data.get("last_refresh"),
        },
        "exploit_intelligence": {
            "count": cats.get("exploit", {}).get("exploit_intelligence", 0),
        },
        "threat_actors": {
            "count": cats.get("threat_actor", {}).get("threat_actor_mappings", 0),
        },
        "supply_chain": {
            "count": cats.get("supply_chain", {}).get("supply_chain_vulns", 0),
        },
    }


@router.get("/scheduler/status")
def get_scheduler_status() -> Dict[str, Any]:
    """Get feed scheduler status.

    Note: The scheduler runs as a background task when enabled.
    Use the /refresh endpoints to manually trigger feed updates.
    """
    return {
        "status": "available",
        "message": "Feed scheduler is available. Use /refresh endpoints to trigger updates.",
        "refresh_endpoints": [
            "/api/v1/feeds/epss/refresh",
            "/api/v1/feeds/kev/refresh",
        ],
        "note": "Background scheduler can be started via FeedsService.scheduler() method",
    }


@router.post("/refresh")
async def refresh_feeds_alias(
    include_nvd: bool = Query(default=True, description="Include NVD feed"),
    include_exploitdb: bool = Query(default=True, description="Include ExploitDB feed"),
    include_osv: bool = Query(default=True, description="Include OSV feed"),
    include_github: bool = Query(default=True, description="Include GitHub Advisories"),
) -> Dict[str, Any]:
    """Alias for /refresh/all — keeps frontend happy."""
    return await refresh_all_feeds(
        include_nvd=include_nvd,
        include_exploitdb=include_exploitdb,
        include_osv=include_osv,
        include_github=include_github,
    )


@router.post("/refresh/all")
async def refresh_all_feeds(
    include_nvd: bool = Query(default=True, description="Include NVD feed"),
    include_exploitdb: bool = Query(default=True, description="Include ExploitDB feed"),
    include_osv: bool = Query(default=True, description="Include OSV feed"),
    include_github: bool = Query(default=True, description="Include GitHub Advisories"),
) -> Dict[str, Any]:
    """Refresh all primary feeds (EPSS, KEV, NVD, ExploitDB, OSV, GitHub Advisories).

    Each feed can be selectively enabled/disabled via query parameters.
    """
    service = get_feeds_service()

    results = {}

    # Always refresh EPSS and KEV (fast, authoritative)
    epss_result = service.refresh_epss()
    results["epss"] = {
        "success": epss_result.success,
        "records_updated": epss_result.records_updated,
        "error": epss_result.error,
    }

    kev_result = service.refresh_kev()
    results["kev"] = {
        "success": kev_result.success,
        "records_updated": kev_result.records_updated,
        "error": kev_result.error,
    }

    # NVD — NIST National Vulnerability Database
    if include_nvd:
        nvd_result = service.refresh_nvd(days=7)
        results["nvd"] = {
            "success": nvd_result.success,
            "records_updated": nvd_result.records_updated,
            "error": nvd_result.error,
        }

    # ExploitDB — public exploit database
    if include_exploitdb:
        exploitdb_result = service.refresh_exploitdb()
        results["exploitdb"] = {
            "success": exploitdb_result.success,
            "records_updated": exploitdb_result.records_updated,
            "error": exploitdb_result.error,
        }

    # OSV — Google Open Source Vulnerabilities
    if include_osv:
        osv_result = service.refresh_osv()
        results["osv"] = {
            "success": osv_result.success,
            "records_updated": osv_result.records_updated,
            "error": osv_result.error,
        }

    # GitHub Security Advisories
    if include_github:
        github_result = service.refresh_github_advisories()
        results["github_advisories"] = {
            "success": github_result.success,
            "records_updated": github_result.records_updated,
            "error": github_result.error,
        }

    all_success = all(r.get("success", False) for r in results.values())
    total_records = sum(r.get("records_updated", 0) for r in results.values())

    # Emit feed updated events
    if _HAS_BRAIN:
        bus = get_event_bus()
        await bus.emit(
            Event(
                event_type=EventType.FEED_UPDATED,
                source="feeds_router.refresh_all",
                data={
                    "results": results,
                    "all_success": all_success,
                    "total_records": total_records,
                },
            )
        )

    return {
        "status": "completed" if all_success else "partial",
        "feeds_refreshed": len(results),
        "total_records_updated": total_records,
        "results": results,
    }
