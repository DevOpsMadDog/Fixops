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

# Import from fixops-enterprise using relative path
# Note: fixops-enterprise should be installed as a package or added to PYTHONPATH
# This import assumes the package is properly installed
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

ENTERPRISE_SRC = Path(__file__).resolve().parent.parent.parent / "fixops-enterprise"
if ENTERPRISE_SRC.exists() and str(ENTERPRISE_SRC) not in sys.path:
    sys.path.insert(0, str(ENTERPRISE_SRC))

from src.services.feeds_service import (
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

router = APIRouter(prefix="/api/v1/feeds", tags=["feeds"])

# Initialize service with default path
_DATA_DIR = Path("data/feeds")
_feeds_service: Optional[FeedsService] = None
_feeds_service_lock = threading.Lock()


def get_feeds_service() -> FeedsService:
    """Get or create feeds service instance (thread-safe singleton)."""
    global _feeds_service
    if _feeds_service is None:
        with _feeds_service_lock:
            # Double-check locking pattern
            if _feeds_service is None:
                _feeds_service = FeedsService(_DATA_DIR / "feeds.db")
    return _feeds_service


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
def refresh_epss_feed(request: RefreshFeedRequest) -> Dict[str, Any]:
    """Refresh EPSS feed from FIRST.org.

    Downloads the latest EPSS scores and updates the local database.
    """
    service = get_feeds_service()
    result = service.refresh_epss()
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

    # Return all KEV entries
    stats = service.get_feed_stats()
    return {
        "message": "Use cve_ids parameter to lookup specific CVEs",
        "total_kev_entries": stats.get("kev_count", 0),
    }


@router.post("/kev/refresh")
def refresh_kev_feed(request: RefreshFeedRequest) -> Dict[str, Any]:
    """Refresh KEV feed from CISA.

    Downloads the latest Known Exploited Vulnerabilities catalog.
    """
    service = get_feeds_service()
    result = service.refresh_kev()
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
def enrich_findings(request: EnrichFindingsRequest) -> Dict[str, Any]:
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
    return {
        "enriched_findings": enriched,
        "count": len(enriched),
        "target_region": target_region.value,
    }


# =============================================================================
# Statistics & Health Endpoints
# =============================================================================


@router.get("/stats")
def get_feed_stats() -> Dict[str, Any]:
    """Get comprehensive statistics across all feed categories."""
    service = get_feeds_service()
    return service.get_comprehensive_stats()


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

    return {
        "status": "healthy",
        "epss": {
            "count": stats.get("epss_count", 0),
            "last_updated": stats.get("epss_last_updated"),
        },
        "kev": {
            "count": stats.get("kev_count", 0),
            "last_updated": stats.get("kev_last_updated"),
        },
        "exploit_intelligence": {
            "count": stats.get("exploit_count", 0),
        },
        "threat_actors": {
            "count": stats.get("threat_actor_count", 0),
        },
        "supply_chain": {
            "count": stats.get("supply_chain_count", 0),
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


@router.post("/refresh/all")
def refresh_all_feeds() -> Dict[str, Any]:
    """Refresh all primary feeds (EPSS and KEV).

    Note: Other feed categories require API keys or manual data ingestion.
    """
    service = get_feeds_service()

    results = {}

    # Refresh EPSS
    epss_result = service.refresh_epss()
    results["epss"] = {
        "success": epss_result.success,
        "records_updated": epss_result.records_updated,
        "error": epss_result.error,
    }

    # Refresh KEV
    kev_result = service.refresh_kev()
    results["kev"] = {
        "success": kev_result.success,
        "records_updated": kev_result.records_updated,
        "error": kev_result.error,
    }

    all_success = all(r.get("success", False) for r in results.values())
    return {
        "status": "completed" if all_success else "partial",
        "results": results,
    }
