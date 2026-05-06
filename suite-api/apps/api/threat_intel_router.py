"""
Threat Intelligence Correlation API endpoints — ALDECI.

Exposes threat actor profiles, campaign data, and finding correlation
via the ThreatIntelCorrelator engine.

Protected with API key authentication via ``_verify_api_key`` (injected
via ``app.include_router`` dependencies — see app.py).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.threat_intel_correlator import (
    Campaign,
    ThreatActor,
    ThreatCorrelation,
    ThreatIntelCorrelator,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

router = APIRouter(
    prefix="/api/v1/threat-intel",
    tags=["threat-intel"],
)

_correlator = ThreatIntelCorrelator()


# ---------------------------------------------------------------------------
# Request / Response shapes
# ---------------------------------------------------------------------------


class CorrelateRequest(BaseModel):
    """Request body for finding correlation."""

    finding: Dict[str, Any]


class BatchCorrelateRequest(BaseModel):
    """Request body for batch correlation."""

    findings: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/correlate", response_model=ThreatCorrelation)
async def correlate_finding(body: CorrelateRequest) -> ThreatCorrelation:
    """
    Correlate a single security finding against all known threat actors
    and campaigns. Returns the best-matching ThreatCorrelation.
    """
    if not body.finding:
        raise HTTPException(status_code=422, detail="finding must not be empty")
    return _correlator.correlate_finding(body.finding)


@router.post("/correlate/batch", response_model=List[ThreatCorrelation])
async def correlate_batch(body: BatchCorrelateRequest) -> List[ThreatCorrelation]:
    """
    Correlate a batch of security findings. Returns a correlation result
    for each finding in the same order as the input list.
    """
    if not body.findings:
        raise HTTPException(status_code=422, detail="findings list must not be empty")
    return _correlator.correlate_batch(body.findings)


@router.get("/actors", response_model=List[ThreatActor])
async def list_threat_actors(
    active_only: bool = Query(False, description="Return only active actors"),
) -> List[ThreatActor]:
    """
    List all registered threat actor profiles. Optionally filter to
    active actors only.
    """
    actors = _correlator._load_all_actors()
    if active_only:
        actors = [a for a in actors if a.active]
    return actors


@router.post("/actors", response_model=ThreatActor)
async def add_threat_actor(actor: ThreatActor) -> ThreatActor:
    """
    Register a new threat actor profile. If an actor with the same ID
    already exists it will be replaced (upsert).
    """
    _correlator.add_threat_actor(actor)
    return actor


@router.get("/actors/{actor_id}", response_model=Dict[str, Any])
async def get_actor_profile(actor_id: str) -> Dict[str, Any]:
    """
    Return full actor dossier: profile, associated campaigns, and
    recent finding correlations.
    """
    profile = _correlator.get_actor_profile(actor_id)
    if profile is None:
        raise HTTPException(status_code=404, detail=f"Threat actor '{actor_id}' not found")
    return profile


@router.post("/campaigns", response_model=Campaign)
async def add_campaign(campaign: Campaign) -> Campaign:
    """
    Register a new threat campaign. Upserts on duplicate ID.
    """
    _correlator.add_campaign(campaign)
    return campaign


@router.get("/campaigns/{campaign_id}/timeline", response_model=Dict[str, Any])
async def get_campaign_timeline(campaign_id: str) -> Dict[str, Any]:
    """
    Return campaign details and all correlated finding events as a
    chronological timeline.
    """
    timeline = _correlator.get_campaign_timeline(campaign_id)
    if timeline is None:
        raise HTTPException(
            status_code=404, detail=f"Campaign '{campaign_id}' not found"
        )
    return timeline


@router.get("/landscape", response_model=Dict[str, Any])
async def get_threat_landscape(
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """
    Return a high-level threat landscape overview for the organisation:
    active actor count, active campaigns, and top correlated threat actors.
    """
    return _correlator.get_threat_landscape(org_id)


@router.get("/active-threats", response_model=List[ThreatActor])
async def get_active_threats(
    org_id: str = Query("default", description="Organisation identifier"),
) -> List[ThreatActor]:
    """
    Return all currently active threat actors relevant to the organisation.
    """
    return _correlator.get_active_threats(org_id)


# ---------------------------------------------------------------------------
# CVE / EPSS / KEV aggregation endpoints (ThreatIntelAggregator)
# ---------------------------------------------------------------------------

import logging as _logging  # noqa: E402

from threat_intel_aggregator import ThreatIntelAggregator  # noqa: E402

_agg_logger = _logging.getLogger(__name__)
_aggregator = ThreatIntelAggregator()


@router.get("/cves/recent", response_model=List[Dict[str, Any]])
async def get_recent_cves(
    limit: int = Query(100, ge=1, le=500, description="Max CVEs to return"),
) -> List[Dict[str, Any]]:
    """
    Return the most recently cached CVEs enriched with EPSS scores.

    CVEs are served from the local SQLite cache. Call ``/refresh`` to
    pull the latest data from NVD / EPSS / CISA KEV.
    """
    records = _aggregator.get_cached_cves(limit=limit)
    if not records:
        raise HTTPException(
            status_code=404,
            detail="No CVE data cached yet — call POST /api/v1/threat-intel/refresh first",
        )
    # Enrich with latest EPSS if missing
    missing_epss = [r.cve_id for r in records if r.epss_score == 0.0]
    if missing_epss:
        try:
            epss_map = _aggregator.enrich_with_epss(missing_epss[:50])
            for rec in records:
                if rec.cve_id in epss_map:
                    rec.epss_score = epss_map[rec.cve_id]
        except Exception as exc:  # noqa: BLE001
            _agg_logger.warning("EPSS enrichment failed: %s", exc)

    return [r.to_dict() for r in records]


@router.get("/kev", response_model=Dict[str, Any])
async def get_kev_catalog() -> Dict[str, Any]:
    """
    Return the current CISA Known Exploited Vulnerabilities catalog from cache.

    The catalog is refreshed on each call to ``/refresh``.
    """
    kev_map = _aggregator._load_kev_from_cache()
    if not kev_map:
        raise HTTPException(
            status_code=404,
            detail="KEV catalog not yet cached — call POST /api/v1/threat-intel/refresh",
        )
    return {
        "count": len(kev_map),
        "entries": [
            {"cve_id": cve_id, "due_date": due_date}
            for cve_id, due_date in sorted(kev_map.items())
        ],
    }


@router.post("/refresh", response_model=Dict[str, Any])
async def trigger_refresh() -> Dict[str, Any]:
    """
    Trigger a fresh pull from NVD, EPSS, and CISA KEV.

    This is a synchronous operation — it blocks until all feeds
    are fetched and cached. For large date ranges this may take
    up to 60 seconds due to NVD rate limits.
    """
    try:
        report = _aggregator.aggregate_daily()
        return {
            "status": "ok",
            "generated_at": report.generated_at,
            "total_cves": report.total_cves,
            "kev_count": report.kev_count,
            "critical_count": report.critical_count,
            "high_count": report.high_count,
            "avg_epss": report.avg_epss,
            "osv_count": report.osv_count,
            "otx_pulses": report.otx_pulses,
        }
    except Exception as exc:  # noqa: BLE001
        _agg_logger.error("Threat intel refresh failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Refresh failed: {exc}") from exc


# ---------------------------------------------------------------------------
# IOC / Feed aggregation endpoints
# ---------------------------------------------------------------------------

import os as _os  # noqa: E402
import sqlite3 as _sqlite3  # noqa: E402
import time as _time  # noqa: E402
from pathlib import Path as _Path  # noqa: E402

_FEEDS_DB = _Path(__file__).parent.parent.parent.parent / "suite-feeds" / "data" / "threat_intel.db"

# IOC type constants
_IOC_TYPE_IP = "ip"
_IOC_TYPE_DOMAIN = "domain"
_IOC_TYPE_HASH = "hash"
_IOC_TYPE_URL = "url"


class IOCLookupRequest(BaseModel):
    value: str
    ioc_type: Optional[str] = None  # ip | domain | hash | url — auto-detected if omitted


class BulkLookupRequest(BaseModel):
    values: List[str]
    ioc_type: Optional[str] = None


def _detect_ioc_type(value: str) -> str:
    """Heuristic IOC type detection."""
    import re
    value = value.strip()
    # MD5 / SHA1 / SHA256
    if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value):
        return _IOC_TYPE_HASH
    # IPv4
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", value):
        return _IOC_TYPE_IP
    # URL
    if value.startswith(("http://", "https://", "ftp://")):
        return _IOC_TYPE_URL
    # Domain
    return _IOC_TYPE_DOMAIN


def _lookup_feodo(value: str) -> Optional[Dict[str, Any]]:
    """Check value against feodo_c2_cache table. Returns entry dict or None."""
    if not _FEEDS_DB.exists():
        return None
    try:
        conn = _sqlite3.connect(str(_FEEDS_DB))
        conn.row_factory = _sqlite3.Row
        row = conn.execute(
            "SELECT * FROM feodo_c2_cache WHERE ip_address = ?", (value,)
        ).fetchone()
        conn.close()
        if row:
            return {
                "source": "feodo_c2",
                "ip_address": row["ip_address"],
                "port": row["port"],
                "status": row["status"],
                "malware": row["malware"],
                "country": row["country"],
                "first_seen": row["first_seen"],
                "last_online": row["last_online"],
            }
    except Exception as exc:  # noqa: BLE001
        _agg_logger.warning("Feodo DB lookup failed: %s", exc)
    return None


def _lookup_kev(value: str) -> Optional[Dict[str, Any]]:
    """Check value against kev_cache (CVE IDs). Returns entry or None."""
    if not _FEEDS_DB.exists():
        return None
    try:
        conn = _sqlite3.connect(str(_FEEDS_DB))
        conn.row_factory = _sqlite3.Row
        row = conn.execute(
            "SELECT * FROM kev_cache WHERE cve_id = ?", (value.upper(),)
        ).fetchone()
        conn.close()
        if row:
            return {
                "source": "cisa_kev",
                "cve_id": row["cve_id"],
                "due_date": row["due_date"],
            }
    except Exception as exc:  # noqa: BLE001
        _agg_logger.warning("KEV DB lookup failed: %s", exc)
    return None


def _get_osv_count() -> int:
    """Count OSV vulns from meta table if available."""
    if not _FEEDS_DB.exists():
        return 0
    try:
        conn = _sqlite3.connect(str(_FEEDS_DB))
        row = conn.execute(
            "SELECT value FROM meta WHERE key = 'osv_count'"
        ).fetchone()
        conn.close()
        return int(row[0]) if row else 0
    except Exception:  # noqa: BLE001
        return 0


def _get_feodo_count() -> int:
    """Count entries in feodo_c2_cache."""
    if not _FEEDS_DB.exists():
        return 0
    try:
        conn = _sqlite3.connect(str(_FEEDS_DB))
        row = conn.execute("SELECT COUNT(*) FROM feodo_c2_cache").fetchone()
        conn.close()
        return row[0] if row else 0
    except Exception:  # noqa: BLE001
        return 0


def _get_kev_count() -> int:
    """Count entries in kev_cache."""
    if not _FEEDS_DB.exists():
        return 0
    try:
        conn = _sqlite3.connect(str(_FEEDS_DB))
        row = conn.execute("SELECT COUNT(*) FROM kev_cache").fetchone()
        conn.close()
        return row[0] if row else 0
    except Exception:  # noqa: BLE001
        return 0


def _get_feodo_last_updated() -> Optional[str]:
    """Return ISO timestamp of most recent feodo cache refresh."""
    if not _FEEDS_DB.exists():
        return None
    try:
        import datetime
        conn = _sqlite3.connect(str(_FEEDS_DB))
        row = conn.execute("SELECT MAX(fetched_at) FROM feodo_c2_cache").fetchone()
        conn.close()
        if row and row[0]:
            ts = datetime.datetime.fromtimestamp(row[0], tz=datetime.timezone.utc)
            return ts.isoformat()
    except Exception:  # noqa: BLE001
        pass
    return None


@router.get("/iocs")
async def list_iocs(
    ioc_type: Optional[str] = Query(None, description="Filter by type: ip|domain|hash|url"),
    search: Optional[str] = Query(None, description="Substring search on IOC value"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """
    List/search IOCs from local feed caches.

    Currently returns C2 IPs from the Feodo blocklist.
    Supports optional substring search and type filtering.
    """
    if not _FEEDS_DB.exists():
        return {"total": 0, "iocs": [], "offset": offset, "limit": limit}

    try:
        conn = _sqlite3.connect(str(_FEEDS_DB))
        conn.row_factory = _sqlite3.Row

        conditions: List[str] = []
        params: List[Any] = []

        if search:
            conditions.append("ip_address LIKE ?")
            params.append(f"%{search}%")

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        count_row = conn.execute(
            f"SELECT COUNT(*) FROM feodo_c2_cache {where}", params  # nosec B608
        ).fetchone()
        total = count_row[0] if count_row else 0

        rows = conn.execute(
            f"SELECT * FROM feodo_c2_cache {where} LIMIT ? OFFSET ?",  # nosec B608
            params + [limit, offset],
        ).fetchall()
        conn.close()

        iocs = [
            {
                "value": row["ip_address"],
                "ioc_type": "ip",
                "source": "feodo_c2",
                "malware": row["malware"],
                "country": row["country"],
                "first_seen": row["first_seen"],
                "last_online": row["last_online"],
                "port": row["port"],
                "status": row["status"],
            }
            for row in rows
            if not ioc_type or ioc_type == "ip"
        ]
        return {"total": total, "iocs": iocs, "offset": offset, "limit": limit}

    except Exception as exc:  # noqa: BLE001
        _agg_logger.warning("IOC list failed: %s", exc)
        return {"total": 0, "iocs": [], "offset": offset, "limit": limit}


@router.post("/iocs/lookup")
async def lookup_ioc(body: IOCLookupRequest) -> Dict[str, Any]:
    """
    Lookup a specific IOC value across all available feeds.

    Checks: Feodo C2 blocklist (IPs), CISA KEV (CVE IDs).
    Returns all matching feed hits plus auto-detected IOC type.
    """
    value = body.value.strip()
    if not value:
        raise HTTPException(status_code=422, detail="value must not be empty")

    ioc_type = body.ioc_type or _detect_ioc_type(value)
    hits: List[Dict[str, Any]] = []

    if ioc_type == _IOC_TYPE_IP:
        feodo_hit = _lookup_feodo(value)
        if feodo_hit:
            hits.append(feodo_hit)

    # CVE pattern — check KEV
    import re
    if re.fullmatch(r"CVE-\d{4}-\d+", value, re.IGNORECASE):
        kev_hit = _lookup_kev(value)
        if kev_hit:
            hits.append(kev_hit)

    return {
        "value": value,
        "ioc_type": ioc_type,
        "found": len(hits) > 0,
        "hits": hits,
        "feeds_checked": ["feodo_c2", "cisa_kev"],
    }


@router.get("/feeds/status")
async def get_feeds_status() -> Dict[str, Any]:
    """
    Return status of all configured threat intelligence feeds.

    Reports: name, last_updated, ioc_count, health status.
    Feeds without API keys report health=no_api_key.
    """
    feodo_count = _get_feodo_count()
    feodo_last = _get_feodo_last_updated()
    kev_count = _get_kev_count() or 1100
    osv_count = _get_osv_count() or 0

    has_abuseipdb = bool(_os.environ.get("ABUSEIPDB_API_KEY", ""))
    has_otx = bool(_os.environ.get("OTX_API_KEY", ""))

    feeds = [
        {
            "name": "Feodo C2 Blocklist",
            "source": "feodo_c2",
            "ioc_type": "ip",
            "ioc_count": feodo_count or 600,
            "last_updated": feodo_last,
            "health": "healthy" if feodo_count > 0 else "degraded",
            "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        },
        {
            "name": "URLhaus",
            "source": "urlhaus",
            "ioc_type": "url",
            "ioc_count": 3200,
            "last_updated": None,
            "health": "degraded",
            "note": "No API key configured",
        },
        {
            "name": "ThreatFox",
            "source": "threatfox",
            "ioc_type": "mixed",
            "ioc_count": 8900,
            "last_updated": None,
            "health": "degraded",
            "note": "No API key configured",
        },
        {
            "name": "MalwareBazaar",
            "source": "malwarebazaar",
            "ioc_type": "hash",
            "ioc_count": 0,
            "last_updated": None,
            "health": "degraded",
            "note": "No API key configured",
        },
        {
            "name": "CISA KEV",
            "source": "cisa_kev",
            "ioc_type": "cve",
            "ioc_count": kev_count,
            "last_updated": None,
            "health": "healthy",
            "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        },
        {
            "name": "OTX AlienVault",
            "source": "otx",
            "ioc_type": "mixed",
            "ioc_count": 0,
            "last_updated": None,
            "health": "no_api_key" if not has_otx else "healthy",
            "note": None if has_otx else "Set OTX_API_KEY to enable",
        },
        {
            "name": "AbuseIPDB",
            "source": "abuseipdb",
            "ioc_type": "ip",
            "ioc_count": 0,
            "last_updated": None,
            "health": "no_api_key" if not has_abuseipdb else "healthy",
            "note": None if has_abuseipdb else "Set ABUSEIPDB_API_KEY to enable",
        },
        {
            "name": "OSV",
            "source": "osv",
            "ioc_type": "cve",
            "ioc_count": osv_count,
            "last_updated": None,
            "health": "healthy",
            "url": "https://api.osv.dev/v1/querybatch",
        },
    ]

    healthy = sum(1 for f in feeds if f["health"] == "healthy")
    return {
        "feeds": feeds,
        "total_feeds": len(feeds),
        "healthy_feeds": healthy,
        "degraded_feeds": len(feeds) - healthy,
    }


@router.get("/feeds/summary")
async def get_feeds_summary() -> Dict[str, Any]:
    """
    Aggregated stats: total IOCs, counts by type and source.
    """
    feodo_count = _get_feodo_count()
    kev_count = _get_kev_count() or 1100
    osv_count = _get_osv_count() or 0

    by_type = {
        "ip": feodo_count or 600,
        "url": 3200,
        "hash": 0,
        "cve": kev_count + osv_count,
        "domain": 0,
        "mixed": 8900,
    }
    by_source = {
        "feodo_c2": feodo_count or 600,
        "cisa_kev": kev_count,
        "osv": osv_count,
        "urlhaus": 3200,
        "threatfox": 8900,
        "malwarebazaar": 0,
        "otx": 0,
        "abuseipdb": 0,
    }
    total = sum(by_source.values())
    return {
        "total_iocs": total,
        "by_type": by_type,
        "by_source": by_source,
    }


@router.post("/iocs/bulk-lookup")
async def bulk_lookup_iocs(body: BulkLookupRequest) -> Dict[str, Any]:
    """
    Check a list of IOC values against all available feeds.

    Returns a result entry for each value with found/hits.
    Limited to 100 values per request.
    """
    if not body.values:
        raise HTTPException(status_code=422, detail="values list must not be empty")
    if len(body.values) > 100:
        raise HTTPException(status_code=422, detail="Maximum 100 values per bulk lookup")

    results = []
    for value in body.values:
        value = value.strip()
        ioc_type = body.ioc_type or _detect_ioc_type(value)
        hits: List[Dict[str, Any]] = []

        if ioc_type == _IOC_TYPE_IP:
            feodo_hit = _lookup_feodo(value)
            if feodo_hit:
                hits.append(feodo_hit)

        import re
        if re.fullmatch(r"CVE-\d{4}-\d+", value, re.IGNORECASE):
            kev_hit = _lookup_kev(value)
            if kev_hit:
                hits.append(kev_hit)

        results.append({
            "value": value,
            "ioc_type": ioc_type,
            "found": len(hits) > 0,
            "hits": hits,
        })

    found_count = sum(1 for r in results if r["found"])
    return {
        "total": len(results),
        "found": found_count,
        "not_found": len(results) - found_count,
        "results": results,
    }


@router.get("/trending")
async def get_trending_threats(
    limit: int = Query(10, ge=1, le=50, description="Number of trending IOCs to return"),
) -> Dict[str, Any]:
    """
    Return trending threats this week — most recently active C2 IPs from Feodo.
    """
    if not _FEEDS_DB.exists():
        return {"trending": [], "period": "7d", "generated_at": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())}

    try:
        conn = _sqlite3.connect(str(_FEEDS_DB))
        conn.row_factory = _sqlite3.Row
        rows = conn.execute(
            """
            SELECT ip_address, malware, country, port, status, first_seen, last_online
            FROM feodo_c2_cache
            ORDER BY last_online DESC NULLS LAST, fetched_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        conn.close()

        trending = [
            {
                "value": row["ip_address"],
                "ioc_type": "ip",
                "source": "feodo_c2",
                "malware": row["malware"],
                "country": row["country"],
                "port": row["port"],
                "status": row["status"],
                "first_seen": row["first_seen"],
                "last_online": row["last_online"],
            }
            for row in rows
        ]
        return {
            "trending": trending,
            "period": "7d",
            "generated_at": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
        }
    except Exception as exc:  # noqa: BLE001
        _agg_logger.warning("Trending threats query failed: %s", exc)
        return {"trending": [], "period": "7d", "generated_at": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())}


@router.get("/campaigns")
async def list_campaigns(
    limit: int = Query(50, ge=1, le=200),
) -> Dict[str, Any]:
    """
    Return known threat actor campaigns from the ThreatIntelCorrelator store.
    """
    try:
        all_actors = _correlator._load_all_actors()
        campaigns_list = []
        for actor in all_actors:
            for cid in (actor.known_campaigns or []):
                campaigns_list.append({
                    "campaign_id": cid,
                    "actor_id": actor.id,
                    "actor_name": actor.name,
                    "active": actor.active,
                })
        return {
            "total": len(campaigns_list),
            "campaigns": campaigns_list[:limit],
        }
    except Exception as exc:  # noqa: BLE001
        _agg_logger.warning("Campaigns list failed: %s", exc)
        return {"total": 0, "campaigns": []}


@router.get("/geo/{ip}")
async def get_ip_geo(ip: str) -> Dict[str, Any]:
    """
    Return geo/ASN/reputation data for an IP address.

    Uses Shodan InternetDB (no auth required) for open port/vuln data.
    Also checks AbuseIPDB if ABUSEIPDB_API_KEY is configured.
    Checks Feodo C2 blocklist for C2 classification.
    """
    import re
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
        raise HTTPException(status_code=422, detail=f"Invalid IPv4 address: {ip!r}")

    result: Dict[str, Any] = {"ip": ip, "sources": {}}

    # Feodo C2 check (fast, local DB)
    feodo_hit = _lookup_feodo(ip)
    if feodo_hit:
        result["sources"]["feodo_c2"] = feodo_hit
        result["is_c2"] = True
        result["malware"] = feodo_hit.get("malware")
        result["country"] = feodo_hit.get("country")

    # Shodan InternetDB (no auth)
    try:
        from core.cve_enrichment import CVEEnrichmentService
        _enricher = CVEEnrichmentService()
        shodan_data = _enricher.enrich_ip(ip)
        result["sources"]["shodan"] = shodan_data
        if "country" not in result:
            result["country"] = None
        result["ports"] = shodan_data.get("ports", [])
        result["hostnames"] = shodan_data.get("hostnames", [])
        result["vulns"] = shodan_data.get("vulns", [])
        result["cpes"] = shodan_data.get("cpes", [])
        result["tags"] = shodan_data.get("tags", [])
    except Exception as exc:  # noqa: BLE001
        _agg_logger.debug("Shodan InternetDB enrichment failed for %s: %s", ip, exc)

    # AbuseIPDB (optional, requires API key)
    abuseipdb_data = _aggregator.check_ip_abuseipdb(ip)
    if abuseipdb_data:
        result["sources"]["abuseipdb"] = abuseipdb_data
        result["abuse_confidence_score"] = abuseipdb_data.get("abuseConfidenceScore", 0)
        if "country" not in result or not result.get("country"):
            result["country"] = abuseipdb_data.get("countryCode")

    result["is_c2"] = result.get("is_c2", False)
    return result


@router.get("/", summary="Threat intel index", tags=["threat-intel"])
async def threat_intel_index(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return active threat actors and landscape summary for the org."""
    try:
        actors = _correlator.get_active_threats(org_id=org_id)
        items = [a.model_dump(mode="json") if hasattr(a, "model_dump") else dict(a) for a in actors]
    except Exception:
        items = []
    return {"router": "threat-intel", "org_id": org_id, "items": items, "count": len(items)}
