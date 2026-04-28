"""Censys CVE-to-host search feed importer.

Source: Censys Search API v2
    https://search.censys.io/api/v2/hosts/search
    Community tier: free with CENSYS_API_ID + CENSYS_API_SECRET env vars.
    Auth: HTTP Basic (api_id:api_secret).
    Docs: https://search.censys.io/api

Credentials:
    CENSYS_API_ID     — API ID from https://search.censys.io/account
    CENSYS_API_SECRET — API secret from same page

Without credentials the importer logs a structured warning and returns without
importing. Use --use-fixture (or fixture_data arg) for offline tests.

Stored shape (keyed by ip):
    {
        "ip": str,
        "last_observation": str (ISO 8601),
        "services": [
            {
                "port": int,
                "service_name": str,
                "product": str,
                "version": str,
            },
            ...
        ],
        "country": str,
        "asn": int | None,
        "cve_ids": [str, ...],
        "imported_at": str (ISO 8601),
    }

Cache: 1-day TTL per CVE query.

DB: data/censys.db (PersistentDict)

Summary returned:
    {
        "hosts": int,
        "by_country": {country: int},
        "by_cve": {cve_id: int},
    }
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

CENSYS_SEARCH_URL = "https://search.censys.io/api/v2/hosts/search"
DOWNLOAD_TIMEOUT = 30.0
CACHE_TTL_SECONDS = 86_400  # 1 day

_HERE = Path(__file__).resolve()
_PROJECT_ROOT = _HERE.parents[3]  # suite-feeds/feeds/censys/importer.py -> project root
_DB_PATH = _PROJECT_ROOT / "data" / "censys.db"

# ---------------------------------------------------------------------------
# Lazy-loaded store
# ---------------------------------------------------------------------------

_store = None


def _get_store(db_path: Optional[str] = None):
    global _store
    if _store is not None and db_path is None:
        return _store

    path = db_path or str(_DB_PATH)
    try:
        suite_core = str(_PROJECT_ROOT / "suite-core")
        if suite_core not in sys.path:
            sys.path.insert(0, suite_core)
        from core.persistent_store import PersistentDict
    except ImportError:
        from collections import UserDict as PersistentDict  # type: ignore[assignment]

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    try:
        store = PersistentDict("censys_hosts", db_path=path)
    except TypeError:
        store = PersistentDict("censys_hosts")  # type: ignore[call-arg]

    if db_path is None:
        _store = store
    return store


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def parse_host_record(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalise a single Censys v2 host hit into our stored shape.

    Returns None if the record lacks a usable IP address.
    """
    ip: Optional[str] = raw.get("ip")
    if not ip or not isinstance(ip, str):
        return None

    last_obs: str = raw.get("last_updated_at") or raw.get("last_observation_time") or ""

    # Services
    services: List[Dict[str, Any]] = []
    for svc in raw.get("services") or []:
        if not isinstance(svc, dict):
            continue
        services.append({
            "port": int(svc.get("port") or 0),
            "service_name": str(svc.get("service_name") or ""),
            "product": str(svc.get("software", [{}])[0].get("product") if svc.get("software") else ""),
            "version": str(svc.get("software", [{}])[0].get("version") if svc.get("software") else ""),
        })

    # Location
    location = raw.get("location") or {}
    country: str = (
        location.get("country_code")
        or location.get("country")
        or ""
    )

    # ASN
    asn_block = raw.get("autonomous_system") or {}
    asn: Optional[int] = None
    try:
        asn = int(asn_block.get("asn") or 0) or None
    except (TypeError, ValueError):
        asn = None

    # CVEs from services.vulnerabilities
    cve_ids: List[str] = []
    seen_cves: set = set()
    for svc in raw.get("services") or []:
        if not isinstance(svc, dict):
            continue
        for vuln in svc.get("vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            cid = vuln.get("cve_id") or vuln.get("id") or ""
            if cid and cid not in seen_cves:
                cve_ids.append(cid)
                seen_cves.add(cid)

    return {
        "ip": ip.strip(),
        "last_observation": last_obs,
        "services": services,
        "country": country,
        "asn": asn,
        "cve_ids": cve_ids,
    }


def parse_hosts_response(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parse the Censys v2 /hosts/search JSON response."""
    results = payload.get("result") or {}
    hits = results.get("hits") or []
    if not isinstance(hits, list):
        return []
    out: List[Dict[str, Any]] = []
    for raw in hits:
        if not isinstance(raw, dict):
            continue
        record = parse_host_record(raw)
        if record is not None:
            out.append(record)
    return out


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

_CACHE_META_PREFIX = "_cache_meta:"


def _cache_key(cve_id: str) -> str:
    return f"{_CACHE_META_PREFIX}{cve_id}"


def _is_cache_fresh(store: Any, cve_id: str) -> bool:
    """Return True if the last import for *cve_id* is within the 1-day TTL."""
    meta_key = _cache_key(cve_id)
    try:
        meta = store.get(meta_key) if hasattr(store, "get") else (
            store[meta_key] if meta_key in store else None
        )
    except Exception:  # noqa: BLE001
        return False

    if not isinstance(meta, dict):
        return False

    imported_at_str: Optional[str] = meta.get("imported_at")
    if not imported_at_str:
        return False
    try:
        if imported_at_str.endswith("Z"):
            imported_at_str = imported_at_str[:-1] + "+00:00"
        imported_at = datetime.fromisoformat(imported_at_str)
        age = datetime.now(timezone.utc) - imported_at
        return age < timedelta(seconds=CACHE_TTL_SECONDS)
    except (ValueError, TypeError):
        return False


def _set_cache_meta(store: Any, cve_id: str, host_count: int) -> None:
    meta_key = _cache_key(cve_id)
    try:
        store[meta_key] = {
            "cve_id": cve_id,
            "imported_at": datetime.now(timezone.utc).isoformat(),
            "host_count": host_count,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("censys: failed to write cache meta for %s: %s", cve_id, exc)


# ---------------------------------------------------------------------------
# Upsert
# ---------------------------------------------------------------------------

def _upsert_hosts(records: List[Dict[str, Any]], store: Any) -> int:
    """Upsert host records into the store. Returns number of records written."""
    now = datetime.now(timezone.utc).isoformat()
    count = 0
    for record in records:
        ip = record["ip"]
        existing = None
        try:
            existing = store.get(ip) if hasattr(store, "get") else (
                store[ip] if ip in store else None
            )
        except Exception:  # noqa: BLE001
            pass

        # Merge CVE IDs if record already exists
        if isinstance(existing, dict):
            merged_cves = list(set(existing.get("cve_ids") or []) | set(record.get("cve_ids") or []))
            record = {**existing, **record, "cve_ids": merged_cves}

        store[ip] = {**record, "imported_at": now}
        count += 1
    return count


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

def _fetch_cve_hosts(
    cve_id: str,
    api_id: str,
    api_secret: str,
    max_results: int = 100,
    timeout: float = DOWNLOAD_TIMEOUT,
) -> Dict[str, Any]:
    """Call Censys Search API for hosts vulnerable to *cve_id*."""
    try:
        import httpx
    except ImportError as exc:
        raise RuntimeError("httpx is required for Censys importer: pip install httpx") from exc

    params = {
        "q": f"services.vulnerabilities.cve_id={cve_id}",
        "per_page": min(max_results, 100),
        "fields": [
            "ip",
            "last_updated_at",
            "services.port",
            "services.service_name",
            "services.software",
            "services.vulnerabilities",
            "location.country_code",
            "autonomous_system.asn",
        ],
    }

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(
            CENSYS_SEARCH_URL,
            params=params,
            auth=(api_id, api_secret),
            headers={"Accept": "application/json"},
        )
        response.raise_for_status()
        return response.json()


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def run_import(
    cve_id: str = "CVE-2021-44228",
    api_id: Optional[str] = None,
    api_secret: Optional[str] = None,
    max_results: int = 100,
    force: bool = False,
    fixture_data: Optional[Dict[str, Any]] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Run the Censys importer for a single CVE.

    Args:
        cve_id:       CVE identifier to search (e.g. "CVE-2021-44228").
        api_id:       Censys API ID (falls back to CENSYS_API_ID env var).
        api_secret:   Censys API secret (falls back to CENSYS_API_SECRET env var).
        max_results:  Max hosts to fetch per CVE (capped at 100 per Censys page).
        force:        Skip 1-day TTL cache check and always re-import.
        fixture_data: If provided, use this JSON payload instead of a real API call
                      (for offline tests — matches --use-fixture CLI flag semantics).
        db_path:      Override default DB path (used in tests).

    Returns:
        {"hosts": N, "by_country": {...}, "by_cve": {...}}
    """
    api_id = api_id or os.environ.get("CENSYS_API_ID") or ""
    api_secret = api_secret or os.environ.get("CENSYS_API_SECRET") or ""

    store = _get_store(db_path)

    # Credentials check — required for live calls
    if not fixture_data and (not api_id or not api_secret):
        logger.warning(
            "censys: status=needs_credentials cve_id=%s "
            "Set CENSYS_API_ID and CENSYS_API_SECRET to enable live imports. "
            "This is a paid-tier feed (community tier free with registration at "
            "https://search.censys.io/account).",
            cve_id,
            extra={"status": "needs_credentials", "cve_id": cve_id},
        )
        return _build_summary(store)

    # Cache check
    if not force and _is_cache_fresh(store, cve_id):
        logger.info("censys: cache hit for %s (TTL 1d)", cve_id)
        return _build_summary(store)

    # Fetch
    try:
        if fixture_data is not None:
            payload = fixture_data
        else:
            logger.info("censys: fetching hosts for %s from Censys Search API", cve_id)
            payload = _fetch_cve_hosts(
                cve_id=cve_id,
                api_id=api_id,
                api_secret=api_secret,
                max_results=max_results,
            )
    except Exception as exc:  # noqa: BLE001
        logger.error("censys: fetch failed for %s: %s", cve_id, exc)
        return {**_build_summary(store), "error": f"{type(exc).__name__}: {exc}"}

    records = parse_hosts_response(payload)

    written = _upsert_hosts(records, store)
    _set_cache_meta(store, cve_id, written)

    logger.info("censys: imported %d hosts for %s", written, cve_id)
    return _build_summary(store)


def _build_summary(store: Any) -> Dict[str, Any]:
    """Walk the store (skipping cache-meta entries) and build the summary."""
    by_country: Dict[str, int] = {}
    by_cve: Dict[str, int] = {}
    host_count = 0

    try:
        items = list(store.items()) if hasattr(store, "items") else []
    except Exception:  # noqa: BLE001
        items = []

    for key, entry in items:
        if not isinstance(entry, dict):
            continue
        if str(key).startswith(_CACHE_META_PREFIX):
            continue
        host_count += 1

        country = entry.get("country") or "unknown"
        by_country[country] = by_country.get(country, 0) + 1

        for cid in entry.get("cve_ids") or []:
            by_cve[cid] = by_cve.get(cid, 0) + 1

    return {
        "hosts": host_count,
        "by_country": by_country,
        "by_cve": by_cve,
    }


# ---------------------------------------------------------------------------
# Query helpers (used by router)
# ---------------------------------------------------------------------------

def list_hosts(
    ip: Optional[str] = None,
    country: Optional[str] = None,
    cve_id: Optional[str] = None,
    last_seen: Optional[str] = None,
    limit: int = 1000,
    offset: int = 0,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return stored host records matching optional filters.

    Args:
        ip:        Exact IP match.
        country:   Filter by country code (case-insensitive).
        cve_id:    Filter hosts that have this CVE in their cve_ids list.
        last_seen: ISO 8601 timestamp; only hosts with last_observation >= this.
        limit / offset: Pagination.
    """
    store = _get_store(db_path)
    threshold_dt = None
    if last_seen:
        try:
            ts = last_seen
            if ts.endswith("Z"):
                ts = ts[:-1] + "+00:00"
            threshold_dt = datetime.fromisoformat(ts)
        except ValueError:
            threshold_dt = None

    results: List[Dict[str, Any]] = []
    try:
        items = list(store.items()) if hasattr(store, "items") else []
    except Exception:  # noqa: BLE001
        items = []

    for key, entry in items:
        if not isinstance(entry, dict):
            continue
        if str(key).startswith(_CACHE_META_PREFIX):
            continue
        if ip and entry.get("ip") != ip:
            continue
        if country and (entry.get("country") or "").upper() != country.upper():
            continue
        if cve_id and cve_id not in (entry.get("cve_ids") or []):
            continue
        if threshold_dt is not None:
            obs = entry.get("last_observation") or ""
            if obs.endswith("Z"):
                obs = obs[:-1] + "+00:00"
            try:
                entry_dt = datetime.fromisoformat(obs) if obs else None
            except ValueError:
                entry_dt = None
            if entry_dt is None or entry_dt < threshold_dt:
                continue
        results.append(entry)

    return results[offset: offset + limit]


def check_host(ip: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Return stored record for *ip*, or None if not found."""
    if not ip:
        return None
    store = _get_store(db_path)
    try:
        entry = store.get(ip) if hasattr(store, "get") else (
            store[ip] if ip in store else None
        )
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(entry, dict) or str(ip).startswith(_CACHE_META_PREFIX):
        return None
    return entry


def total_count(db_path: Optional[str] = None) -> int:
    """Return number of host records in the store (excluding cache-meta entries)."""
    store = _get_store(db_path)
    count = 0
    try:
        for key in store:
            if not str(key).startswith(_CACHE_META_PREFIX):
                count += 1
    except Exception:  # noqa: BLE001
        pass
    return count


def get_store_stats(db_path: Optional[str] = None) -> Dict[str, Any]:
    """Return summary stats (alias for _build_summary)."""
    return _build_summary(_get_store(db_path))
