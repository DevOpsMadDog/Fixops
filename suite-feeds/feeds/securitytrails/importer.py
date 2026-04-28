"""SecurityTrails passive DNS feed importer.

Source: SecurityTrails API — https://api.securitytrails.com/v1/
Tier:   Free (50 calls/month) requires SECURITYTRAILS_API_KEY env var.
        Without a key the importer logs a warning and returns status="needs_credentials".

Endpoints used:
  GET /v1/domain/{domain}/subdomains   — subdomain enumeration
  GET /v1/history/{domain}/dns/a       — passive DNS A-record history
  GET /v1/ips/{ip}                     — reverse DNS lookup

Stored shape (keyed by domain):
    {
        "domain":              "example.com",
        "subdomain_count":     int,
        "subdomains":          ["www", "api", ...],       # bare labels
        "current_a_records":   ["1.2.3.4", ...],
        "historical_a_records": [
            {"ip": "5.6.7.8", "first_seen": "2024-01-01", "last_seen": "2024-06-01"},
            ...
        ],
        "cached_at":    "<iso8601>",
        "imported_at":  "<iso8601>",
        "status":       "ok" | "needs_credentials" | "error",
    }

Cache: 7-day TTL (subdomain enumeration is stable).

Reverse-DNS records (keyed by "rdns:<ip>"):
    {
        "ip":          "1.2.3.4",
        "hostnames":   ["host.example.com", ...],
        "cached_at":   "<iso8601>",
        "imported_at": "<iso8601>",
        "status":      "ok" | "needs_credentials" | "error",
    }

DB: data/securitytrails.db (PersistentDict)
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SECURITYTRAILS_BASE_URL = "https://api.securitytrails.com/v1"
DOWNLOAD_TIMEOUT = 20.0
CACHE_TTL_SECONDS = 7 * 86_400  # 7 days — subdomain data is stable

_HERE = Path(__file__).resolve()
_PROJECT_ROOT = _HERE.parents[3]  # suite-feeds/feeds/securitytrails -> project root
_DB_PATH = _PROJECT_ROOT / "data" / "securitytrails.db"

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
        store = PersistentDict("securitytrails_data", db_path=path)
    except TypeError:
        store = PersistentDict("securitytrails_data")

    if db_path is None:
        _store = store
    return store


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _api_key() -> Optional[str]:
    return os.environ.get("SECURITYTRAILS_API_KEY") or None


def _build_headers() -> Optional[Dict[str, str]]:
    key = _api_key()
    if not key:
        return None
    return {
        "Accept": "application/json",
        "APIKEY": key,
    }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_fresh(record: Dict[str, Any]) -> bool:
    """Return True if *record* was cached within CACHE_TTL_SECONDS."""
    cached_at = record.get("cached_at") or ""
    if not cached_at:
        return False
    try:
        if cached_at.endswith("Z"):
            cached_at = cached_at[:-1] + "+00:00"
        ts = datetime.fromisoformat(cached_at)
        age = (datetime.now(timezone.utc) - ts).total_seconds()
        return age < CACHE_TTL_SECONDS
    except (ValueError, TypeError):
        return False


def _store_get(store, key: str) -> Optional[Dict[str, Any]]:
    """Safely retrieve a key from any store type."""
    try:
        entry = store.get(key) if hasattr(store, "get") else (
            store[key] if key in store else None
        )
        return entry if isinstance(entry, dict) else None
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# Parse — subdomains
# ---------------------------------------------------------------------------

def parse_subdomains_response(payload: Dict[str, Any]) -> List[str]:
    """Extract bare subdomain labels from GET /v1/domain/{domain}/subdomains."""
    subdomains = payload.get("subdomains") or []
    return [str(s).lower().strip() for s in subdomains if s]


# ---------------------------------------------------------------------------
# Parse — DNS A-record history
# ---------------------------------------------------------------------------

def parse_dns_history_response(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Extract current + historical A records from GET /v1/history/{domain}/dns/a.

    Returns:
        {
            "current_a_records":    ["1.2.3.4", ...],
            "historical_a_records": [{"ip": str, "first_seen": str, "last_seen": str}, ...],
        }
    """
    records = payload.get("records") or []
    current_ips: List[str] = []
    historical: List[Dict[str, str]] = []

    for record in records:
        if not isinstance(record, dict):
            continue
        values = record.get("values") or []
        first_seen = str(record.get("first_seen") or "")
        last_seen = str(record.get("last_seen") or "")
        type_ = str(record.get("type") or "a").lower()
        if type_ != "a":
            continue
        for val in values:
            ip = None
            if isinstance(val, dict):
                ip = val.get("ip") or val.get("value")
            elif isinstance(val, str):
                ip = val
            if not ip:
                continue
            ip = str(ip).strip()
            historical.append({
                "ip": ip,
                "first_seen": first_seen,
                "last_seen": last_seen,
            })

    # "Current" = most recent record (largest last_seen or first entry)
    if historical:
        latest = max(historical, key=lambda r: r.get("last_seen", ""), default=None)
        if latest:
            current_ips = [latest["ip"]]

    return {
        "current_a_records": current_ips,
        "historical_a_records": historical,
    }


# ---------------------------------------------------------------------------
# Parse — reverse DNS
# ---------------------------------------------------------------------------

def parse_rdns_response(payload: Dict[str, Any]) -> List[str]:
    """Extract hostnames from GET /v1/ips/{ip}.

    SecurityTrails returns various shapes; we normalise to a flat hostname list.
    """
    hostnames: List[str] = []

    # Shape 1: {"records": [{"hostname": "..."}, ...]}
    records = payload.get("records") or []
    for r in records:
        if isinstance(r, dict):
            h = r.get("hostname") or r.get("host")
            if h:
                hostnames.append(str(h).lower().strip())

    # Shape 2: {"hostnames": ["..."]}
    raw_hostnames = payload.get("hostnames") or []
    for h in raw_hostnames:
        if h and str(h) not in hostnames:
            hostnames.append(str(h).lower().strip())

    return list(dict.fromkeys(hostnames))  # deduplicate, preserve order


# ---------------------------------------------------------------------------
# Core domain enumeration
# ---------------------------------------------------------------------------

def enumerate_domain(
    domain: str,
    *,
    force_refresh: bool = False,
    timeout: float = DOWNLOAD_TIMEOUT,
    db_path: Optional[str] = None,
    fixture: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Fetch subdomains + DNS history for *domain* and persist to the store.

    Args:
        domain:        The apex domain to enumerate (e.g. "example.com").
        force_refresh: Bypass the 7-day cache.
        timeout:       httpx request timeout in seconds.
        db_path:       Override DB path (useful in tests).
        fixture:       Pre-parsed fixture dict ({"subdomains": [...], "history": {...}}).
                       Set via the --use-fixture flag to avoid real API calls in tests.

    Returns:
        The stored domain record (see module docstring for schema).
    """
    store = _get_store(db_path)
    domain = domain.lower().strip()
    now = _now_iso()

    # Cache hit
    if not force_refresh:
        existing = _store_get(store, domain)
        if isinstance(existing, dict) and _is_fresh(existing) and existing.get("status") == "ok":
            logger.debug("securitytrails: cache hit for domain %s", domain)
            return existing

    # Credentials check
    headers = _build_headers()
    if headers is None and fixture is None:
        logger.warning(
            "securitytrails: SECURITYTRAILS_API_KEY not set — skipping domain %s",
            domain,
        )
        record: Dict[str, Any] = {
            "domain": domain,
            "subdomain_count": 0,
            "subdomains": [],
            "current_a_records": [],
            "historical_a_records": [],
            "cached_at": now,
            "imported_at": now,
            "status": "needs_credentials",
        }
        store[domain] = record
        return record

    # Use fixture data (test mode)
    if fixture is not None:
        subdomains = fixture.get("subdomains") or []
        dns_data = fixture.get("history") or {}
        current_ips = dns_data.get("current_a_records") or []
        historical = dns_data.get("historical_a_records") or []
    else:
        # Real API calls
        assert headers is not None  # guarded above
        subdomains = _fetch_subdomains(domain, headers=headers, timeout=timeout)
        dns_history = _fetch_dns_history(domain, headers=headers, timeout=timeout)
        current_ips = dns_history.get("current_a_records") or []
        historical = dns_history.get("historical_a_records") or []

    record = {
        "domain": domain,
        "subdomain_count": len(subdomains),
        "subdomains": subdomains,
        "current_a_records": current_ips,
        "historical_a_records": historical,
        "cached_at": now,
        "imported_at": now,
        "status": "ok",
    }
    store[domain] = record
    logger.info(
        "securitytrails: enumerated %s — %d subdomains, %d historical IPs",
        domain, len(subdomains), len(historical),
    )
    return record


def _fetch_subdomains(
    domain: str,
    headers: Dict[str, str],
    timeout: float = DOWNLOAD_TIMEOUT,
) -> List[str]:
    url = f"{SECURITYTRAILS_BASE_URL}/domain/{domain}/subdomains"
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(url, headers=headers)
        resp.raise_for_status()
        return parse_subdomains_response(resp.json())


def _fetch_dns_history(
    domain: str,
    headers: Dict[str, str],
    timeout: float = DOWNLOAD_TIMEOUT,
) -> Dict[str, Any]:
    url = f"{SECURITYTRAILS_BASE_URL}/history/{domain}/dns/a"
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(url, headers=headers)
        resp.raise_for_status()
        return parse_dns_history_response(resp.json())


# ---------------------------------------------------------------------------
# Reverse DNS lookup
# ---------------------------------------------------------------------------

def lookup_ip(
    ip: str,
    *,
    force_refresh: bool = False,
    timeout: float = DOWNLOAD_TIMEOUT,
    db_path: Optional[str] = None,
    fixture: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Reverse-DNS lookup for *ip* via SecurityTrails /v1/ips/{ip}.

    Caches with the same 7-day TTL. Keyed as "rdns:<ip>" in the store.
    """
    store = _get_store(db_path)
    ip = ip.strip()
    key = f"rdns:{ip}"
    now = _now_iso()

    # Cache hit
    if not force_refresh:
        existing = _store_get(store, key)
        if isinstance(existing, dict) and _is_fresh(existing) and existing.get("status") == "ok":
            logger.debug("securitytrails: rdns cache hit for %s", ip)
            return existing

    # Credentials check
    headers = _build_headers()
    if headers is None and fixture is None:
        logger.warning(
            "securitytrails: SECURITYTRAILS_API_KEY not set — skipping rdns %s", ip
        )
        record: Dict[str, Any] = {
            "ip": ip,
            "hostnames": [],
            "cached_at": now,
            "imported_at": now,
            "status": "needs_credentials",
        }
        store[key] = record
        return record

    if fixture is not None:
        hostnames = fixture.get("hostnames") or []
    else:
        assert headers is not None
        url = f"{SECURITYTRAILS_BASE_URL}/ips/{ip}"
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(url, headers=headers)
            resp.raise_for_status()
            hostnames = parse_rdns_response(resp.json())

    record = {
        "ip": ip,
        "hostnames": hostnames,
        "cached_at": now,
        "imported_at": now,
        "status": "ok",
    }
    store[key] = record
    logger.info("securitytrails: rdns %s -> %d hostnames", ip, len(hostnames))
    return record


# ---------------------------------------------------------------------------
# Bulk import (registry callable)
# ---------------------------------------------------------------------------

def run_import(
    domains: Optional[List[str]] = None,
    *,
    force_refresh: bool = False,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Import passive DNS data for a list of domains.

    If no domains are provided the importer is a no-op (returns zero counts).
    This is intentional — domain selection is a per-customer concern delegated
    to the /enumerate endpoint.

    Returns:
        {
            "domains_processed": N,
            "subdomains_total":  N,
            "ips_resolved":      N,
            "status":            "ok" | "needs_credentials",
        }
    """
    api_key = _api_key()
    if not api_key:
        logger.warning(
            "securitytrails: SECURITYTRAILS_API_KEY not set — importer skipped"
        )
        return {
            "domains_processed": 0,
            "subdomains_total": 0,
            "ips_resolved": 0,
            "status": "needs_credentials",
        }

    domains = domains or []
    domains_processed = 0
    subdomains_total = 0
    ips_resolved = 0
    errors: List[str] = []

    for domain in domains:
        try:
            record = enumerate_domain(domain, force_refresh=force_refresh, db_path=db_path)
            if record.get("status") == "ok":
                domains_processed += 1
                subdomains_total += record.get("subdomain_count") or 0
                ips_resolved += len(record.get("historical_a_records") or [])
        except Exception as exc:  # noqa: BLE001
            logger.warning("securitytrails: enumerate_domain failed for %s: %s", domain, exc)
            errors.append(f"{domain}: {type(exc).__name__}: {exc}")

    result: Dict[str, Any] = {
        "domains_processed": domains_processed,
        "subdomains_total": subdomains_total,
        "ips_resolved": ips_resolved,
        "status": "ok",
    }
    if errors:
        result["errors"] = errors
    return result


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def get_domain_report(
    domain: str,
    db_path: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Return the cached report for *domain*, or None if not stored."""
    store = _get_store(db_path)
    return _store_get(store, domain.lower().strip())


def get_ip_report(ip: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Return the cached reverse-DNS record for *ip*, or None if not stored."""
    store = _get_store(db_path)
    return _store_get(store, f"rdns:{ip.strip()}")


def get_store_stats(db_path: Optional[str] = None) -> Dict[str, Any]:
    """Return summary stats from the local store."""
    store = _get_store(db_path)
    domain_count = 0
    rdns_count = 0
    subdomain_total = 0
    for key in store.keys() if hasattr(store, "keys") else []:
        entry = _store_get(store, str(key))
        if not entry:
            continue
        if str(key).startswith("rdns:"):
            rdns_count += 1
        else:
            domain_count += 1
            subdomain_total += entry.get("subdomain_count") or 0
    return {
        "domains_cached": domain_count,
        "rdns_cached": rdns_count,
        "subdomains_total": subdomain_total,
    }


def total_count(db_path: Optional[str] = None) -> int:
    return len(_get_store(db_path))
