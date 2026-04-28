"""GreyNoise Community feed importer.

Primary source (no API key required):
    GET https://api.greynoise.io/v3/community/{ip}
    Returns benign/malicious/unknown classification for a single IP.
    Rate-limited at ~1 req/s on the free community tier.
    License: GreyNoise Community API Terms of Service.

Optional paid tier (GREYNOISE_API_KEY env var):
    Uses the Authorization header to unlock bulk/enterprise endpoints.
    The same /v3/community/{ip} path is used even with a key — a key
    simply removes rate-limit restrictions on the free path.

Stored shape (keyed by IP string):
    {
        "ip":             "1.2.3.4",
        "classification": "benign" | "malicious" | "unknown",
        "name":           "Shodan.io scanner" | None,
        "last_seen":      "2026-04-26" | None,
        "link":           "https://viz.greynoise.io/ip/1.2.3.4" | None,
        "message":        "This IP is commonly associated with..." | None,
        "cached_at":      "<iso8601>",          # when we last fetched from API
        "imported_at":    "<iso8601>",          # when stored to DB
    }

Cache:
    Each IP record carries a ``cached_at`` timestamp. Lookups that find a
    record newer than CACHE_TTL_SECONDS (86 400 = 1 day) skip the API call.

DB: data/greynoise.db (PersistentDict)
"""

from __future__ import annotations

import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GREYNOISE_COMMUNITY_URL = "https://api.greynoise.io/v3/community/{ip}"
DOWNLOAD_TIMEOUT = 15.0
CACHE_TTL_SECONDS = 86_400  # 1 day
_RATE_LIMIT_DELAY = 1.1     # seconds between unauthenticated requests

_HERE = Path(__file__).resolve()
_PROJECT_ROOT = _HERE.parents[3]  # suite-feeds/feeds/greynoise -> project root
_DB_PATH = _PROJECT_ROOT / "data" / "greynoise.db"

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
        store = PersistentDict("greynoise_ips", db_path=path)
    except TypeError:
        store = PersistentDict("greynoise_ips")

    if db_path is None:
        _store = store
    return store


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _api_key() -> Optional[str]:
    """Return GREYNOISE_API_KEY from env if set, else None."""
    return os.environ.get("GREYNOISE_API_KEY") or None


def _build_headers() -> Dict[str, str]:
    key = _api_key()
    headers: Dict[str, str] = {"Accept": "application/json"}
    if key:
        headers["key"] = key
    return headers


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


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------

def parse_community_response(payload: Dict[str, Any], ip: str) -> Dict[str, Any]:
    """Normalise a GreyNoise /v3/community/{ip} JSON payload into our schema.

    Handles both successful payloads and the ``{"message": "...", "ip": "..."}``
    style returned when the IP is not in the GreyNoise dataset (classification
    defaults to "unknown").
    """
    classification = payload.get("classification") or "unknown"
    name = payload.get("name") or None
    last_seen = payload.get("last_seen") or None
    link = payload.get("link") or None
    message = payload.get("message") or None

    return {
        "ip": ip,
        "classification": classification,
        "name": name,
        "last_seen": last_seen,
        "link": link,
        "message": message,
    }


# ---------------------------------------------------------------------------
# Core lookup (single IP)
# ---------------------------------------------------------------------------

def lookup_ip(
    ip: str,
    *,
    force_refresh: bool = False,
    timeout: float = DOWNLOAD_TIMEOUT,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Look up *ip* via the GreyNoise community API with 1-day cache.

    Args:
        ip:            IPv4 or IPv6 address string.
        force_refresh: Bypass the cache and always hit the API.
        timeout:       httpx request timeout in seconds.
        db_path:       Override the default DB path (useful in tests).

    Returns:
        The normalised IP record dict (see module docstring for schema).

    Raises:
        httpx.HTTPStatusError: On non-200/404 HTTP responses.
        httpx.RequestError:    On network failures.
    """
    store = _get_store(db_path)
    now = _now_iso()

    # Cache check
    if not force_refresh:
        existing = store.get(ip) if hasattr(store, "get") else (
            store[ip] if ip in store else None
        )
        if isinstance(existing, dict) and _is_fresh(existing):
            return existing

    url = GREYNOISE_COMMUNITY_URL.format(ip=ip)
    headers = _build_headers()

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(url, headers=headers)

        if resp.status_code == 404:
            # IP not found in GreyNoise dataset
            record = {
                "ip": ip,
                "classification": "unknown",
                "name": None,
                "last_seen": None,
                "link": f"https://viz.greynoise.io/ip/{ip}",
                "message": "This IP is not in the GreyNoise dataset.",
                "cached_at": now,
                "imported_at": now,
            }
            store[ip] = record
            return record

        resp.raise_for_status()
        payload = resp.json()

    except httpx.HTTPStatusError:
        raise
    except httpx.RequestError:
        raise

    record = parse_community_response(payload, ip)
    record["cached_at"] = now
    record["imported_at"] = now
    store[ip] = record
    return record


# ---------------------------------------------------------------------------
# Bulk import
# ---------------------------------------------------------------------------

def bulk_import(
    ips: List[str],
    *,
    force_refresh: bool = False,
    rate_limit_delay: float = _RATE_LIMIT_DELAY,
    timeout: float = DOWNLOAD_TIMEOUT,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Look up a list of IPs against the GreyNoise community API.

    Respects the 1-day cache — IPs with fresh cache entries are skipped
    unless *force_refresh* is True.

    Adds a *rate_limit_delay* second pause between unauthenticated API calls
    (suppressed when GREYNOISE_API_KEY is set).

    Returns:
        {
            "lookups":            N,      # total IPs processed (cache hits + API calls)
            "by_classification":  {...},  # {"benign": N, "malicious": N, "unknown": N}
            "cache_hits":         N,      # IPs served from cache
        }
    """
    store = _get_store(db_path)
    has_key = bool(_api_key())
    now = _now_iso()

    lookups = 0
    cache_hits = 0
    by_classification: Dict[str, int] = {}
    errors: List[str] = []

    for ip in ips:
        ip = ip.strip()
        if not ip:
            continue

        lookups += 1

        # Cache check
        if not force_refresh:
            existing = store.get(ip) if hasattr(store, "get") else (
                store[ip] if ip in store else None
            )
            if isinstance(existing, dict) and _is_fresh(existing):
                cache_hits += 1
                cls = existing.get("classification", "unknown")
                by_classification[cls] = by_classification.get(cls, 0) + 1
                continue

        try:
            record = lookup_ip(ip, force_refresh=True, timeout=timeout, db_path=db_path)
            cls = record.get("classification", "unknown")
            by_classification[cls] = by_classification.get(cls, 0) + 1
        except Exception as exc:  # noqa: BLE001
            logger.warning("GreyNoise lookup failed for %s: %s", ip, exc)
            errors.append(f"{ip}: {type(exc).__name__}: {exc}")
            # Store a placeholder so we don't hammer a failing IP
            record = {
                "ip": ip,
                "classification": "unknown",
                "name": None,
                "last_seen": None,
                "link": f"https://viz.greynoise.io/ip/{ip}",
                "message": f"Lookup failed: {exc}",
                "cached_at": now,
                "imported_at": now,
            }
            store[ip] = record
            by_classification["unknown"] = by_classification.get("unknown", 0) + 1

        # Throttle only unauthenticated requests
        if not has_key:
            time.sleep(rate_limit_delay)

    result: Dict[str, Any] = {
        "lookups": lookups,
        "by_classification": by_classification,
        "cache_hits": cache_hits,
    }
    if errors:
        result["errors"] = errors
    return result


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def total_count(db_path: Optional[str] = None) -> int:
    """Return total number of stored IP records."""
    return len(_get_store(db_path))


def get_store_stats(db_path: Optional[str] = None) -> Dict[str, Any]:
    """Return summary stats from the local store (no network calls)."""
    store = _get_store(db_path)
    by_classification: Dict[str, int] = {}
    for entry in store.values():
        if not isinstance(entry, dict):
            continue
        cls = entry.get("classification", "unknown")
        by_classification[cls] = by_classification.get(cls, 0) + 1
    return {
        "total": len(store),
        "by_classification": by_classification,
    }


def check_ip(ip: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Return the stored entry for *ip*, or None if not in the local DB."""
    if not ip:
        return None
    store = _get_store(db_path)
    entry = store.get(ip) if hasattr(store, "get") else (
        store[ip] if ip in store else None
    )
    return entry if isinstance(entry, dict) else None
