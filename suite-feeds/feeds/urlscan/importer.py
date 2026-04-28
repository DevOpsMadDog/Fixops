"""URLscan.io public feed importer.

Source (no auth required for public scans):
    https://urlscan.io/api/v1/search/?q=<query>&size=100

Optional: set URLSCAN_API_KEY env var to unlock higher rate limits.

Stored shape (keyed by URLscan id):
    {
        "id": str,
        "indexed_at": str,          # ISO 8601
        "url": str,
        "domain": str,
        "country": str,
        "method": str,              # "manual" | "api" | "automatic"
        "tags": [str, ...],
        "source": str,
        "malicious": bool,
        "score": int,
        "screenshot_url": str,
        "imported_at": str,         # ISO 8601 UTC
    }

DB: data/urlscan.db  (PersistentDict)

CLI usage:
    python -m feeds.urlscan.importer
    python -m feeds.urlscan.importer --query "task.tags:malware"
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/"
DEFAULT_QUERY = "task.tags:phishing"
DEFAULT_SIZE = 100
DOWNLOAD_TIMEOUT = 60.0

# ---------------------------------------------------------------------------
# Paths / store
# ---------------------------------------------------------------------------

_HERE = Path(__file__).resolve()
_PROJECT_ROOT = _HERE.parents[3]  # suite-feeds/feeds/urlscan -> project root
_DB_PATH = _PROJECT_ROOT / "data" / "urlscan.db"

_store = None


def _get_store():
    global _store
    if _store is None:
        try:
            suite_core = str(_PROJECT_ROOT / "suite-core")
            if suite_core not in sys.path:
                sys.path.insert(0, suite_core)
            from core.persistent_store import PersistentDict
        except ImportError:
            from collections import UserDict as PersistentDict  # type: ignore[assignment]

        _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        try:
            _store = PersistentDict("urlscan_results", db_path=str(_DB_PATH))
        except TypeError:
            _store = PersistentDict("urlscan_results")
    return _store


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _extract_tld(domain: str) -> str:
    """Return the TLD (last dot-separated component) or 'unknown'."""
    if not domain:
        return "unknown"
    parts = domain.rstrip(".").split(".")
    return parts[-1] if parts else "unknown"


def parse_results(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parse URLscan.io search API response into normalised entries.

    Args:
        data: Parsed JSON from the URLscan /search/ endpoint.

    Returns:
        List of normalised result dicts.
    """
    rows: List[Dict[str, Any]] = []
    now_iso = datetime.now(timezone.utc).isoformat()

    for result in data.get("results", []):
        entry_id = result.get("_id") or result.get("id") or ""
        if not entry_id:
            continue

        page = result.get("page") or {}
        task = result.get("task") or {}
        verdicts = result.get("verdicts") or {}
        overall = verdicts.get("overall") or {}

        raw_tags = task.get("tags") or []
        if isinstance(raw_tags, str):
            raw_tags = [t.strip() for t in raw_tags.split(",") if t.strip()]

        screenshot_url = result.get("screenshot") or ""
        if not screenshot_url and entry_id:
            screenshot_url = f"https://urlscan.io/screenshots/{entry_id}.png"

        rows.append({
            "id": entry_id,
            "indexed_at": result.get("indexedAt") or now_iso,
            "url": page.get("url") or "",
            "domain": page.get("domain") or "",
            "country": page.get("country") or "",
            "method": task.get("method") or "",
            "tags": raw_tags,
            "source": task.get("source") or "",
            "malicious": bool(overall.get("malicious", False)),
            "score": int(overall.get("score") or 0),
            "screenshot_url": screenshot_url,
            "imported_at": now_iso,
        })

    return rows


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------

def _build_headers() -> Dict[str, str]:
    headers: Dict[str, str] = {"Accept": "application/json"}
    api_key = os.environ.get("URLSCAN_API_KEY", "").strip()
    if api_key:
        headers["API-Key"] = api_key
    return headers


def _fetch(query: str, size: int = DEFAULT_SIZE, timeout: float = DOWNLOAD_TIMEOUT) -> Dict[str, Any]:
    """Fetch URLscan search results. Returns parsed JSON dict."""
    params = {"q": query, "size": size}
    headers = _build_headers()
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(URLSCAN_SEARCH_URL, params=params, headers=headers)
        response.raise_for_status()
        return response.json()


# ---------------------------------------------------------------------------
# Upsert
# ---------------------------------------------------------------------------

def _upsert(rows: List[Dict[str, Any]]) -> int:
    """Upsert rows by URLscan id. Returns count upserted."""
    store = _get_store()
    for row in rows:
        store[row["id"]] = row
    return len(rows)


# ---------------------------------------------------------------------------
# Summary helpers
# ---------------------------------------------------------------------------

def _build_summary(
    results_count: int = 0,
    errors: Optional[List[str]] = None,
) -> Dict[str, Any]:
    store = _get_store()
    by_verdict: Dict[str, int] = {"malicious": 0, "clean": 0}
    by_domain_tld: Dict[str, int] = {}
    total = 0

    for entry in store.values():
        if not isinstance(entry, dict):
            continue
        total += 1
        if entry.get("malicious"):
            by_verdict["malicious"] = by_verdict.get("malicious", 0) + 1
        else:
            by_verdict["clean"] = by_verdict.get("clean", 0) + 1

        tld = _extract_tld(entry.get("domain") or "")
        by_domain_tld[tld] = by_domain_tld.get(tld, 0) + 1

    summary: Dict[str, Any] = {
        "results": results_count,
        "total_stored": total,
        "by_verdict": by_verdict,
        "by_domain_tld": dict(
            sorted(by_domain_tld.items(), key=lambda x: x[1], reverse=True)[:20]
        ),
    }
    if errors:
        summary["errors"] = errors
    return summary


def get_store_stats() -> Dict[str, Any]:
    return _build_summary()


def total_count() -> int:
    return len(_get_store())


# ---------------------------------------------------------------------------
# Public run_import
# ---------------------------------------------------------------------------

def run_import(
    query: str = DEFAULT_QUERY,
    size: int = DEFAULT_SIZE,
) -> Dict[str, Any]:
    """Pull URLscan.io public search results and upsert into local DB.

    Args:
        query: URLscan search query (default: ``task.tags:phishing``).
        size:  Max results to fetch (default: 100).

    Returns:
        ``{"results": N, "by_verdict": {...}, "by_domain_tld": {...}}``
    """
    errors: List[str] = []
    upserted = 0

    try:
        logger.info("Fetching URLscan feed: query=%r size=%d", query, size)
        data = _fetch(query=query, size=size)
        rows = parse_results(data)
        upserted = _upsert(rows)
        logger.info("URLscan: upserted %d results", upserted)
    except Exception as exc:  # noqa: BLE001
        logger.warning("URLscan import failed: %s", exc)
        errors.append(f"{type(exc).__name__}: {exc}")

    return _build_summary(results_count=upserted, errors=errors if errors else None)


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def list_results(
    domain: Optional[str] = None,
    verdict: Optional[str] = None,
    since: Optional[str] = None,
    limit: int = 1000,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """List stored URLscan results with optional filters.

    Args:
        domain:  Filter by exact domain match.
        verdict: Filter by verdict string: ``"malicious"`` or ``"clean"``.
        since:   ISO 8601 timestamp; only return entries indexed on/after.
        limit:   Max rows to return.
        offset:  Pagination offset.
    """
    store = _get_store()
    results: List[Dict[str, Any]] = []

    for entry in store.values():
        if not isinstance(entry, dict):
            continue

        if domain and entry.get("domain") != domain:
            continue

        if verdict is not None:
            is_malicious = bool(entry.get("malicious"))
            if verdict == "malicious" and not is_malicious:
                continue
            if verdict == "clean" and is_malicious:
                continue

        if since:
            indexed = entry.get("indexed_at") or entry.get("imported_at") or ""
            if indexed < since:
                continue

        results.append(entry)

    return results[offset: offset + limit]


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import json

    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="URLscan.io feed importer")
    parser.add_argument(
        "--query",
        default=DEFAULT_QUERY,
        help=f"URLscan search query (default: {DEFAULT_QUERY!r})",
    )
    parser.add_argument(
        "--size",
        type=int,
        default=DEFAULT_SIZE,
        help=f"Max results to fetch (default: {DEFAULT_SIZE})",
    )
    args = parser.parse_args()
    result = run_import(query=args.query, size=args.size)
    print(json.dumps(result, indent=2))
