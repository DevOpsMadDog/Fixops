"""URLhaus malicious-URL feed importer (abuse.ch).

Source (no auth required):
    Recent (last 1000):  https://urlhaus.abuse.ch/downloads/csv_recent/
    Full (~1M URLs):     https://urlhaus.abuse.ch/downloads/csv/

CSV columns (after stripping comment lines that start with '#'):
    id, dateadded, url, url_status, last_online, threat, tags,
    urlhaus_link, reporter

Stored shape (keyed by URLhaus id):
    {
        "id": str,
        "dateadded": str,       # ISO 8601
        "url": str,
        "url_status": str,      # "online" | "offline" | ""
        "last_online": str,
        "threat": str,          # "malware_download" | etc.
        "tags": [str, ...],
        "urlhaus_link": str,
        "reporter": str,
        "imported_at": str,     # ISO 8601 UTC
    }

DB: data/urlhaus.db  (PersistentDict)

CLI usage:
    python -m feeds.urlhaus.importer           # recent feed (last 1000)
    python -m feeds.urlhaus.importer --full    # full feed (~1M)
"""

from __future__ import annotations

import csv
import io
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

URLHAUS_RECENT_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
URLHAUS_FULL_URL = "https://urlhaus.abuse.ch/downloads/csv/"

DOWNLOAD_TIMEOUT = 60.0

# ---------------------------------------------------------------------------
# Paths / store
# ---------------------------------------------------------------------------

_HERE = Path(__file__).resolve()
_PROJECT_ROOT = _HERE.parents[3]  # suite-feeds/feeds/urlhaus -> project root
_DB_PATH = _PROJECT_ROOT / "data" / "urlhaus.db"

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
            _store = PersistentDict("urlhaus_urls", db_path=str(_DB_PATH))
        except TypeError:
            _store = PersistentDict("urlhaus_urls")
    return _store


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

_CSV_FIELDS = [
    "id", "dateadded", "url", "url_status", "last_online",
    "threat", "tags", "urlhaus_link", "reporter",
]


def parse_csv_text(text: str) -> List[Dict[str, Any]]:
    """Parse URLhaus CSV text.

    Lines beginning with '#' are comment/header lines and are skipped.
    Returns a list of normalised row dicts.
    """
    rows: List[Dict[str, Any]] = []
    # Strip comment lines before handing to DictReader so the reader sees
    # only data rows (the first non-comment line is the actual CSV header).
    clean_lines: List[str] = []
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        clean_lines.append(line)

    if not clean_lines:
        return rows

    reader = csv.DictReader(io.StringIO("\n".join(clean_lines)))
    now_iso = datetime.now(timezone.utc).isoformat()

    for row in reader:
        # Normalise field names (strip whitespace)
        row = {k.strip(): (v.strip() if isinstance(v, str) else v) for k, v in row.items()}

        entry_id = row.get("id") or row.get("# id") or ""
        if not entry_id:
            continue

        raw_tags = row.get("tags") or ""
        tags = [t.strip() for t in raw_tags.split(",") if t.strip()] if raw_tags else []

        rows.append({
            "id": entry_id,
            "dateadded": row.get("dateadded") or "",
            "url": row.get("url") or "",
            "url_status": row.get("url_status") or "",
            "last_online": row.get("last_online") or "",
            "threat": row.get("threat") or "",
            "tags": tags,
            "urlhaus_link": row.get("urlhaus_link") or "",
            "reporter": row.get("reporter") or "",
            "imported_at": now_iso,
        })

    return rows


# ---------------------------------------------------------------------------
# Upsert
# ---------------------------------------------------------------------------

def _upsert(rows: List[Dict[str, Any]]) -> int:
    """Upsert rows by id. Returns count upserted."""
    store = _get_store()
    count = 0
    for row in rows:
        entry_id = row["id"]
        store[entry_id] = row
        count += 1
    return count


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

def _fetch(url: str, timeout: float = DOWNLOAD_TIMEOUT) -> str:
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(url)
        response.raise_for_status()
        return response.text


# ---------------------------------------------------------------------------
# Summary helpers
# ---------------------------------------------------------------------------

def _build_summary(errors: Optional[List[str]] = None) -> Dict[str, Any]:
    store = _get_store()
    by_threat: Dict[str, int] = {}
    by_status: Dict[str, int] = {}
    total = 0

    for entry in store.values():
        if not isinstance(entry, dict):
            continue
        total += 1
        threat = entry.get("threat") or "unknown"
        by_threat[threat] = by_threat.get(threat, 0) + 1
        status = entry.get("url_status") or "unknown"
        by_status[status] = by_status.get(status, 0) + 1

    summary: Dict[str, Any] = {
        "urls": total,
        "by_threat": by_threat,
        "by_status": by_status,
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

def run_import(full: bool = False) -> Dict[str, Any]:
    """Pull the URLhaus CSV feed and upsert into local DB.

    Args:
        full: If True, download the full feed (~1M URLs).
              Defaults to the recent feed (last 1000 URLs).

    Returns:
        {"urls": N, "by_threat": {...}, "by_status": {...}}
    """
    url = URLHAUS_FULL_URL if full else URLHAUS_RECENT_URL
    errors: List[str] = []

    try:
        logger.info("Fetching URLhaus feed from %s", url)
        text = _fetch(url)
        rows = parse_csv_text(text)
        _upsert(rows)
        logger.info("URLhaus: upserted %d rows", len(rows))
    except Exception as exc:  # noqa: BLE001
        logger.warning("URLhaus import failed: %s", exc)
        errors.append(f"{type(exc).__name__}: {exc}")

    return _build_summary(errors=errors if errors else None)


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def list_urls(
    threat: Optional[str] = None,
    url_status: Optional[str] = None,
    limit: int = 1000,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """List stored URLs with optional filters.

    Args:
        threat:     Filter by threat type (e.g. "malware_download").
        url_status: Filter by status ("online" | "offline").
        limit:      Max rows to return.
        offset:     Pagination offset.
    """
    store = _get_store()
    results: List[Dict[str, Any]] = []

    for entry in store.values():
        if not isinstance(entry, dict):
            continue
        if threat and entry.get("threat") != threat:
            continue
        if url_status and entry.get("url_status") != url_status:
            continue
        results.append(entry)

    return results[offset: offset + limit]


def check_url(url: str) -> Optional[Dict[str, Any]]:
    """Return the stored entry whose 'url' field equals *url*, or None.

    Note: the store is keyed by URLhaus id; we do a linear scan here.
    For high-volume membership checks at scale, build a secondary index.
    """
    if not url:
        return None
    store = _get_store()
    for entry in store.values():
        if isinstance(entry, dict) and entry.get("url") == url:
            return entry
    return None


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="URLhaus feed importer")
    parser.add_argument(
        "--full", action="store_true",
        help="Download full feed (~1M URLs) instead of recent (last 1000)",
    )
    args = parser.parse_args()
    result = run_import(full=args.full)
    import json
    print(json.dumps(result, indent=2))
