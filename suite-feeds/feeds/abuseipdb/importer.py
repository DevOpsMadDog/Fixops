"""AbuseIPDB / EmergingThreats blocklist importer.

Primary source (no API key required):
    https://rules.emergingthreats.net/blockrules/compromised-ips.txt
    Plain text, one IPv4 address per line. Lines starting with '#' are comments.
    License: BSD-style (Emerging Threats Open Ruleset).

Secondary source (when ABUSEIPDB_API_KEY is set in env):
    https://api.abuseipdb.com/api/v2/blacklist
    Returns top 10K abusive IPs with confidence (0-100) + lastReportedAt + categories.
    License: AbuseIPDB API ToS — free tier 1000 calls/day.

Stored shape (per IP, keyed by ip address):
    {
        "ip": "1.2.3.4",
        "source": "et" | "abuseipdb",
        "confidence_score": int 0-100,        # ET defaults to 100 (presence = blocklist)
        "categories": [int, ...],             # AbuseIPDB category IDs; [] for ET
        "last_reported_at": iso8601 string,
        "imported_at": iso8601 string,
    }

When the same IP appears in both feeds the AbuseIPDB record wins (richer metadata).

DB: data/abuseipdb.db (PersistentDict)
"""

from __future__ import annotations

import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import httpx

logger = logging.getLogger(__name__)

ET_COMPROMISED_IPS_URL = (
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
)
ABUSEIPDB_BLACKLIST_URL = "https://api.abuseipdb.com/api/v2/blacklist"
DOWNLOAD_TIMEOUT = 60.0

_HERE = Path(__file__).resolve()
_PROJECT_ROOT = _HERE.parents[3]  # suite-feeds/feeds/abuseipdb -> project root
_DB_PATH = _PROJECT_ROOT / "data" / "abuseipdb.db"

# IPv4 in dotted-quad form
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$"
)

# Defaults — overridable via run() args
_ET_DEFAULT_CONFIDENCE = 100
_ABUSEIPDB_TOP_N = 10_000
_ABUSEIPDB_MIN_CONFIDENCE = 75


# ---------------------------------------------------------------------------
# Lazy-loaded store
# ---------------------------------------------------------------------------

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
            _store = PersistentDict("abuseipdb_ips", db_path=str(_DB_PATH))
        except TypeError:
            _store = PersistentDict("abuseipdb_ips")
    return _store


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_emergingthreats_text(text: str) -> List[str]:
    """Parse the ET compromised-ips.txt body into a deduped list of IPv4 strings."""
    seen: set[str] = set()
    out: List[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Some lines may have inline comments
        candidate = line.split("#", 1)[0].strip()
        if not _IPV4_RE.match(candidate):
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        out.append(candidate)
    return out


def parse_abuseipdb_payload(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parse the AbuseIPDB /api/v2/blacklist JSON response into normalised dicts."""
    data = payload.get("data") or []
    out: List[Dict[str, Any]] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        ip = entry.get("ipAddress")
        if not ip or not isinstance(ip, str):
            continue
        try:
            confidence = int(entry.get("abuseConfidenceScore", 0))
        except (TypeError, ValueError):
            confidence = 0
        last_reported = entry.get("lastReportedAt") or ""
        categories = entry.get("categories") or []
        if not isinstance(categories, list):
            categories = []
        out.append({
            "ip": ip.strip(),
            "confidence_score": max(0, min(100, confidence)),
            "categories": [int(c) for c in categories if isinstance(c, (int, float))],
            "last_reported_at": str(last_reported),
        })
    return out


# ---------------------------------------------------------------------------
# Upsert
# ---------------------------------------------------------------------------

def _upsert_et(ips: Iterable[str], confidence: int = _ET_DEFAULT_CONFIDENCE) -> int:
    """Upsert IPs from the ET feed. Does NOT overwrite existing AbuseIPDB rows."""
    store = _get_store()
    now = datetime.now(timezone.utc).isoformat()
    count = 0
    for ip in ips:
        existing = store.get(ip) if hasattr(store, "get") else (
            store[ip] if ip in store else None
        )
        if existing and isinstance(existing, dict) and existing.get("source") == "abuseipdb":
            # AbuseIPDB record wins — skip ET overwrite
            count += 1
            continue
        store[ip] = {
            "ip": ip,
            "source": "et",
            "confidence_score": confidence,
            "categories": [],
            "last_reported_at": now,
            "imported_at": now,
        }
        count += 1
    return count


def _upsert_abuseipdb(records: Iterable[Dict[str, Any]]) -> int:
    """Upsert AbuseIPDB records. AbuseIPDB always overwrites ET (richer data)."""
    store = _get_store()
    now = datetime.now(timezone.utc).isoformat()
    count = 0
    for rec in records:
        ip = rec["ip"]
        store[ip] = {
            "ip": ip,
            "source": "abuseipdb",
            "confidence_score": int(rec.get("confidence_score", 0)),
            "categories": rec.get("categories") or [],
            "last_reported_at": rec.get("last_reported_at") or now,
            "imported_at": now,
        }
        count += 1
    return count


# ---------------------------------------------------------------------------
# Core import logic
# ---------------------------------------------------------------------------

def import_emergingthreats_text(text: str, confidence: int = _ET_DEFAULT_CONFIDENCE) -> int:
    """Parse the ET compromised-ips.txt body and upsert. Returns count upserted."""
    ips = parse_emergingthreats_text(text)
    return _upsert_et(ips, confidence=confidence)


def import_abuseipdb_payload(payload: Dict[str, Any]) -> int:
    """Parse an AbuseIPDB blacklist response and upsert. Returns count upserted."""
    records = parse_abuseipdb_payload(payload)
    return _upsert_abuseipdb(records)


def _fetch_emergingthreats(timeout: float = DOWNLOAD_TIMEOUT) -> str:
    """Download the ET compromised-ips.txt body."""
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(ET_COMPROMISED_IPS_URL)
        response.raise_for_status()
        return response.text


def _fetch_abuseipdb(
    api_key: str,
    confidence_minimum: int = _ABUSEIPDB_MIN_CONFIDENCE,
    limit: int = _ABUSEIPDB_TOP_N,
    timeout: float = DOWNLOAD_TIMEOUT,
) -> Dict[str, Any]:
    """Call AbuseIPDB /api/v2/blacklist. Returns the parsed JSON payload."""
    headers = {"Accept": "application/json", "Key": api_key}
    params = {"confidenceMinimum": confidence_minimum, "limit": limit}
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(ABUSEIPDB_BLACKLIST_URL, headers=headers, params=params)
        response.raise_for_status()
        return response.json()


def run_import(
    api_key: Optional[str] = None,
    et_url: Optional[str] = None,
) -> Dict[str, Any]:
    """Run the importer.

    Always pulls the ET compromised-ips list. If *api_key* (or env
    ABUSEIPDB_API_KEY) is set, additionally calls the AbuseIPDB blacklist API.

    Returns:
        {
          "ips": int,            # total IPs in the store after this run
          "by_source": {"et": N, "abuseipdb": N},
          "high_confidence": int # count of IPs with confidence >= 80
        }
    """
    api_key = api_key or os.environ.get("ABUSEIPDB_API_KEY") or None
    url = et_url or ET_COMPROMISED_IPS_URL

    et_count = 0
    aip_count = 0
    errors: List[str] = []

    # ET (primary)
    try:
        logger.info("Fetching ET compromised-ips from %s", url)
        with httpx.Client(timeout=DOWNLOAD_TIMEOUT, follow_redirects=True) as client:
            response = client.get(url)
            response.raise_for_status()
            text = response.text
        et_count = import_emergingthreats_text(text)
    except Exception as exc:  # noqa: BLE001 — network failure is operator-recoverable
        logger.warning("ET import failed: %s", exc)
        errors.append(f"et: {type(exc).__name__}: {exc}")

    # AbuseIPDB (secondary, opt-in via API key)
    if api_key:
        try:
            logger.info("Fetching AbuseIPDB blacklist (top %d)", _ABUSEIPDB_TOP_N)
            payload = _fetch_abuseipdb(api_key=api_key)
            aip_count = import_abuseipdb_payload(payload)
        except Exception as exc:  # noqa: BLE001
            logger.warning("AbuseIPDB import failed: %s", exc)
            errors.append(f"abuseipdb: {type(exc).__name__}: {exc}")

    return _build_summary(errors=errors)


def _build_summary(errors: Optional[List[str]] = None) -> Dict[str, Any]:
    """Compose the post-import summary by walking the store."""
    store = _get_store()
    by_source: Dict[str, int] = {}
    high_conf = 0
    total = 0
    for entry in store.values():
        if not isinstance(entry, dict):
            continue
        total += 1
        src = entry.get("source") or "unknown"
        by_source[src] = by_source.get(src, 0) + 1
        try:
            if int(entry.get("confidence_score", 0)) >= 80:
                high_conf += 1
        except (TypeError, ValueError):
            pass

    summary: Dict[str, Any] = {
        "ips": total,
        "by_source": by_source,
        "high_confidence": high_conf,
    }
    if errors:
        summary["errors"] = errors
    return summary


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def _parse_iso(s: str) -> Optional[datetime]:
    if not s or not isinstance(s, str):
        return None
    try:
        # Accept trailing Z or explicit offset
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def list_ips(
    ip: Optional[str] = None,
    confidence_min: Optional[int] = None,
    last_seen_since: Optional[str] = None,
    source: Optional[str] = None,
    limit: int = 1000,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """List IPs with optional filters.

    Args:
        ip:               exact IP match (returns 0 or 1 entry).
        confidence_min:   minimum confidence_score (0-100).
        last_seen_since:  ISO 8601 timestamp; only IPs with last_reported_at >= this.
        source:           "et" | "abuseipdb".
        limit/offset:     pagination.
    """
    store = _get_store()
    threshold_dt: Optional[datetime] = _parse_iso(last_seen_since) if last_seen_since else None

    results: List[Dict[str, Any]] = []
    for entry in store.values():
        if not isinstance(entry, dict):
            continue
        if ip and entry.get("ip") != ip:
            continue
        if source and entry.get("source") != source:
            continue
        if confidence_min is not None:
            try:
                if int(entry.get("confidence_score", 0)) < int(confidence_min):
                    continue
            except (TypeError, ValueError):
                continue
        if threshold_dt is not None:
            entry_dt = _parse_iso(str(entry.get("last_reported_at") or ""))
            if entry_dt is None or entry_dt < threshold_dt:
                continue
        results.append(entry)

    return results[offset: offset + limit]


def check_ip(ip: str) -> Optional[Dict[str, Any]]:
    """Return the stored entry for *ip*, or None if not found."""
    if not ip:
        return None
    store = _get_store()
    entry = store.get(ip) if hasattr(store, "get") else (store[ip] if ip in store else None)
    if not isinstance(entry, dict):
        return None
    return entry


def get_store_stats() -> Dict[str, Any]:
    """Return total count, by_source breakdown, and high-confidence count."""
    return _build_summary()


def total_count() -> int:
    return len(_get_store())
