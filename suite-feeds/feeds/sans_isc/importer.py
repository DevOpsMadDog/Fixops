"""SANS Internet Storm Center (ISC) importer.

Sources (public, no API key required):
    https://isc.sans.edu/api/sources/attacks/100  — top 100 attack source IPs
    https://isc.sans.edu/api/topports              — top attacked ports

Both endpoints return JSON.  The importer fetches both, stores them in two
tables inside data/sans_isc.db, and **replaces** (snapshot-style — full table
wipe before insert) on every run.

Stored shapes
-------------
top_sources table (keyed by ip):
    {
        "ip": "1.2.3.4",
        "country": "CN",
        "attack_count": 1234,
        "first_seen": "2024-01-01",
        "last_seen":  "2024-04-27",
        "imported_at": "<iso8601>",
    }

top_ports table (keyed by str(port)):
    {
        "port": 22,
        "service": "ssh",
        "attack_count": 9876,
        "imported_at": "<iso8601>",
    }

DB: data/sans_isc.db (PersistentDict pattern — two namespaces)
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

SANS_SOURCES_URL = "https://isc.sans.edu/api/sources/attacks/100"
SANS_TOP_PORTS_URL = "https://isc.sans.edu/api/topports"
DOWNLOAD_TIMEOUT = 30.0

_HERE = Path(__file__).resolve()
_PROJECT_ROOT = _HERE.parents[3]  # suite-feeds/feeds/sans_isc -> project root
_DB_PATH = _PROJECT_ROOT / "data" / "sans_isc.db"


# ---------------------------------------------------------------------------
# Store helpers (two PersistentDict namespaces in one DB file)
# ---------------------------------------------------------------------------

_sources_store = None
_ports_store = None


def _ensure_path(suite_core: str) -> None:
    if suite_core not in sys.path:
        sys.path.insert(0, suite_core)


def _get_sources_store():
    global _sources_store
    if _sources_store is None:
        _ensure_path(str(_PROJECT_ROOT / "suite-core"))
        try:
            from core.persistent_store import PersistentDict
        except ImportError:
            from collections import UserDict as PersistentDict  # type: ignore[assignment]
        _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        try:
            _sources_store = PersistentDict("sans_isc_sources", db_path=str(_DB_PATH))
        except TypeError:
            _sources_store = PersistentDict("sans_isc_sources")
    return _sources_store


def _get_ports_store():
    global _ports_store
    if _ports_store is None:
        _ensure_path(str(_PROJECT_ROOT / "suite-core"))
        try:
            from core.persistent_store import PersistentDict
        except ImportError:
            from collections import UserDict as PersistentDict  # type: ignore[assignment]
        _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        try:
            _ports_store = PersistentDict("sans_isc_ports", db_path=str(_DB_PATH))
        except TypeError:
            _ports_store = PersistentDict("sans_isc_ports")
    return _ports_store


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_top_sources(payload: Any) -> List[Dict[str, Any]]:
    """Parse the /api/sources/attacks/N JSON response.

    The API returns either:
      - a list of dicts directly, or
      - {"sources": [...]}

    Each entry contains keys like: ipCount, country, attacks, maxdate, mindate
    (field names vary between API versions — we handle both snake_case and
    camelCase gracefully).
    """
    rows: List[Any] = []
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        for key in ("sources", "data", "results"):
            if isinstance(payload.get(key), list):
                rows = payload[key]
                break
        if not rows:
            rows = list(payload.values()) if payload else []

    out: List[Dict[str, Any]] = []
    for entry in rows:
        if not isinstance(entry, dict):
            continue
        ip = (
            entry.get("ip")
            or entry.get("ipAddress")
            or entry.get("source")
            or ""
        )
        if not ip or not isinstance(ip, str):
            continue
        ip = ip.strip()

        country = str(
            entry.get("country") or entry.get("cc") or entry.get("CountryCode") or ""
        ).strip()

        attack_count = 0
        for key in ("attacks", "attack_count", "count", "ipCount"):
            val = entry.get(key)
            if val is not None:
                try:
                    attack_count = int(val)
                    break
                except (TypeError, ValueError):
                    pass

        first_seen = str(
            entry.get("first_seen")
            or entry.get("mindate")
            or entry.get("firstSeen")
            or ""
        ).strip()
        last_seen = str(
            entry.get("last_seen")
            or entry.get("maxdate")
            or entry.get("lastSeen")
            or ""
        ).strip()

        out.append({
            "ip": ip,
            "country": country,
            "attack_count": attack_count,
            "first_seen": first_seen,
            "last_seen": last_seen,
        })
    return out


def parse_top_ports(payload: Any) -> List[Dict[str, Any]]:
    """Parse the /api/topports JSON response.

    The API returns either a list or {"ports": [...]}.
    Each entry contains keys like: targetPort, records, service.
    """
    rows: List[Any] = []
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        for key in ("ports", "data", "results"):
            if isinstance(payload.get(key), list):
                rows = payload[key]
                break
        if not rows:
            rows = list(payload.values()) if payload else []

    out: List[Dict[str, Any]] = []
    for entry in rows:
        if not isinstance(entry, dict):
            continue

        port_val = (
            entry.get("port")
            or entry.get("targetPort")
            or entry.get("target_port")
            or entry.get("dstport")
        )
        if port_val is None:
            continue
        try:
            port = int(port_val)
        except (TypeError, ValueError):
            continue

        service = str(
            entry.get("service")
            or entry.get("serviceName")
            or entry.get("service_name")
            or ""
        ).strip()

        attack_count = 0
        for key in ("records", "attack_count", "count", "attacks", "total"):
            val = entry.get(key)
            if val is not None:
                try:
                    attack_count = int(val)
                    break
                except (TypeError, ValueError):
                    pass

        out.append({
            "port": port,
            "service": service,
            "attack_count": attack_count,
        })
    return out


# ---------------------------------------------------------------------------
# Store — snapshot replace (wipe then insert)
# ---------------------------------------------------------------------------

def _replace_sources(records: List[Dict[str, Any]], now: str) -> int:
    store = _get_sources_store()
    # Clear existing snapshot
    for key in list(store.keys()):
        del store[key]
    for rec in records:
        rec["imported_at"] = now
        store[rec["ip"]] = rec
    return len(records)


def _replace_ports(records: List[Dict[str, Any]], now: str) -> int:
    store = _get_ports_store()
    for key in list(store.keys()):
        del store[key]
    for rec in records:
        rec["imported_at"] = now
        store[str(rec["port"])] = rec
    return len(records)


# ---------------------------------------------------------------------------
# HTTP fetch
# ---------------------------------------------------------------------------

def _fetch_json(url: str, timeout: float = DOWNLOAD_TIMEOUT) -> Any:
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        response = client.get(url, headers={"Accept": "application/json"})
        response.raise_for_status()
        return response.json()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_import(
    sources_url: Optional[str] = None,
    ports_url: Optional[str] = None,
    timeout: float = DOWNLOAD_TIMEOUT,
) -> Dict[str, Any]:
    """Fetch both SANS ISC endpoints, replace local tables, return summary.

    Returns:
        {"top_sources": N, "top_ports": N}
    """
    sources_url = sources_url or SANS_SOURCES_URL
    ports_url = ports_url or SANS_TOP_PORTS_URL
    now = datetime.now(timezone.utc).isoformat()

    source_count = 0
    port_count = 0
    errors: List[str] = []

    # -- top attack sources --
    try:
        logger.info("Fetching SANS ISC top attack sources from %s", sources_url)
        payload = _fetch_json(sources_url, timeout=timeout)
        records = parse_top_sources(payload)
        source_count = _replace_sources(records, now)
        logger.info("SANS ISC: stored %d top attack sources", source_count)
    except Exception as exc:  # noqa: BLE001
        logger.warning("SANS ISC sources import failed: %s", exc)
        errors.append(f"sources: {type(exc).__name__}: {exc}")

    # -- top ports --
    try:
        logger.info("Fetching SANS ISC top ports from %s", ports_url)
        payload = _fetch_json(ports_url, timeout=timeout)
        records = parse_top_ports(payload)
        port_count = _replace_ports(records, now)
        logger.info("SANS ISC: stored %d top ports", port_count)
    except Exception as exc:  # noqa: BLE001
        logger.warning("SANS ISC ports import failed: %s", exc)
        errors.append(f"ports: {type(exc).__name__}: {exc}")

    result: Dict[str, Any] = {
        "top_sources": source_count,
        "top_ports": port_count,
    }
    if errors:
        result["errors"] = errors
    return result


def get_top_sources(
    limit: int = 100,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """Return stored top attack sources sorted by attack_count descending."""
    store = _get_sources_store()
    rows = [v for v in store.values() if isinstance(v, dict)]
    rows.sort(key=lambda r: int(r.get("attack_count") or 0), reverse=True)
    return rows[offset: offset + limit]


def get_top_ports(
    limit: int = 100,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """Return stored top ports sorted by attack_count descending."""
    store = _get_ports_store()
    rows = [v for v in store.values() if isinstance(v, dict)]
    rows.sort(key=lambda r: int(r.get("attack_count") or 0), reverse=True)
    return rows[offset: offset + limit]


def total_source_count() -> int:
    return len(_get_sources_store())


def total_port_count() -> int:
    return len(_get_ports_store())
