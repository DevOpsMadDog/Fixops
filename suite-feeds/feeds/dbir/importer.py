"""DBIR / VERIS Community Database (VCDB) Importer.

Source: https://github.com/vz-risk/VCDB — public breach incident dataset that
backs the Verizon Data Breach Investigations Report (DBIR). Each incident is a
JSON file under data/json/validated/.

Pulls the master tarball, walks the validated incidents, normalises them into
the shape ALDECI consumes, and upserts into data/dbir.db (PersistentDict).

Returns a summary keyed by action_pattern, actor, and victim NAICS.
"""

from __future__ import annotations

import io
import json
import logging
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import httpx

logger = logging.getLogger(__name__)

VCDB_TAR_URL = "https://github.com/vz-risk/VCDB/archive/refs/heads/master.tar.gz"
DOWNLOAD_TIMEOUT = 90.0  # seconds

_VALIDATED_PATH_PARTS = ("data", "json", "validated")
_ACTION_PATTERNS = (
    "malware",
    "hacking",
    "social",
    "error",
    "misuse",
    "physical",
    "environmental",
)
_ACTOR_TYPES = ("external", "internal", "partner")
_ATTRIBUTES = ("confidentiality", "integrity", "availability")

_HERE = Path(__file__).resolve()
_PROJECT_ROOT = _HERE.parents[3]  # suite-feeds/feeds/dbir -> project root
_DB_PATH = _PROJECT_ROOT / "data" / "dbir.db"


# ---------------------------------------------------------------------------
# Lazy-loaded store
# ---------------------------------------------------------------------------

_store = None


def _get_store():
    global _store
    if _store is None:
        try:
            import sys
            sys.path.insert(0, str(_PROJECT_ROOT / "suite-core"))
            from core.persistent_store import PersistentDict
        except ImportError:
            from collections import UserDict as PersistentDict  # type: ignore[assignment]

        _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        try:
            _store = PersistentDict("dbir_incidents", db_path=str(_DB_PATH))
        except TypeError:
            _store = PersistentDict("dbir_incidents")
    return _store


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _extract_action_patterns(action: Any) -> List[str]:
    """Return action pattern keys that are present in the incident.

    VERIS allows multiple simultaneous patterns (e.g. malware + hacking).
    """
    if not isinstance(action, dict):
        return []
    return [p for p in _ACTION_PATTERNS if p in action]


def _extract_actors(actor: Any) -> List[str]:
    if not isinstance(actor, dict):
        return []
    return [a for a in _ACTOR_TYPES if a in actor]


def _extract_attributes(attribute: Any) -> List[str]:
    if not isinstance(attribute, dict):
        return []
    return [a for a in _ATTRIBUTES if a in attribute]


def _extract_asset_categories(asset: Any) -> List[str]:
    """Pull asset variety prefixes (S, P, M, N, U, T) from asset.assets[]."""
    if not isinstance(asset, dict):
        return []
    assets = asset.get("assets") or []
    cats: List[str] = []
    for entry in assets:
        if not isinstance(entry, dict):
            continue
        variety = entry.get("variety")
        if isinstance(variety, str) and variety:
            # VERIS variety strings look like "S - Web application"
            head = variety.split("-", 1)[0].strip()
            if head:
                cats.append(head)
    return list(dict.fromkeys(cats))


def _extract_discovery_method(discovery_method: Any) -> str:
    """Return the first non-empty key of the discovery_method dict."""
    if not isinstance(discovery_method, dict):
        return ""
    for key in discovery_method:
        if discovery_method[key]:
            return key
    return next(iter(discovery_method), "")


def _coerce_naics(industry: Any) -> str:
    if isinstance(industry, str):
        return industry
    if isinstance(industry, (int, float)):
        return str(int(industry))
    if isinstance(industry, list) and industry:
        first = industry[0]
        if isinstance(first, (str, int, float)):
            return str(first)
    return ""


def _coerce_country(country: Any) -> List[str]:
    if isinstance(country, list):
        return [str(c) for c in country if c]
    if isinstance(country, str) and country:
        return [country]
    return []


def parse_incident(doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalise a single VERIS incident dict.

    Returns None if the document is missing an incident_id.
    """
    if not isinstance(doc, dict):
        return None

    incident_id = doc.get("incident_id")
    if not incident_id:
        return None

    action = doc.get("action") or {}
    actor = doc.get("actor") or {}
    asset = doc.get("asset") or {}
    attribute = doc.get("attribute") or {}
    discovery = doc.get("discovery_method") or {}
    victim = doc.get("victim") or {}
    timeline = doc.get("timeline") or {}

    action_patterns = _extract_action_patterns(action)
    actors = _extract_actors(actor)
    attributes = _extract_attributes(attribute)
    asset_categories = _extract_asset_categories(asset)

    return {
        "incident_id": str(incident_id),
        "summary": doc.get("summary", ""),
        "action_patterns": action_patterns,
        "primary_action_pattern": action_patterns[0] if action_patterns else "unknown",
        "actors": actors,
        "primary_actor": actors[0] if actors else "unknown",
        "asset_categories": asset_categories,
        "attributes": attributes,
        "discovery_method": _extract_discovery_method(discovery),
        "victim": {
            "industry_naics": _coerce_naics(victim.get("industry")),
            "employee_count": victim.get("employee_count", ""),
            "country": _coerce_country(victim.get("country")),
        },
        "timeline": timeline,
        "raw_action": action,
        "imported_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Path filter
# ---------------------------------------------------------------------------

def _is_validated_incident(name: str) -> bool:
    """Return True iff name is a JSON file inside data/json/validated/."""
    if not name.endswith(".json"):
        return False
    parts = Path(name).parts
    if len(parts) < 4:
        return False
    # Look for the consecutive triple "data", "json", "validated"
    for i in range(len(parts) - 2):
        if parts[i:i + 3] == _VALIDATED_PATH_PARTS:
            return True
    return False


# ---------------------------------------------------------------------------
# Core import logic
# ---------------------------------------------------------------------------

def import_incidents_from_archive(tar_bytes: bytes) -> Dict[str, Any]:
    """Extract incidents from tar.gz bytes, parse, upsert, return summary."""
    store = _get_store()
    parsed = 0
    skipped = 0
    by_action_pattern: Dict[str, int] = {}
    by_actor: Dict[str, int] = {}
    by_industry_naics: Dict[str, int] = {}

    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            if not _is_validated_incident(member.name):
                continue

            try:
                f = tf.extractfile(member)
                if f is None:
                    continue
                doc = json.loads(f.read().decode("utf-8", errors="replace"))
            except (json.JSONDecodeError, OSError) as exc:
                logger.debug("Failed to parse %s: %s", member.name, exc)
                skipped += 1
                continue

            incident = parse_incident(doc)
            if incident is None:
                skipped += 1
                continue

            store[incident["incident_id"]] = incident
            parsed += 1

            for ap in incident["action_patterns"] or ["unknown"]:
                by_action_pattern[ap] = by_action_pattern.get(ap, 0) + 1
            for ac in incident["actors"] or ["unknown"]:
                by_actor[ac] = by_actor.get(ac, 0) + 1
            naics = incident["victim"]["industry_naics"] or "unknown"
            by_industry_naics[naics] = by_industry_naics.get(naics, 0) + 1

    logger.info("DBIR/VCDB import complete: %d incidents parsed, %d skipped", parsed, skipped)
    return {
        "incidents": parsed,
        "skipped": skipped,
        "by_action_pattern": by_action_pattern,
        "by_actor": by_actor,
        "by_industry_naics": by_industry_naics,
    }


def run_import() -> Dict[str, Any]:
    """Download VCDB master archive and import all validated incidents."""
    logger.info("Downloading VCDB from %s", VCDB_TAR_URL)
    with httpx.Client(timeout=DOWNLOAD_TIMEOUT, follow_redirects=True) as client:
        response = client.get(VCDB_TAR_URL)
        response.raise_for_status()
        tar_bytes = response.content

    logger.info("Downloaded %d bytes, extracting incidents…", len(tar_bytes))
    return import_incidents_from_archive(tar_bytes)


# ---------------------------------------------------------------------------
# Query helpers (used by the API endpoint)
# ---------------------------------------------------------------------------

def list_incidents(
    action_pattern: Optional[str] = None,
    actor: Optional[str] = None,
    industry_naics: Optional[str] = None,
    limit: int = 500,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """Return incidents from the DB with optional filters."""
    store = _get_store()
    results: List[Dict[str, Any]] = []

    ap_lc = action_pattern.lower() if action_pattern else None
    actor_lc = actor.lower() if actor else None

    for inc in store.values():
        if not isinstance(inc, dict):
            continue

        if ap_lc:
            patterns = [p.lower() for p in (inc.get("action_patterns") or [])]
            if ap_lc not in patterns:
                continue

        if actor_lc:
            actors = [a.lower() for a in (inc.get("actors") or [])]
            if actor_lc not in actors:
                continue

        if industry_naics:
            naics = (inc.get("victim") or {}).get("industry_naics", "")
            if not str(naics).startswith(str(industry_naics)):
                continue

        results.append(inc)

    return results[offset: offset + limit]


def get_store_stats() -> Dict[str, Any]:
    """Return total incident count and breakdowns."""
    store = _get_store()
    total = len(store)
    by_action_pattern: Dict[str, int] = {}
    by_actor: Dict[str, int] = {}
    by_industry_naics: Dict[str, int] = {}

    for inc in store.values():
        if not isinstance(inc, dict):
            continue
        for ap in inc.get("action_patterns") or ["unknown"]:
            by_action_pattern[ap] = by_action_pattern.get(ap, 0) + 1
        for ac in inc.get("actors") or ["unknown"]:
            by_actor[ac] = by_actor.get(ac, 0) + 1
        naics = (inc.get("victim") or {}).get("industry_naics") or "unknown"
        by_industry_naics[naics] = by_industry_naics.get(naics, 0) + 1

    return {
        "total": total,
        "by_action_pattern": by_action_pattern,
        "by_actor": by_actor,
        "by_industry_naics": by_industry_naics,
    }
