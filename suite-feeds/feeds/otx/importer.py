"""AlienVault OTX (Open Threat Exchange) Pulses + Indicators importer.

Source: AlienVault OTX REST API
  - Public activity endpoint (no auth):
        https://otx.alienvault.com/api/v1/pulses/activity?limit=50
  - Authenticated subscribed endpoint (requires X-OTX-API-KEY header):
        https://otx.alienvault.com/api/v1/pulses/subscribed

Each OTX *pulse* is a curated threat-intel report containing metadata
(author, references, tags, malware families, MITRE ATT&CK technique IDs)
plus a list of indicators (IPv4/IPv6/domain/hostname/URL/email/file hashes/CVE).

The importer:
  * defaults to the public-activity endpoint when ``OTX_API_KEY`` is unset,
    and switches to the subscribed endpoint when the env var is provided
  * persists pulses keyed by ``id`` into ``data/otx.db``
  * flattens every pulse's ``indicators[*]`` into a separate ``indicators``
    namespace keyed by ``"<pulse_id>::<indicator_id_or_value>"`` so the
    list-indicators endpoint can filter by type / pulse / since
  * is idempotent: re-running with the same payload does not create
    duplicate rows

Returns::

    {
        "pulses": <int>,
        "indicators": <int>,
        "by_indicator_type": {"IPv4": N, "domain": N, ...},
        "with_attack_id": <int>,
    }
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
OTX_PUBLIC_ACTIVITY_URL = f"{OTX_BASE_URL}/pulses/activity"
OTX_SUBSCRIBED_URL = f"{OTX_BASE_URL}/pulses/subscribed"
DOWNLOAD_TIMEOUT = 60.0

_HERE = Path(__file__).resolve()
_PROJECT_ROOT = _HERE.parents[3]  # suite-feeds/feeds/otx -> project root
_DB_PATH = _PROJECT_ROOT / "data" / "otx.db"

_INDICATOR_TYPES: Tuple[str, ...] = (
    "IPv4",
    "IPv6",
    "domain",
    "hostname",
    "URL",
    "URI",
    "email",
    "FileHash-MD5",
    "FileHash-SHA1",
    "FileHash-SHA256",
    "FileHash-SHA512",
    "FileHash-PEHASH",
    "FileHash-IMPHASH",
    "CIDR",
    "FilePath",
    "Mutex",
    "CVE",
    "YARA",
    "JA3",
    "BitcoinAddress",
)


# ---------------------------------------------------------------------------
# Lazy-loaded stores
# ---------------------------------------------------------------------------

_pulses_store = None
_indicators_store = None


def _load_persistent_dict():
    """Return the PersistentDict class, falling back to dict for stripped envs."""
    try:
        suite_core = str(_PROJECT_ROOT / "suite-core")
        if suite_core not in sys.path:
            sys.path.insert(0, suite_core)
        from core.persistent_store import PersistentDict
        return PersistentDict
    except ImportError:
        from collections import UserDict
        return UserDict  # type: ignore[return-value]


def _open_store(table: str):
    PersistentDict = _load_persistent_dict()
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        return PersistentDict(table, db_path=str(_DB_PATH))
    except TypeError:
        return PersistentDict(table)


def _get_pulses_store():
    global _pulses_store
    if _pulses_store is None:
        _pulses_store = _open_store("otx_pulses")
    return _pulses_store


def _get_indicators_store():
    global _indicators_store
    if _indicators_store is None:
        _indicators_store = _open_store("otx_indicators")
    return _indicators_store


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _coerce_str_list(value: Any) -> List[str]:
    if isinstance(value, list):
        out: List[str] = []
        for item in value:
            if isinstance(item, str) and item:
                out.append(item)
            elif isinstance(item, dict):
                # OTX malware_families / attack_ids items are dicts with display_name + id
                ident = item.get("display_name") or item.get("name") or item.get("id")
                if isinstance(ident, str) and ident:
                    out.append(ident)
        return out
    if isinstance(value, str) and value:
        return [value]
    return []


def _extract_attack_ids(value: Any) -> List[str]:
    """Return MITRE ATT&CK technique IDs (T#### / T####.###) found in a pulse."""
    if not isinstance(value, list):
        return []
    out: List[str] = []
    for entry in value:
        if isinstance(entry, dict):
            tid = entry.get("id") or entry.get("display_name") or entry.get("name")
            if isinstance(tid, str) and tid:
                out.append(tid.strip())
        elif isinstance(entry, str) and entry:
            out.append(entry.strip())
    return out


def _normalise_indicator_type(raw: Any) -> str:
    """Return canonical indicator type string. Unknown types are passed through."""
    if not isinstance(raw, str):
        return ""
    s = raw.strip()
    if not s:
        return ""
    # OTX is mostly canonical already (IPv4, domain, FileHash-SHA256, CVE, …)
    return s


def _indicator_key(pulse_id: str, indicator: Dict[str, Any]) -> str:
    """Build a stable composite key for an indicator inside the indicators store."""
    ind_id = indicator.get("id")
    if ind_id is not None and str(ind_id):
        return f"{pulse_id}::{ind_id}"
    # fall back to (type, value)
    t = indicator.get("type") or ""
    v = indicator.get("indicator") or indicator.get("value") or ""
    return f"{pulse_id}::{t}:{v}"


def parse_indicator(pulse_id: str, raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, dict):
        return None
    value = raw.get("indicator") or raw.get("value")
    ind_type = _normalise_indicator_type(raw.get("type"))
    if not value or not ind_type:
        return None
    return {
        "key": _indicator_key(pulse_id, raw),
        "pulse_id": pulse_id,
        "indicator_id": str(raw.get("id")) if raw.get("id") is not None else "",
        "type": ind_type,
        "indicator": str(value),
        "description": raw.get("description", "") or "",
        "created": raw.get("created", "") or "",
        "expiration": raw.get("expiration", "") or "",
        "is_active": bool(raw.get("is_active", True)),
        "title": raw.get("title", "") or "",
        "content": raw.get("content", "") or "",
        "role": raw.get("role", "") or "",
    }


def parse_pulse(doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalise a single OTX pulse document.

    Returns None if the pulse has no ``id``.
    """
    if not isinstance(doc, dict):
        return None
    pulse_id = doc.get("id")
    if not isinstance(pulse_id, str) or not pulse_id:
        return None

    indicators_raw = doc.get("indicators") or []
    indicators: List[Dict[str, Any]] = []
    for ind in indicators_raw:
        parsed = parse_indicator(pulse_id, ind if isinstance(ind, dict) else {})
        if parsed is not None:
            indicators.append(parsed)

    attack_ids = _extract_attack_ids(doc.get("attack_ids"))
    malware_families = _coerce_str_list(doc.get("malware_families"))
    industries = _coerce_str_list(doc.get("industries"))
    targeted_countries = _coerce_str_list(doc.get("targeted_countries"))

    return {
        "id": pulse_id,
        "name": doc.get("name", "") or "",
        "description": doc.get("description", "") or "",
        "author_name": doc.get("author_name", "") or "",
        "created": doc.get("created", "") or "",
        "modified": doc.get("modified", "") or "",
        "references": _coerce_str_list(doc.get("references")),
        "tags": _coerce_str_list(doc.get("tags")),
        "malware_families": malware_families,
        "attack_ids": attack_ids,
        "industries": industries,
        "targeted_countries": targeted_countries,
        "tlp": doc.get("tlp", "") or "",
        "adversary": doc.get("adversary", "") or "",
        "public": bool(doc.get("public", True)),
        "indicator_count": len(indicators),
        "imported_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------

def import_pulses(pulses: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Persist parsed pulses + flattened indicators. Idempotent.

    Accepts an iterable of *raw* pulse dicts as returned by the OTX API
    ``results`` array.
    """
    pulses_store = _get_pulses_store()
    indicators_store = _get_indicators_store()

    pulses_count = 0
    indicators_count = 0
    skipped_pulses = 0
    by_indicator_type: Dict[str, int] = {}
    with_attack_id = 0

    for raw_pulse in pulses:
        if not isinstance(raw_pulse, dict):
            skipped_pulses += 1
            continue

        parsed = parse_pulse(raw_pulse)
        if parsed is None:
            skipped_pulses += 1
            continue

        pulse_id = parsed["id"]
        pulses_store[pulse_id] = parsed
        pulses_count += 1
        if parsed["attack_ids"]:
            with_attack_id += 1

        for ind in raw_pulse.get("indicators") or []:
            parsed_ind = parse_indicator(pulse_id, ind if isinstance(ind, dict) else {})
            if parsed_ind is None:
                continue
            indicators_store[parsed_ind["key"]] = parsed_ind
            indicators_count += 1
            t = parsed_ind["type"] or "unknown"
            by_indicator_type[t] = by_indicator_type.get(t, 0) + 1

    return {
        "pulses": pulses_count,
        "indicators": indicators_count,
        "by_indicator_type": by_indicator_type,
        "with_attack_id": with_attack_id,
        "skipped_pulses": skipped_pulses,
    }


# ---------------------------------------------------------------------------
# Network fetch
# ---------------------------------------------------------------------------

def _fetch_otx(api_key: Optional[str], limit: int = 50, max_pages: int = 1) -> List[Dict[str, Any]]:
    """Fetch pulses from OTX. Uses subscribed endpoint when *api_key* is set."""
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("httpx is required to fetch OTX pulses") from exc

    headers: Dict[str, str] = {
        "User-Agent": "ALDECI-Fixops/1.0 (+OTX-importer)",
        "Accept": "application/json",
    }
    if api_key:
        url = OTX_SUBSCRIBED_URL
        headers["X-OTX-API-KEY"] = api_key
    else:
        url = OTX_PUBLIC_ACTIVITY_URL

    pulses: List[Dict[str, Any]] = []
    pages_fetched = 0
    next_url: Optional[str] = f"{url}?limit={limit}"

    with httpx.Client(timeout=DOWNLOAD_TIMEOUT, follow_redirects=True) as client:
        while next_url and pages_fetched < max_pages:
            logger.info("OTX: GET %s", next_url)
            resp = client.get(next_url, headers=headers)
            resp.raise_for_status()
            payload = resp.json()
            results = payload.get("results") or payload.get("pulses") or []
            if isinstance(results, list):
                pulses.extend(p for p in results if isinstance(p, dict))
            pages_fetched += 1
            nxt = payload.get("next")
            next_url = nxt if isinstance(nxt, str) and nxt else None

    return pulses


def run_import(
    api_key: Optional[str] = None,
    limit: int = 50,
    max_pages: int = 1,
) -> Dict[str, Any]:
    """Fetch pulses (subscribed when api_key set, else public activity) and import."""
    if api_key is None:
        api_key = os.environ.get("OTX_API_KEY") or None

    raw_pulses = _fetch_otx(api_key=api_key, limit=limit, max_pages=max_pages)
    logger.info("OTX: %d raw pulses fetched (auth=%s)", len(raw_pulses), bool(api_key))
    return import_pulses(raw_pulses)


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def _to_dt(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    s = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        # Fall back to date-only ISO
        try:
            return datetime.strptime(value[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            return None


def list_pulses(
    pulse_id: Optional[str] = None,
    author: Optional[str] = None,
    tag: Optional[str] = None,
    since: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """Return pulses from the DB with optional filters and pagination."""
    store = _get_pulses_store()

    since_dt = _to_dt(since) if since else None
    author_lc = author.lower() if author else None
    tag_lc = tag.lower() if tag else None

    rows: List[Dict[str, Any]] = []
    for pid, pulse in store.items():
        if not isinstance(pulse, dict):
            continue
        if pulse_id and pulse.get("id") != pulse_id:
            continue
        if author_lc and pulse.get("author_name", "").lower() != author_lc:
            continue
        if tag_lc:
            tags = [t.lower() for t in (pulse.get("tags") or [])]
            if tag_lc not in tags:
                continue
        if since_dt:
            modified_dt = _to_dt(pulse.get("modified") or pulse.get("created"))
            if modified_dt is None or modified_dt < since_dt:
                continue
        rows.append(pulse)

    rows.sort(
        key=lambda p: (p.get("modified") or p.get("created") or ""),
        reverse=True,
    )
    return rows[offset: offset + limit]


def list_indicators(
    pulse_id: Optional[str] = None,
    indicator_type: Optional[str] = None,
    since: Optional[str] = None,
    limit: int = 500,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """Return indicators from the DB with optional filters and pagination."""
    store = _get_indicators_store()

    since_dt = _to_dt(since) if since else None
    type_lc = indicator_type.lower() if indicator_type else None

    rows: List[Dict[str, Any]] = []
    for ind in store.values():
        if not isinstance(ind, dict):
            continue
        if pulse_id and ind.get("pulse_id") != pulse_id:
            continue
        if type_lc and ind.get("type", "").lower() != type_lc:
            continue
        if since_dt:
            created_dt = _to_dt(ind.get("created"))
            if created_dt is None or created_dt < since_dt:
                continue
        rows.append(ind)

    rows.sort(key=lambda r: (r.get("created") or ""), reverse=True)
    return rows[offset: offset + limit]


def get_store_stats() -> Dict[str, Any]:
    """Return total pulse + indicator counts and indicator-type breakdown."""
    pulses_store = _get_pulses_store()
    indicators_store = _get_indicators_store()

    by_indicator_type: Dict[str, int] = {}
    with_attack_id = 0

    for pulse in pulses_store.values():
        if isinstance(pulse, dict) and pulse.get("attack_ids"):
            with_attack_id += 1

    for ind in indicators_store.values():
        if not isinstance(ind, dict):
            continue
        t = ind.get("type") or "unknown"
        by_indicator_type[t] = by_indicator_type.get(t, 0) + 1

    return {
        "total_pulses": len(pulses_store),
        "total_indicators": len(indicators_store),
        "by_indicator_type": by_indicator_type,
        "with_attack_id": with_attack_id,
    }


def total_pulse_count() -> int:
    return len(_get_pulses_store())


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Import AlienVault OTX pulses into local DB")
    parser.add_argument(
        "--api-key",
        default=None,
        help="OTX API key (defaults to env OTX_API_KEY; falls back to public activity feed)",
    )
    parser.add_argument("--limit", type=int, default=50, help="Pulses per page (default 50)")
    parser.add_argument("--max-pages", type=int, default=1, help="Max pages to walk (default 1)")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    result = run_import(
        api_key=args.api_key,
        limit=args.limit,
        max_pages=args.max_pages,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
