"""Spamhaus DROP / EDROP blocklist importer.

Sources (public, no API key required):
    DROP  — https://www.spamhaus.org/drop/drop.txt
    EDROP — https://www.spamhaus.org/drop/edrop.txt

Format: plain text, one CIDR per line.
  - Lines starting with ';' are comments.
  - Data lines: ``<cidr> ; SBL<id>``

Stored shape (keyed by ``<list_name>:<cidr>``):
    {
        "cidr":        "1.2.3.0/24",
        "sbl_id":      "SBL1234",
        "list_name":   "drop" | "edrop",
        "imported_at": "<iso8601>",
    }

DB: data/spamhaus_drop.db (PersistentDict)
"""

from __future__ import annotations

import ipaddress
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger(__name__)

DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
EDROP_URL = "https://www.spamhaus.org/drop/edrop.txt"
DOWNLOAD_TIMEOUT = 60.0

_HERE = Path(__file__).resolve()
_PROJECT_ROOT = _HERE.parents[3]  # suite-feeds/feeds/spamhaus_drop -> project root
_DB_PATH = _PROJECT_ROOT / "data" / "spamhaus_drop.db"

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
            _store = PersistentDict("spamhaus_drop_cidrs", db_path=str(_DB_PATH))
        except TypeError:
            _store = PersistentDict("spamhaus_drop_cidrs")
    return _store


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_drop_text(text: str, list_name: str) -> List[Tuple[str, str]]:
    """Parse a DROP/EDROP text body.

    Returns a list of (cidr, sbl_id) tuples.  Comment lines (starting with
    ';') and blank lines are silently skipped.  Invalid CIDRs are skipped with
    a warning.
    """
    results: List[Tuple[str, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(";"):
            continue
        # Format: ``1.2.3.0/24 ; SBL1234``
        parts = line.split(";", 1)
        cidr = parts[0].strip()
        sbl_id = parts[1].strip() if len(parts) > 1 else ""
        # Validate CIDR
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            logger.debug("spamhaus_drop: skipping invalid CIDR %r in %s", cidr, list_name)
            continue
        results.append((cidr, sbl_id))
    return results


# ---------------------------------------------------------------------------
# Store helpers (replace-not-append)
# ---------------------------------------------------------------------------

def _replace_list(list_name: str, entries: List[Tuple[str, str]]) -> int:
    """Replace all existing entries for *list_name* with fresh *entries*.

    Returns the count of new entries stored.
    """
    store = _get_store()
    now = datetime.now(timezone.utc).isoformat()

    # Remove stale entries for this list
    stale_keys = [k for k in store.keys() if str(k).startswith(f"{list_name}:")]
    for k in stale_keys:
        try:
            del store[k]
        except Exception:  # noqa: BLE001
            pass

    # Insert fresh entries
    count = 0
    for cidr, sbl_id in entries:
        key = f"{list_name}:{cidr}"
        store[key] = {
            "cidr": cidr,
            "sbl_id": sbl_id,
            "list_name": list_name,
            "imported_at": now,
        }
        count += 1
    return count


# ---------------------------------------------------------------------------
# Public import function
# ---------------------------------------------------------------------------

def run_import(
    drop_url: str = DROP_URL,
    edrop_url: str = EDROP_URL,
    timeout: float = DOWNLOAD_TIMEOUT,
) -> Dict[str, Any]:
    """Fetch DROP and EDROP lists, replace store contents, return summary.

    Returns:
        {"drop_cidrs": N, "edrop_cidrs": N}
    """
    drop_count = 0
    edrop_count = 0
    errors: List[str] = []

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        # DROP
        try:
            logger.info("Fetching Spamhaus DROP from %s", drop_url)
            resp = client.get(drop_url)
            resp.raise_for_status()
            entries = parse_drop_text(resp.text, "drop")
            drop_count = _replace_list("drop", entries)
            logger.info("Spamhaus DROP: stored %d CIDRs", drop_count)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Spamhaus DROP fetch failed: %s", exc)
            errors.append(f"drop: {type(exc).__name__}: {exc}")

        # EDROP
        try:
            logger.info("Fetching Spamhaus EDROP from %s", edrop_url)
            resp = client.get(edrop_url)
            resp.raise_for_status()
            entries = parse_drop_text(resp.text, "edrop")
            edrop_count = _replace_list("edrop", entries)
            logger.info("Spamhaus EDROP: stored %d CIDRs", edrop_count)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Spamhaus EDROP fetch failed: %s", exc)
            errors.append(f"edrop: {type(exc).__name__}: {exc}")

    result: Dict[str, Any] = {"drop_cidrs": drop_count, "edrop_cidrs": edrop_count}
    if errors:
        result["errors"] = errors
    return result


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def list_cidrs(
    list_name: Optional[str] = None,
    limit: int = 1000,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """Return stored CIDR entries, optionally filtered by *list_name*.

    Args:
        list_name: "drop" | "edrop" | None (returns both).
        limit / offset: pagination.
    """
    store = _get_store()
    results: List[Dict[str, Any]] = []
    for entry in store.values():
        if not isinstance(entry, dict):
            continue
        if list_name and entry.get("list_name") != list_name:
            continue
        results.append(entry)
    return results[offset: offset + limit]


def check_ip(ip: str) -> Dict[str, Any]:
    """Check whether *ip* falls inside any stored CIDR.

    Returns:
        {
            "ip": str,
            "matched": bool,
            "matches": [{"cidr": ..., "sbl_id": ..., "list_name": ...}, ...],
        }
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "matched": False, "matches": [], "error": "invalid IP address"}

    store = _get_store()
    matches: List[Dict[str, Any]] = []
    for entry in store.values():
        if not isinstance(entry, dict):
            continue
        cidr_str = entry.get("cidr") or ""
        try:
            network = ipaddress.ip_network(cidr_str, strict=False)
            if addr in network:
                matches.append({
                    "cidr": cidr_str,
                    "sbl_id": entry.get("sbl_id", ""),
                    "list_name": entry.get("list_name", ""),
                })
        except ValueError:
            continue

    return {"ip": ip, "matched": bool(matches), "matches": matches}


def total_count() -> int:
    return len(_get_store())


def get_store_stats() -> Dict[str, Any]:
    store = _get_store()
    by_list: Dict[str, int] = {}
    for entry in store.values():
        if not isinstance(entry, dict):
            continue
        ln = entry.get("list_name", "unknown")
        by_list[ln] = by_list.get(ln, 0) + 1
    return {"total": sum(by_list.values()), "by_list": by_list}
