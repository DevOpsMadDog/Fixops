"""Global Feed Registry — unified catalog for all threat-intel importers.

A single source of truth that lists every feed the platform consumes, their
metadata (source URL, license, refresh interval), and their last import
status (imported_at, entry count, ok/error).

Usage:
    from feeds.registry import (
        list_feeds, get_feed, refresh_feed, registered_feed_ids,
    )

DB: data/feed_registry.db (PersistentDict pattern)

Adding a new feed: append a `_register(...)` call inside `_discover()` —
keep importer module imports inside that function so an ImportError in one
feed module does not crash the registry as a whole.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Persistent state (last_imported_at / last_entry_count / last_status)
# ---------------------------------------------------------------------------

_HERE = Path(__file__).resolve()
_PROJECT_ROOT = _HERE.parents[2]  # suite-feeds/feeds/registry.py -> project root
_DEFAULT_DB = str(_PROJECT_ROOT / "data" / "feed_registry.db")

_state_lock = threading.Lock()
_state_store = None  # type: ignore[var-annotated]


def _get_state_store(db_path: Optional[str] = None):
    """Return a PersistentDict-backed state store.

    Falls back to a plain in-memory dict when PersistentDict cannot be
    imported (e.g. tests or stripped environments).
    """
    global _state_store
    if _state_store is not None and db_path is None:
        return _state_store

    path = db_path or _DEFAULT_DB
    try:
        import sys
        suite_core = str(_PROJECT_ROOT / "suite-core")
        if suite_core not in sys.path:
            sys.path.insert(0, suite_core)
        from core.persistent_store import PersistentDict
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        store = PersistentDict("feed_registry_state", db_path=path)
    except Exception as exc:  # noqa: BLE001 — defensive: never crash registry
        logger.warning("feed_registry: PersistentDict unavailable, using in-memory: %s", exc)
        store = {}

    if db_path is None:
        _state_store = store
    return store


# ---------------------------------------------------------------------------
# Feed definition
# ---------------------------------------------------------------------------

@dataclass
class FeedDefinition:
    """Static metadata for a registered feed."""

    id: str  # slug (e.g. "cisa_kev")
    display_name: str
    source_url: str
    source_type: str  # one of: json, xml, csv, yaml, stix
    license: str
    refresh_interval_seconds: int
    importer_callable: Callable[[], Dict[str, Any]] = field(repr=False)
    count_callable: Optional[Callable[[], int]] = field(default=None, repr=False)
    description: str = ""


# ---------------------------------------------------------------------------
# Discovery — populate _FEEDS by importing each feed module
# ---------------------------------------------------------------------------

_FEEDS: Dict[str, FeedDefinition] = {}
_discovery_lock = threading.Lock()
_discovery_done = False


def _register(feed: FeedDefinition) -> None:
    if feed.id in _FEEDS:
        logger.warning("feed_registry: duplicate registration for %r — skipping", feed.id)
        return
    _FEEDS[feed.id] = feed


def _discover() -> None:
    """Walk the importer modules and register a FeedDefinition for each.

    Each importer is loaded inside its own try/except so an unrelated
    ImportError in one module never crashes the registry as a whole.
    """
    # ---------- CISA KEV ----------
    try:
        from feeds.cisa_kev.importer import CisaKevImporter, CISA_KEV_URL

        def _refresh_cisa_kev() -> Dict[str, Any]:
            imp = CisaKevImporter()
            return imp.run(idempotent=True)

        def _count_cisa_kev() -> int:
            try:
                return CisaKevImporter().total_count()
            except Exception:  # noqa: BLE001
                return 0

        _register(FeedDefinition(
            id="cisa_kev",
            display_name="CISA Known Exploited Vulnerabilities",
            source_url=CISA_KEV_URL,
            source_type="json",
            license="CC0-1.0 (US Government work)",
            refresh_interval_seconds=86_400,  # daily
            importer_callable=_refresh_cisa_kev,
            count_callable=_count_cisa_kev,
            description="CISA's authoritative catalog of CVEs known to be exploited in the wild.",
        ))
    except ImportError as exc:
        logger.warning("feed_registry: cisa_kev importer unavailable: %s", exc)

    # ---------- MITRE ATT&CK ----------
    try:
        from feeds.mitre_attack.extractor import (
            MitreAttackExtractor,
            STIX_BUNDLE_URL,
            _DEFAULT_DB as _MITRE_DB,
        )

        def _refresh_mitre() -> Dict[str, Any]:
            return MitreAttackExtractor().run()

        def _count_mitre() -> int:
            try:
                store = MitreAttackExtractor(_MITRE_DB).get_store()
                rows = store.all()
                store.close()
                return len(rows)
            except Exception:  # noqa: BLE001
                return 0

        _register(FeedDefinition(
            id="mitre_attack",
            display_name="MITRE ATT&CK Enterprise",
            source_url=STIX_BUNDLE_URL,
            source_type="stix",
            license="Apache-2.0",
            refresh_interval_seconds=604_800,  # weekly
            importer_callable=_refresh_mitre,
            count_callable=_count_mitre,
            description="MITRE ATT&CK enterprise STIX 2.1 bundle — techniques, sub-techniques, and tactics.",
        ))
    except ImportError as exc:
        logger.warning("feed_registry: mitre_attack importer unavailable: %s", exc)

    # ---------- SigmaHQ ----------
    try:
        from feeds.sigmahq.importer import (
            run_import as _sigma_run,
            get_store_stats as _sigma_stats,
            SIGMAHQ_TAR_URL,
        )

        def _refresh_sigma() -> Dict[str, Any]:
            return _sigma_run()

        def _count_sigma() -> int:
            try:
                return int(_sigma_stats().get("total", 0))
            except Exception:  # noqa: BLE001
                return 0

        _register(FeedDefinition(
            id="sigmahq",
            display_name="SigmaHQ Detection Rules",
            source_url=SIGMAHQ_TAR_URL,
            source_type="yaml",
            license="DRL-1.1 (Detection Rule License)",
            refresh_interval_seconds=86_400,  # daily
            importer_callable=_refresh_sigma,
            count_callable=_count_sigma,
            description="Open-source generic detection rule format — Sigma — covering SIEM/EDR.",
        ))
    except ImportError as exc:
        logger.warning("feed_registry: sigmahq importer unavailable: %s", exc)


def _ensure_discovered() -> None:
    global _discovery_done
    with _discovery_lock:
        if _discovery_done:
            return
        _discover()
        _discovery_done = True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def registered_feed_ids() -> List[str]:
    """Return all registered feed IDs (sorted)."""
    _ensure_discovered()
    return sorted(_FEEDS.keys())


def _to_dict(feed: FeedDefinition, store: Any) -> Dict[str, Any]:
    """Combine static metadata + last-run state into a single dict."""
    state: Dict[str, Any] = {}
    try:
        if hasattr(store, "get"):
            state = store.get(feed.id, {}) or {}
        elif feed.id in store:
            state = store[feed.id]
    except Exception:  # noqa: BLE001
        state = {}

    entry_count = state.get("last_entry_count")
    if entry_count is None and feed.count_callable is not None:
        try:
            entry_count = feed.count_callable()
        except Exception:  # noqa: BLE001
            entry_count = None

    return {
        "id": feed.id,
        "display_name": feed.display_name,
        "source_url": feed.source_url,
        "source_type": feed.source_type,
        "license": feed.license,
        "refresh_interval_seconds": feed.refresh_interval_seconds,
        "description": feed.description,
        "last_imported_at": state.get("last_imported_at"),
        "last_entry_count": entry_count,
        "last_status": state.get("last_status", "unknown"),
        "last_error": state.get("last_error"),
        "last_result": state.get("last_result"),
    }


def list_feeds(db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return all registered feeds with their last-run state."""
    _ensure_discovered()
    store = _get_state_store(db_path)
    return [_to_dict(_FEEDS[fid], store) for fid in sorted(_FEEDS.keys())]


def get_feed(feed_id: str, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Return a single feed's metadata + state. Raises KeyError if unknown."""
    _ensure_discovered()
    if feed_id not in _FEEDS:
        raise KeyError(feed_id)
    store = _get_state_store(db_path)
    return _to_dict(_FEEDS[feed_id], store)


def refresh_feed(feed_id: str, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Trigger the importer for *feed_id*, persist last-run state, return result.

    Raises:
        KeyError: feed_id is not registered.
    """
    _ensure_discovered()
    if feed_id not in _FEEDS:
        raise KeyError(feed_id)

    feed = _FEEDS[feed_id]
    store = _get_state_store(db_path)
    now_iso = datetime.now(timezone.utc).isoformat()

    state: Dict[str, Any] = {
        "last_imported_at": now_iso,
        "last_status": "ok",
        "last_error": None,
        "last_result": None,
        "last_entry_count": None,
    }

    try:
        result = feed.importer_callable()
        if not isinstance(result, dict):
            result = {"raw": result}
        state["last_result"] = result
        # Try to derive an entry count from common keys
        derived = (
            result.get("source_count")
            or result.get("rules")
            or (
                (result.get("techniques") or 0)
                + (result.get("subtechniques") or 0)
            )
            or result.get("imported")
        )
        if not derived and feed.count_callable is not None:
            try:
                derived = feed.count_callable()
            except Exception:  # noqa: BLE001
                derived = None
        state["last_entry_count"] = int(derived) if derived else 0
    except Exception as exc:  # noqa: BLE001
        logger.exception("feed_registry: refresh failed for %s", feed_id)
        state["last_status"] = "error"
        state["last_error"] = f"{type(exc).__name__}: {exc}"

    with _state_lock:
        try:
            store[feed_id] = state
        except Exception as exc:  # noqa: BLE001
            logger.warning("feed_registry: failed to persist state for %s: %s", feed_id, exc)

    return {
        "feed_id": feed_id,
        "status": state["last_status"],
        "imported_at": state["last_imported_at"],
        "entry_count": state["last_entry_count"],
        "result": state["last_result"],
        "error": state["last_error"],
    }


# ---------------------------------------------------------------------------
# Test helpers (NOT part of the public API but useful for unit tests)
# ---------------------------------------------------------------------------

def _reset_for_tests() -> None:
    """Drop the in-process registry + state cache. Tests only."""
    global _discovery_done, _state_store
    with _discovery_lock:
        _FEEDS.clear()
        _discovery_done = False
    _state_store = None


def _force_register(feed: FeedDefinition) -> None:
    """Forcibly add a feed (overwriting any existing entry). Tests only."""
    _ensure_discovered()
    _FEEDS[feed.id] = feed
