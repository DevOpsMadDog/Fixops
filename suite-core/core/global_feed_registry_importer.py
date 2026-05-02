"""Global Feed Registry Importer — ALDECI.

Wires the global feed catalog defined in ``suite-feeds/feeds_service.py``
(28+ real public threat-intelligence feeds across 7 categories) into the
per-org ``tia_feeds`` table managed by
``ThreatIntelligenceAutomationEngine``.

Source-of-truth catalogs (real URLs, no mocks):
  - AUTHORITATIVE_FEEDS  — NVD, CISA KEV, MITRE, EPSS, CERT/CC, ICS-CERT, ...
  - NATIONAL_CERT_FEEDS  — NCSC UK, BSI, ANSSI, JPCERT, CERT-In, ACSC, ...
  - EXPLOIT_FEEDS        — Exploit-DB, Metasploit, Vulners, Shodan, Nuclei, ...
  - THREAT_ACTOR_FEEDS   — MITRE ATT&CK, OTX, abuse.ch, Feodo, Ransomware-Live
  - SUPPLY_CHAIN_FEEDS   — OSV, GHSA, deps.dev, npm advisory, PyPI advisory, ...
  - CLOUD_RUNTIME_FEEDS  — AWS / Azure / GCP / k8s / RHEL / Ubuntu / Alpine
  - EARLY_SIGNAL_FEEDS   — MSRC, Apple, Cisco PSIRT, Palo Alto, Fortinet, ...

Behaviour:
  - Idempotent: a feed already registered for the org (matched by feed_name)
    is skipped with skipped_existing += 1.
  - Format normalisation: the global registry uses formats like rss / html /
    csv_gz / toml that are not in the engine's _VALID_FORMATS set
    {stix, misp, csv, json, xml, taxii}. They are projected to the closest
    valid bucket (rss/html -> json metadata, csv_gz -> csv, toml -> json).
  - Type assignment: government CERTs -> "government"; commercial APIs that
    require an API key -> "commercial"; everything else -> "osint".

No fake values: every URL, name, and refresh interval comes directly from
``suite-feeds/feeds_service.py``.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

_logger = logging.getLogger(__name__)


# Engine constraints (mirrored to avoid a circular import on engine module load)
_VALID_FORMATS = {"stix", "misp", "csv", "json", "xml", "taxii"}
_VALID_FEED_TYPES = {
    "osint", "commercial", "isac", "government", "dark_web", "honeypot", "internal",
}

# Catalogs that should be tagged as government CERTs.
_GOVERNMENT_CATALOGS = {"NATIONAL_CERT_FEEDS"}

# Specific feed_keys that should override category to "government" even when
# coming from another catalog (e.g. CISA KEV is in AUTHORITATIVE_FEEDS).
_GOVERNMENT_FEED_KEYS = {
    "cisa_kev", "cisa_vulnrichment", "ics_cert", "cert_cc",
}


def _normalise_format(raw: Any) -> str:
    """Project the global-catalog format to one accepted by the engine."""
    if not raw:
        return "json"
    s = str(raw).strip().lower()
    if s in _VALID_FORMATS:
        return s
    if s in {"csv_gz", "csv.gz"}:
        return "csv"
    if s in {"rss", "html", "rdf", "toml"}:
        # No structured-record format on the engine side — store as JSON
        # because the importer that ingests them will produce JSON records
        # downstream. The engine's "format" column documents the *normalised*
        # ingestion format, not the raw transport format.
        return "json"
    if s in {"xml", "scap"}:
        return "xml"
    return "json"


def _classify_feed_type(catalog_key: str, feed_key: str, meta: Dict[str, Any]) -> str:
    """Return one of _VALID_FEED_TYPES for a global-catalog feed.

    Government CERTs and CISA-class feeds are tagged "government".
    Commercial APIs (require api_key) are tagged "commercial".
    Everything else -> "osint".
    """
    if feed_key in _GOVERNMENT_FEED_KEYS:
        return "government"
    if catalog_key in _GOVERNMENT_CATALOGS:
        return "government"
    if meta.get("api_key_required"):
        return "commercial"
    return "osint"


def _build_records() -> List[Tuple[str, str, Dict[str, Any]]]:
    """Return [(catalog_key, feed_key, meta), ...] for every catalog entry.

    Catalogs are imported lazily so that this module remains importable in
    environments where ``suite-feeds`` is not on sys.path (the engine still
    works without the global registry).
    """
    try:
        from feeds_service import (
            AUTHORITATIVE_FEEDS,
            CLOUD_RUNTIME_FEEDS,
            EARLY_SIGNAL_FEEDS,
            EXPLOIT_FEEDS,
            NATIONAL_CERT_FEEDS,
            SUPPLY_CHAIN_FEEDS,
            THREAT_ACTOR_FEEDS,
        )
    except ImportError as exc:
        _logger.warning("Global feed registry not importable: %s", exc)
        return []

    catalogs: List[Tuple[str, Dict[str, Dict[str, Any]]]] = [
        ("AUTHORITATIVE_FEEDS", AUTHORITATIVE_FEEDS),
        ("NATIONAL_CERT_FEEDS", NATIONAL_CERT_FEEDS),
        ("EXPLOIT_FEEDS", EXPLOIT_FEEDS),
        ("THREAT_ACTOR_FEEDS", THREAT_ACTOR_FEEDS),
        ("SUPPLY_CHAIN_FEEDS", SUPPLY_CHAIN_FEEDS),
        ("CLOUD_RUNTIME_FEEDS", CLOUD_RUNTIME_FEEDS),
        ("EARLY_SIGNAL_FEEDS", EARLY_SIGNAL_FEEDS),
    ]

    records: List[Tuple[str, str, Dict[str, Any]]] = []
    for cat_key, catalog in catalogs:
        if not isinstance(catalog, dict):
            continue
        for feed_key, meta in catalog.items():
            if not isinstance(meta, dict):
                continue
            records.append((cat_key, str(feed_key), meta))
    return records


def import_global_feeds(
    engine: Any,
    org_id: str,
    catalog_records: Optional[List[Tuple[str, str, Dict[str, Any]]]] = None,
) -> Dict[str, Any]:
    """Bulk-register every global-registry feed into the org's tia_feeds.

    Args:
        engine: a ThreatIntelligenceAutomationEngine instance (duck-typed:
                must expose ``register_feed(org_id, dict)`` and
                ``list_feeds(org_id)``).
        org_id: target organisation.
        catalog_records: optional injected records (used by tests). When None,
                         the global feeds_service catalogs are read live.

    Returns:
        {
          "source": "global-registry",
          "imported": int,           # newly registered feeds
          "skipped_existing": int,   # already in tia_feeds (matched by feed_name)
          "errors": int,             # validation/insert failures (logged)
          "by_catalog": {cat_key: {imported, skipped, errors}},
          "by_feed_type": {feed_type: count of newly imported},
          "total_available": int,
        }
    """
    records = catalog_records if catalog_records is not None else _build_records()
    if not records:
        return {
            "source": "global-registry",
            "imported": 0,
            "skipped_existing": 0,
            "errors": 0,
            "by_catalog": {},
            "by_feed_type": {},
            "total_available": 0,
            "warning": "Global feed registry empty or feeds_service unavailable.",
        }

    # Snapshot of currently-registered feed_names for the org (lower-cased).
    existing_names = set()
    try:
        for row in engine.list_feeds(org_id):
            name = (row.get("feed_name") or "").strip().lower()
            if name:
                existing_names.add(name)
    except Exception as exc:  # pragma: no cover — defensive
        _logger.warning("list_feeds for %s failed: %s", org_id, exc)

    imported = 0
    skipped = 0
    errors = 0
    by_catalog: Dict[str, Dict[str, int]] = {}
    by_feed_type: Dict[str, int] = {}

    for cat_key, feed_key, meta in records:
        cat_bucket = by_catalog.setdefault(
            cat_key, {"imported": 0, "skipped": 0, "errors": 0}
        )
        feed_name = (meta.get("name") or feed_key).strip()
        if not feed_name:
            errors += 1
            cat_bucket["errors"] += 1
            continue

        if feed_name.lower() in existing_names:
            skipped += 1
            cat_bucket["skipped"] += 1
            continue

        feed_type = _classify_feed_type(cat_key, feed_key, meta)
        if feed_type not in _VALID_FEED_TYPES:
            feed_type = "osint"

        fmt = _normalise_format(meta.get("format"))
        if fmt not in _VALID_FORMATS:
            fmt = "json"

        try:
            poll_minutes = int(meta.get("refresh_hours", 24)) * 60
        except (TypeError, ValueError):
            poll_minutes = 24 * 60
        if poll_minutes <= 0:
            poll_minutes = 60

        payload: Dict[str, Any] = {
            "feed_name": feed_name,
            "feed_type": feed_type,
            "url": str(meta.get("url", "")),
            "api_key": "",  # never stored — caller must POST /feeds with their key
            "format": fmt,
            "status": "active",
            "poll_interval_minutes": poll_minutes,
            "ioc_count": 0,
            "last_polled": None,
        }

        try:
            engine.register_feed(org_id, payload)
        except ValueError as exc:
            _logger.warning(
                "global-feed register_feed validation failed (%s/%s): %s",
                cat_key, feed_key, exc,
            )
            errors += 1
            cat_bucket["errors"] += 1
            continue
        except Exception as exc:
            _logger.warning(
                "global-feed register_feed unexpected error (%s/%s): %s",
                cat_key, feed_key, exc,
            )
            errors += 1
            cat_bucket["errors"] += 1
            continue

        imported += 1
        cat_bucket["imported"] += 1
        by_feed_type[feed_type] = by_feed_type.get(feed_type, 0) + 1
        existing_names.add(feed_name.lower())

    return {
        "source": "global-registry",
        "imported": imported,
        "skipped_existing": skipped,
        "errors": errors,
        "by_catalog": by_catalog,
        "by_feed_type": by_feed_type,
        "total_available": len(records),
    }
