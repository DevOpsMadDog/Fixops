"""ProjectDiscovery Nuclei Templates Catalog Importer.

Downloads the nuclei-templates master archive, parses every YAML template,
upserts into data/nuclei_templates.db (PersistentDict pattern), and returns
a summary broken down by severity and category.

Source: https://github.com/projectdiscovery/nuclei-templates (MIT)

Skips: .github/, helpers/, workflows/ directories.
"""

from __future__ import annotations

import io
import logging
import re
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
import yaml

logger = logging.getLogger(__name__)

NUCLEI_TAR_URL = (
    "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.tar.gz"
)
DOWNLOAD_TIMEOUT = 90.0  # seconds

# Subdirs to skip (top-level directory path components)
_SKIP_DIRS = {".github", "helpers", "workflows"}

# Resolve DB path relative to project root (data/nuclei_templates.db)
_HERE = Path(__file__).resolve()
_PROJECT_ROOT = _HERE.parents[3]  # suite-feeds/feeds/nuclei_templates -> project root
_DB_PATH = _PROJECT_ROOT / "data" / "nuclei_templates.db"


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
            _store = PersistentDict("nuclei_templates", db_path=str(_DB_PATH))
        except TypeError:
            _store = PersistentDict("nuclei_templates")
    return _store


# ---------------------------------------------------------------------------
# YAML parsing helpers
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}


def _normalise_severity(raw: Any) -> str:
    """Return a lowercase severity string, defaulting to 'unknown'."""
    if not raw:
        return "unknown"
    val = str(raw).lower().strip()
    return val if val in _VALID_SEVERITIES else "unknown"


def _extract_cve_ids(classification: Any) -> List[str]:
    """Extract CVE IDs from the classification block."""
    if not isinstance(classification, dict):
        return []
    raw = classification.get("cve-id") or classification.get("cve_id") or []
    if isinstance(raw, str):
        raw = [raw]
    result: List[str] = []
    for item in raw:
        m = _CVE_RE.search(str(item))
        if m:
            result.append(m.group(0).upper())
    return list(dict.fromkeys(result))  # deduplicate, preserve order


def _extract_cwe_ids(classification: Any) -> List[str]:
    """Extract CWE IDs from the classification block."""
    if not isinstance(classification, dict):
        return []
    raw = classification.get("cwe-id") or classification.get("cwe_id") or []
    if isinstance(raw, str):
        raw = [raw]
    result: List[str] = []
    for item in raw:
        s = str(item).strip()
        if s:
            result.append(s)
    return list(dict.fromkeys(result))


def _derive_category(archive_path: str) -> str:
    """Derive the top-level category from the archive member path.

    The archive structure is:  nuclei-templates-main/<category>/...
    We return the first path component after the top-level repo dir.
    """
    parts = Path(archive_path).parts
    # parts[0] = 'nuclei-templates-main' (or similar), parts[1] = category
    if len(parts) >= 2:
        return parts[1]
    return "unknown"


def _slug_from_path(archive_path: str) -> str:
    """Return a stable id slug from the archive member path (no extension)."""
    p = Path(archive_path)
    # Strip the top-level repo dir prefix (e.g. nuclei-templates-main/)
    parts = p.parts
    if len(parts) >= 2:
        relative = Path(*parts[1:])
    else:
        relative = p
    return str(relative.with_suffix("")).replace("\\", "/")


def parse_nuclei_yaml(yaml_text: str, source_path: str = "") -> Optional[Dict[str, Any]]:
    """Parse a single Nuclei template YAML string into a normalised dict.

    Returns None if the document is not a valid template.
    """
    try:
        doc = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        logger.debug("YAML parse error in %s: %s", source_path, exc)
        return None

    if not isinstance(doc, dict):
        return None

    info = doc.get("info")
    if not isinstance(info, dict):
        return None

    # Use the template id field; fall back to path slug
    template_id = doc.get("id") or _slug_from_path(source_path)
    if not template_id:
        return None

    classification = info.get("classification") or {}
    tags_raw = info.get("tags") or []
    if isinstance(tags_raw, str):
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
    elif isinstance(tags_raw, list):
        tags = [str(t).strip() for t in tags_raw if t]
    else:
        tags = []

    references_raw = info.get("reference") or info.get("references") or []
    if isinstance(references_raw, str):
        references = [references_raw]
    else:
        references = [str(r) for r in references_raw if r]

    author_raw = info.get("author") or ""
    if isinstance(author_raw, list):
        author = ", ".join(str(a) for a in author_raw)
    else:
        author = str(author_raw)

    category = _derive_category(source_path)

    return {
        "id": str(template_id),
        "name": info.get("name", ""),
        "severity": _normalise_severity(info.get("severity")),
        "author": author,
        "tags": tags,
        "cve_id": _extract_cve_ids(classification),
        "cwe_id": _extract_cwe_ids(classification),
        "references": references,
        "category": category,
        "source_path": source_path,
        "imported_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Path filter
# ---------------------------------------------------------------------------

def _should_skip(parts: tuple) -> bool:
    """Return True if any top-level component after the repo root is in _SKIP_DIRS."""
    # parts[0] = repo-root-dir (e.g. nuclei-templates-main), parts[1] = category/subdir
    if len(parts) >= 2 and parts[1] in _SKIP_DIRS:
        return True
    return False


# ---------------------------------------------------------------------------
# Core import logic
# ---------------------------------------------------------------------------

def import_templates_from_archive(tar_bytes: bytes) -> Dict[str, Any]:
    """Extract templates from tar.gz bytes, parse, upsert, return summary."""
    store = _get_store()
    parsed = 0
    skipped = 0
    by_severity: Dict[str, int] = {}
    by_category: Dict[str, int] = {}
    with_cve = 0

    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            if not (member.name.endswith(".yaml") or member.name.endswith(".yml")):
                continue

            parts = Path(member.name).parts
            if _should_skip(parts):
                skipped += 1
                continue

            try:
                f = tf.extractfile(member)
                if f is None:
                    continue
                yaml_text = f.read().decode("utf-8", errors="replace")
            except Exception as exc:  # noqa: BLE001
                logger.debug("Failed to read %s: %s", member.name, exc)
                continue

            template = parse_nuclei_yaml(yaml_text, source_path=member.name)
            if template is None:
                skipped += 1
                continue

            # Upsert by template id slug
            store[template["id"]] = template
            parsed += 1

            sev = template["severity"]
            by_severity[sev] = by_severity.get(sev, 0) + 1

            cat = template["category"]
            by_category[cat] = by_category.get(cat, 0) + 1

            if template["cve_id"]:
                with_cve += 1

    logger.info(
        "Nuclei templates import complete: %d parsed, %d skipped", parsed, skipped
    )
    return {
        "templates": parsed,
        "skipped": skipped,
        "by_severity": by_severity,
        "by_category": by_category,
        "with_cve": with_cve,
    }


def run_import() -> Dict[str, Any]:
    """Download ProjectDiscovery nuclei-templates archive and import all templates."""
    logger.info("Downloading Nuclei templates from %s", NUCLEI_TAR_URL)
    with httpx.Client(timeout=DOWNLOAD_TIMEOUT, follow_redirects=True) as client:
        response = client.get(NUCLEI_TAR_URL)
        response.raise_for_status()
        tar_bytes = response.content

    logger.info("Downloaded %d bytes, extracting templates...", len(tar_bytes))
    return import_templates_from_archive(tar_bytes)


# ---------------------------------------------------------------------------
# Query helpers (used by the API endpoint)
# ---------------------------------------------------------------------------

def list_templates(
    severity: Optional[str] = None,
    tag: Optional[str] = None,
    cve_id: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = 500,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """Return templates from the DB with optional filters.

    severity  — exact match (e.g. 'high', 'critical', 'medium')
    tag       — substring match against the tags list
    cve_id    — exact CVE ID match (e.g. 'CVE-2021-44228')
    category  — exact match on top-level directory category
    """
    store = _get_store()
    results: List[Dict[str, Any]] = []

    sev_lc = severity.lower() if severity else None
    tag_lc = tag.lower() if tag else None
    cve_upper = cve_id.upper() if cve_id else None
    cat_lc = category.lower() if category else None

    for tmpl in store.values():
        if not isinstance(tmpl, dict):
            continue

        if sev_lc and tmpl.get("severity", "").lower() != sev_lc:
            continue

        if tag_lc:
            tags_lower = [t.lower() for t in (tmpl.get("tags") or [])]
            if not any(tag_lc in t for t in tags_lower):
                continue

        if cve_upper:
            cves = [c.upper() for c in (tmpl.get("cve_id") or [])]
            if cve_upper not in cves:
                continue

        if cat_lc and tmpl.get("category", "").lower() != cat_lc:
            continue

        results.append(tmpl)

    return results[offset: offset + limit]


def get_store_stats() -> Dict[str, Any]:
    """Return total template count and breakdowns."""
    store = _get_store()
    total = len(store)
    by_severity: Dict[str, int] = {}
    by_category: Dict[str, int] = {}
    with_cve = 0

    for tmpl in store.values():
        if not isinstance(tmpl, dict):
            continue
        sev = tmpl.get("severity", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        cat = tmpl.get("category", "unknown")
        by_category[cat] = by_category.get(cat, 0) + 1
        if tmpl.get("cve_id"):
            with_cve += 1

    return {
        "total": total,
        "by_severity": by_severity,
        "by_category": by_category,
        "with_cve": with_cve,
    }
