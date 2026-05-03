"""SigmaHQ Detection Rule Importer.

Downloads the SigmaHQ master archive, parses every YAML rule under rules/,
upserts into data/sigmahq_rules.db (PersistentDict pattern), and returns
a summary broken down by level and platform.

Skips: tests/, deprecated/, unsupported/ subdirectories.
"""

from __future__ import annotations

import io
import logging
import re
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
import yaml

logger = logging.getLogger(__name__)

SIGMAHQ_TAR_URL = (
    "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.tar.gz"
)
DOWNLOAD_TIMEOUT = 90.0  # seconds

# Subdirs to skip (relative path components)
_SKIP_DIRS = {"tests", "deprecated", "unsupported"}

# Resolve DB path relative to project root (data/sigmahq_rules.db)
_HERE = Path(__file__).resolve()
_PROJECT_ROOT = _HERE.parents[3]  # suite-feeds/feeds/sigmahq -> project root
_DB_PATH = _PROJECT_ROOT / "data" / "sigmahq_rules.db"


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
            # Fallback: plain dict (tests / standalone runs)
            from collections import UserDict as PersistentDict  # type: ignore[assignment]

        _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        try:
            _store = PersistentDict("sigmahq_rules", db_path=str(_DB_PATH))
        except TypeError:
            # PersistentDict may not accept db_path kwarg in all versions
            _store = PersistentDict("sigmahq_rules")
    return _store


# ---------------------------------------------------------------------------
# YAML parsing helpers
# ---------------------------------------------------------------------------

_ATTACK_TECHNIQUE_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)


def _extract_attack_techniques(tags: List[str]) -> List[str]:
    """Return unique ATT&CK technique IDs (lower-cased) from a tag list."""
    techniques: List[str] = []
    for tag in tags:
        m = _ATTACK_TECHNIQUE_RE.match(tag.lower())
        if m:
            techniques.append(m.group(1))
    return list(dict.fromkeys(techniques))  # deduplicate, preserve order


def parse_sigma_yaml(yaml_text: str, source_path: str = "") -> Optional[Dict[str, Any]]:
    """Parse a single Sigma rule YAML string into a normalised dict.

    Returns None if the document is missing a required 'id' field.
    """
    try:
        doc = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        logger.debug("YAML parse error in %s: %s", source_path, exc)
        return None

    if not isinstance(doc, dict):
        return None

    rule_id = doc.get("id")
    if not rule_id:
        return None

    tags: List[str] = doc.get("tags") or []
    logsource: Dict[str, Any] = doc.get("logsource") or {}

    return {
        "id": str(rule_id),
        "title": doc.get("title", ""),
        "status": doc.get("status", ""),
        "description": doc.get("description", ""),
        "references": doc.get("references") or [],
        "tags": tags,
        "attack_techniques": _extract_attack_techniques(tags),
        "logsource": logsource,
        "platform": logsource.get("product") or logsource.get("category") or logsource.get("service") or "unknown",
        "detection": doc.get("detection") or {},
        "level": (doc.get("level") or "informational").lower(),
        "falsepositives": doc.get("falsepositives") or [],
        "source_path": source_path,
        "imported_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Path filter
# ---------------------------------------------------------------------------

def _should_skip(path_parts: tuple) -> bool:
    """Return True if any component of the path is in _SKIP_DIRS."""
    return bool(_SKIP_DIRS.intersection(path_parts))


# ---------------------------------------------------------------------------
# Core import logic
# ---------------------------------------------------------------------------

def import_rules_from_archive(tar_bytes: bytes) -> Dict[str, Any]:
    """Extract rules from tar.gz bytes, parse, upsert, return summary."""
    store = _get_store()
    parsed = 0
    skipped = 0
    by_level: Dict[str, int] = {}
    by_platform: Dict[str, int] = {}

    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            # Only process .yml files inside rules/ directory
            parts = Path(member.name).parts
            if "rules" not in parts:
                continue
            rules_idx = parts.index("rules")
            sub_parts = parts[rules_idx + 1:]  # path components after rules/

            if not member.name.endswith(".yml"):
                continue

            # Skip blacklisted subdirs
            if _should_skip(set(sub_parts[:-1])):
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

            rule = parse_sigma_yaml(yaml_text, source_path=member.name)
            if rule is None:
                skipped += 1
                continue

            # Upsert by UUID
            store[rule["id"]] = rule
            parsed += 1

            level = rule["level"]
            by_level[level] = by_level.get(level, 0) + 1

            platform = rule["platform"]
            by_platform[platform] = by_platform.get(platform, 0) + 1

    logger.info("SigmaHQ import complete: %d rules parsed, %d skipped", parsed, skipped)
    return {
        "rules": parsed,
        "skipped": skipped,
        "by_level": by_level,
        "by_platform": by_platform,
    }


def run_import() -> Dict[str, Any]:
    """Download SigmaHQ master archive and import all rules."""
    logger.info("Downloading SigmaHQ rules from %s", SIGMAHQ_TAR_URL)
    with httpx.Client(timeout=DOWNLOAD_TIMEOUT, follow_redirects=True) as client:
        response = client.get(SIGMAHQ_TAR_URL)
        response.raise_for_status()
        tar_bytes = response.content

    logger.info("Downloaded %d bytes, extracting rules…", len(tar_bytes))
    return import_rules_from_archive(tar_bytes)


# ---------------------------------------------------------------------------
# Query helpers (used by the API endpoint)
# ---------------------------------------------------------------------------

def list_rules(
    level: Optional[str] = None,
    technique: Optional[str] = None,
    platform: Optional[str] = None,
    limit: int = 500,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """Return rules from the DB with optional filters.

    level      — exact match (e.g. 'high'); also returns 'critical' when
                 level='high' so callers get high+critical in one call.
    technique  — ATT&CK technique substring match (e.g. 't1059.001').
    platform   — exact match on logsource product/category.
    """
    store = _get_store()
    results: List[Dict[str, Any]] = []

    # Normalise filter values
    level_lc = level.lower() if level else None
    tech_lc = technique.lower() if technique else None

    for rule in store.values():
        if not isinstance(rule, dict):
            continue

        if level_lc:
            rule_level = rule.get("level", "")
            # 'high' filter includes critical as well
            if level_lc == "high":
                if rule_level not in ("high", "critical"):
                    continue
            else:
                if rule_level != level_lc:
                    continue

        if tech_lc:
            techniques = [t.lower() for t in (rule.get("attack_techniques") or [])]
            if not any(tech_lc in t for t in techniques):
                continue

        if platform:
            if rule.get("platform", "").lower() != platform.lower():
                continue

        results.append(rule)

    # Apply pagination
    return results[offset: offset + limit]


def get_store_stats() -> Dict[str, Any]:
    """Return total rule count and breakdowns."""
    store = _get_store()
    total = len(store)
    by_level: Dict[str, int] = {}
    by_platform: Dict[str, int] = {}

    for rule in store.values():
        if not isinstance(rule, dict):
            continue
        lv = rule.get("level", "unknown")
        by_level[lv] = by_level.get(lv, 0) + 1
        pl = rule.get("platform", "unknown")
        by_platform[pl] = by_platform.get(pl, 0) + 1

    return {"total": total, "by_level": by_level, "by_platform": by_platform}


# ---------------------------------------------------------------------------
# Custom rule importer (user-supplied Sigma YAML)
# ---------------------------------------------------------------------------

class CustomRuleValidationError(ValueError):
    """Raised when a submitted custom rule fails validation."""


def upsert_custom_rule(yaml_text: str, source_label: str = "custom") -> Dict[str, Any]:
    """Parse, validate, and upsert a single user-supplied Sigma-format YAML rule.

    Args:
        yaml_text:    Raw YAML text of the Sigma rule.
        source_label: Free-form label stored in `source_path` (e.g. tenant ID).

    Returns:
        The normalised rule dict that was stored.

    Raises:
        CustomRuleValidationError: If the YAML is invalid or missing required fields.
    """
    rule = parse_sigma_yaml(yaml_text, source_path=source_label)
    if rule is None:
        raise CustomRuleValidationError(
            "Rule must be valid YAML and contain a top-level 'id' field."
        )

    # Require at minimum: title and detection block
    if not rule.get("title"):
        raise CustomRuleValidationError("Rule must have a non-empty 'title' field.")
    if not rule.get("detection"):
        raise CustomRuleValidationError("Rule must have a non-empty 'detection' block.")

    # Mark as custom so it can be distinguished from SigmaHQ-sourced rules
    rule["custom"] = True

    store = _get_store()
    store[rule["id"]] = rule
    logger.info("Custom rule upserted: id=%s title=%r", rule["id"], rule["title"])
    return rule
