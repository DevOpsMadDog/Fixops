"""MITRE ATT&CK Technique Extractor.

Pulls the STIX 2.1 enterprise-attack bundle from the MITRE CTI GitHub repo,
filters to attack-pattern objects, extracts structured fields, and upserts
into a local SQLite DB (PersistentDict pattern).

Usage:
    from feeds.mitre_attack.extractor import MitreAttackExtractor
    extractor = MitreAttackExtractor()
    result = extractor.run()
    # {"techniques": N, "subtechniques": N, "tactics": N, "platforms": N}
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import httpx

logger = logging.getLogger(__name__)

STIX_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
_DEFAULT_DB = Path("data/mitre_attack.db")
_HTTP_TIMEOUT = 60.0


# ---------------------------------------------------------------------------
# Lightweight SQLite store (PersistentDict pattern)
# ---------------------------------------------------------------------------

class _TechniqueStore:
    """SQLite-backed store for ATT&CK techniques."""

    def __init__(self, db_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS techniques (
                technique_id TEXT PRIMARY KEY,
                name         TEXT NOT NULL,
                description  TEXT,
                tactic_ids   TEXT,
                platforms    TEXT,
                tactic_type  TEXT,
                data_sources TEXT,
                is_subtechnique INTEGER DEFAULT 0,
                parent_id    TEXT,
                stix_id      TEXT,
                imported_at  TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def upsert(self, rec: Dict[str, Any]) -> None:
        self._conn.execute(
            """
            INSERT INTO techniques
              (technique_id, name, description, tactic_ids, platforms,
               tactic_type, data_sources, is_subtechnique, parent_id,
               stix_id, imported_at)
            VALUES
              (:technique_id, :name, :description, :tactic_ids, :platforms,
               :tactic_type, :data_sources, :is_subtechnique, :parent_id,
               :stix_id, :imported_at)
            ON CONFLICT(technique_id) DO UPDATE SET
              name          = excluded.name,
              description   = excluded.description,
              tactic_ids    = excluded.tactic_ids,
              platforms     = excluded.platforms,
              tactic_type   = excluded.tactic_type,
              data_sources  = excluded.data_sources,
              is_subtechnique = excluded.is_subtechnique,
              parent_id     = excluded.parent_id,
              stix_id       = excluded.stix_id,
              imported_at   = excluded.imported_at
            """,
            rec,
        )

    def commit(self) -> None:
        self._conn.commit()

    def all(self) -> List[Dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT technique_id, name, description, tactic_ids, platforms, "
            "tactic_type, data_sources, is_subtechnique, parent_id, stix_id, imported_at "
            "FROM techniques ORDER BY technique_id"
        )
        cols = [d[0] for d in cur.description]
        rows = []
        for row in cur.fetchall():
            d = dict(zip(cols, row))
            d["tactic_ids"] = json.loads(d["tactic_ids"] or "[]")
            d["platforms"] = json.loads(d["platforms"] or "[]")
            d["data_sources"] = json.loads(d["data_sources"] or "[]")
            rows.append(d)
        return rows

    def filter_by_tactic(self, tactic: str) -> List[Dict[str, Any]]:
        """Return techniques whose tactic_ids list contains *tactic*."""
        all_rows = self.all()
        tactic_lower = tactic.lower()
        return [r for r in all_rows if tactic_lower in [t.lower() for t in r["tactic_ids"]]]

    def close(self) -> None:
        self._conn.close()


# ---------------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------------

class MitreAttackExtractor:
    """Downloads STIX bundle and extracts ATT&CK techniques into SQLite."""

    def __init__(self, db_path: Path = _DEFAULT_DB) -> None:
        self._db_path = Path(db_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, bundle: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Fetch (or accept pre-loaded) STIX bundle and import techniques.

        Args:
            bundle: Pre-loaded STIX bundle dict. If None, downloads from MITRE.

        Returns:
            {"techniques": N, "subtechniques": N, "tactics": N, "platforms": N}
        """
        if bundle is None:
            bundle = self._fetch_bundle()
        return self._import(bundle)

    def get_store(self) -> _TechniqueStore:
        return _TechniqueStore(self._db_path)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _fetch_bundle(self) -> Dict[str, Any]:
        logger.info("mitre_attack.fetch_start", extra={"url": STIX_BUNDLE_URL})
        with httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=True) as client:
            resp = client.get(STIX_BUNDLE_URL)
            resp.raise_for_status()
        bundle = resp.json()
        logger.info("mitre_attack.fetch_done", extra={"objects": len(bundle.get("objects", []))})
        return bundle

    def _import(self, bundle: Dict[str, Any]) -> Dict[str, Any]:
        objects = bundle.get("objects", [])
        store = _TechniqueStore(self._db_path)
        imported_at = datetime.now(timezone.utc).isoformat()

        # Build stix_id → external_id index for parent-link resolution
        stix_to_ext: Dict[str, str] = {}
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            ext_id = _extract_external_id(obj)
            if ext_id:
                stix_to_ext[obj["id"]] = ext_id

        tactics_seen: Set[str] = set()
        platforms_seen: Set[str] = set()
        technique_count = 0
        subtechnique_count = 0

        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue

            ext_id = _extract_external_id(obj)
            if not ext_id:
                continue

            is_sub = "." in ext_id
            parent_id: Optional[str] = None
            if is_sub:
                parent_id = ext_id.split(".")[0]  # T1059.001 → T1059

            tactic_ids = _extract_tactics(obj)
            platforms = obj.get("x_mitre_platforms") or []
            tactic_type = obj.get("x_mitre_tactic_type") or ""
            data_sources = obj.get("x_mitre_data_sources") or []

            tactics_seen.update(tactic_ids)
            platforms_seen.update(platforms)

            store.upsert(
                {
                    "technique_id": ext_id,
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                    "tactic_ids": json.dumps(tactic_ids),
                    "platforms": json.dumps(platforms),
                    "tactic_type": tactic_type,
                    "data_sources": json.dumps(data_sources),
                    "is_subtechnique": int(is_sub),
                    "parent_id": parent_id,
                    "stix_id": obj.get("id", ""),
                    "imported_at": imported_at,
                }
            )

            if is_sub:
                subtechnique_count += 1
            else:
                technique_count += 1

        store.commit()
        store.close()

        result = {
            "techniques": technique_count,
            "subtechniques": subtechnique_count,
            "tactics": len(tactics_seen),
            "platforms": len(platforms_seen),
        }
        logger.info("mitre_attack.import_done", extra=result)
        return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_external_id(obj: Dict[str, Any]) -> Optional[str]:
    """Return the first MITRE-sourced external_id (T-number) from the object."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"):
            ext_id = ref.get("external_id", "")
            if ext_id.startswith("T"):
                return ext_id
    return None


def _extract_tactics(obj: Dict[str, Any]) -> List[str]:
    """Extract kill-chain phase names from kill_chain_phases."""
    return [
        phase["phase_name"]
        for phase in obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") in (
            "mitre-attack",
            "mitre-mobile-attack",
            "mitre-ics-attack",
        )
    ]


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_extractor_instance: Optional[MitreAttackExtractor] = None


def get_mitre_extractor(db_path: Path = _DEFAULT_DB) -> MitreAttackExtractor:
    global _extractor_instance
    if _extractor_instance is None:
        _extractor_instance = MitreAttackExtractor(db_path)
    return _extractor_instance
