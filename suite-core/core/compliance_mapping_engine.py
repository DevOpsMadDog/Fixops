"""Compliance Mapping Engine — ALDECI.

Cross-framework control mapping: NIST CSF, ISO 27001, PCI-DSS, SOC 2, HIPAA,
GDPR, CIS Controls, NIST 800-53. Tracks evidence, implementation status, and
coverage statistics across all frameworks.

Compliance: NIST CSF ID.GV-4, ISO/IEC 27001 A.18.2, SOC 2 CC9.1
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "compliance_mapping.db"
)

_VALID_FRAMEWORKS = {
    "nist_csf", "iso27001", "pci_dss", "soc2", "hipaa",
    "gdpr", "cis_controls", "nist_800_53",
}
_VALID_CONTROL_STATUSES = {
    "implemented", "partial", "not_implemented", "not_applicable",
}
_VALID_MAPPING_STRENGTHS = {"strong", "moderate", "weak"}


class ComplianceMappingEngine:
    """SQLite WAL-backed Compliance Mapping engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS compliance_controls (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    control_id           TEXT NOT NULL,
                    framework            TEXT NOT NULL,
                    control_name         TEXT NOT NULL DEFAULT '',
                    description          TEXT NOT NULL DEFAULT '',
                    control_status       TEXT NOT NULL DEFAULT 'not_implemented',
                    implementation_notes TEXT NOT NULL DEFAULT '',
                    owner                TEXT NOT NULL DEFAULT '',
                    evidence_count       INTEGER NOT NULL DEFAULT 0,
                    last_reviewed        DATETIME,
                    created_at           DATETIME NOT NULL
                );

                CREATE TABLE IF NOT EXISTS control_mappings (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    source_control_id TEXT NOT NULL,
                    target_control_id TEXT NOT NULL,
                    source_framework TEXT NOT NULL,
                    target_framework TEXT NOT NULL,
                    mapping_strength TEXT NOT NULL DEFAULT 'moderate',
                    notes            TEXT NOT NULL DEFAULT '',
                    created_at       DATETIME NOT NULL
                );

                CREATE TABLE IF NOT EXISTS control_evidence (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    control_id     TEXT NOT NULL,
                    evidence_type  TEXT NOT NULL DEFAULT '',
                    description    TEXT NOT NULL DEFAULT '',
                    file_reference TEXT NOT NULL DEFAULT '',
                    collected_at   DATETIME,
                    expires_at     DATETIME,
                    collector      TEXT NOT NULL DEFAULT '',
                    created_at     DATETIME NOT NULL
                );
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Controls
    # ------------------------------------------------------------------

    def add_control(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a compliance control.

        Required: control_id, control_name.
        framework defaults to 'nist_csf'; control_status defaults to 'not_implemented'.
        """
        control_id = (data.get("control_id") or "").strip()
        if not control_id:
            raise ValueError("control_id is required")

        control_name = (data.get("control_name") or "").strip()
        if not control_name:
            raise ValueError("control_name is required")

        framework = data.get("framework", "nist_csf")
        if framework not in _VALID_FRAMEWORKS:
            raise ValueError(
                f"Invalid framework '{framework}'. Valid: {sorted(_VALID_FRAMEWORKS)}"
            )

        control_status = data.get("control_status", "not_implemented")
        if control_status not in _VALID_CONTROL_STATUSES:
            raise ValueError(
                f"Invalid control_status '{control_status}'. "
                f"Valid: {sorted(_VALID_CONTROL_STATUSES)}"
            )

        now = self._now()
        rec = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "control_id": control_id,
            "framework": framework,
            "control_name": control_name,
            "description": data.get("description", ""),
            "control_status": control_status,
            "implementation_notes": data.get("implementation_notes", ""),
            "owner": data.get("owner", ""),
            "evidence_count": 0,
            "last_reviewed": data.get("last_reviewed"),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO compliance_controls
                        (id, org_id, control_id, framework, control_name, description,
                         control_status, implementation_notes, owner, evidence_count,
                         last_reviewed, created_at)
                    VALUES
                        (:id, :org_id, :control_id, :framework, :control_name,
                         :description, :control_status, :implementation_notes,
                         :owner, :evidence_count, :last_reviewed, :created_at)
                    """,
                    rec,
                )
        if _get_tg_bus is not None:
            try:
                _get_tg_bus().emit("CONTROL_ASSESSED", {
                    "org_id": org_id,
                    "entity": "compliance_control",
                    "record_id": rec["id"],
                    "control_id": control_id,
                    "framework": framework,
                    "control_status": control_status,
                })
            except Exception:
                pass
        return rec

    def list_controls(
        self,
        org_id: str,
        framework: Optional[str] = None,
        control_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List compliance controls with optional filters."""
        query = "SELECT * FROM compliance_controls WHERE org_id = ?"
        params: List[Any] = [org_id]

        if framework is not None:
            query += " AND framework = ?"
            params.append(framework)
        if control_status is not None:
            query += " AND control_status = ?"
            params.append(control_status)

        query += " ORDER BY framework, control_id"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_control(self, org_id: str, control_id_param: str) -> Optional[Dict[str, Any]]:
        """Get a single control by its primary-key id column."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM compliance_controls WHERE org_id = ? AND id = ?",
                (org_id, control_id_param),
            ).fetchone()
        return self._row(row) if row else None

    def update_control_status(
        self,
        org_id: str,
        control_id_param: str,
        new_status: str,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update control_status (and optionally implementation_notes).

        Raises KeyError if control not found, ValueError for invalid status.
        """
        if new_status not in _VALID_CONTROL_STATUSES:
            raise ValueError(
                f"Invalid control_status '{new_status}'. "
                f"Valid: {sorted(_VALID_CONTROL_STATUSES)}"
            )

        now = self._now()
        with self._lock:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT * FROM compliance_controls WHERE org_id = ? AND id = ?",
                    (org_id, control_id_param),
                ).fetchone()
                if existing is None:
                    raise KeyError(f"Control '{control_id_param}' not found")

                if notes is not None:
                    conn.execute(
                        """
                        UPDATE compliance_controls
                        SET control_status = ?, implementation_notes = ?, last_reviewed = ?
                        WHERE org_id = ? AND id = ?
                        """,
                        (new_status, notes, now, org_id, control_id_param),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE compliance_controls
                        SET control_status = ?, last_reviewed = ?
                        WHERE org_id = ? AND id = ?
                        """,
                        (new_status, now, org_id, control_id_param),
                    )

                row = conn.execute(
                    "SELECT * FROM compliance_controls WHERE org_id = ? AND id = ?",
                    (org_id, control_id_param),
                ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # Mappings
    # ------------------------------------------------------------------

    def add_mapping(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a cross-framework control mapping.

        Required: source_control_id, target_control_id, source_framework,
        target_framework, mapping_strength.
        """
        source_control_id = (data.get("source_control_id") or "").strip()
        if not source_control_id:
            raise ValueError("source_control_id is required")

        target_control_id = (data.get("target_control_id") or "").strip()
        if not target_control_id:
            raise ValueError("target_control_id is required")

        source_framework = data.get("source_framework", "")
        if source_framework not in _VALID_FRAMEWORKS:
            raise ValueError(
                f"Invalid source_framework '{source_framework}'. "
                f"Valid: {sorted(_VALID_FRAMEWORKS)}"
            )

        target_framework = data.get("target_framework", "")
        if target_framework not in _VALID_FRAMEWORKS:
            raise ValueError(
                f"Invalid target_framework '{target_framework}'. "
                f"Valid: {sorted(_VALID_FRAMEWORKS)}"
            )

        mapping_strength = data.get("mapping_strength", "")
        if mapping_strength not in _VALID_MAPPING_STRENGTHS:
            raise ValueError(
                f"Invalid mapping_strength '{mapping_strength}'. "
                f"Valid: {sorted(_VALID_MAPPING_STRENGTHS)}"
            )

        now = self._now()
        rec = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "source_control_id": source_control_id,
            "target_control_id": target_control_id,
            "source_framework": source_framework,
            "target_framework": target_framework,
            "mapping_strength": mapping_strength,
            "notes": data.get("notes", ""),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO control_mappings
                        (id, org_id, source_control_id, target_control_id,
                         source_framework, target_framework, mapping_strength,
                         notes, created_at)
                    VALUES
                        (:id, :org_id, :source_control_id, :target_control_id,
                         :source_framework, :target_framework, :mapping_strength,
                         :notes, :created_at)
                    """,
                    rec,
                )
        return rec

    def list_mappings(
        self,
        org_id: str,
        source_framework: Optional[str] = None,
        target_framework: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List mappings with optional framework filters."""
        query = "SELECT * FROM control_mappings WHERE org_id = ?"
        params: List[Any] = [org_id]

        if source_framework is not None:
            query += " AND source_framework = ?"
            params.append(source_framework)
        if target_framework is not None:
            query += " AND target_framework = ?"
            params.append(target_framework)

        query += " ORDER BY source_framework, source_control_id"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------

    def add_evidence(
        self, org_id: str, control_id_param: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add evidence for a control; increments evidence_count on the control.

        Required: evidence_type, description.
        control_id_param is the primary-key id of the compliance_controls row.
        """
        evidence_type = (data.get("evidence_type") or "").strip()
        if not evidence_type:
            raise ValueError("evidence_type is required")

        description = (data.get("description") or "").strip()
        if not description:
            raise ValueError("description is required")

        now = self._now()
        rec = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "control_id": control_id_param,
            "evidence_type": evidence_type,
            "description": description,
            "file_reference": data.get("file_reference", ""),
            "collected_at": data.get("collected_at", now),
            "expires_at": data.get("expires_at"),
            "collector": data.get("collector", ""),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO control_evidence
                        (id, org_id, control_id, evidence_type, description,
                         file_reference, collected_at, expires_at, collector, created_at)
                    VALUES
                        (:id, :org_id, :control_id, :evidence_type, :description,
                         :file_reference, :collected_at, :expires_at, :collector,
                         :created_at)
                    """,
                    rec,
                )
                # Increment evidence_count on the parent control
                conn.execute(
                    """
                    UPDATE compliance_controls
                    SET evidence_count = evidence_count + 1
                    WHERE org_id = ? AND id = ?
                    """,
                    (org_id, control_id_param),
                )
        return rec

    def list_evidence(
        self,
        org_id: str,
        control_id_param: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List evidence records; optionally filter by control primary-key id."""
        query = "SELECT * FROM control_evidence WHERE org_id = ?"
        params: List[Any] = [org_id]

        if control_id_param is not None:
            query += " AND control_id = ?"
            params.append(control_id_param)

        query += " ORDER BY collected_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_control_context(self, org_id: str, control_id: str) -> Dict[str, Any]:
        """Query TrustGraph for cross-domain context about a compliance control.

        Returns related findings, evidence, and assets covered by this control.
        Degrades gracefully when TrustGraph is unavailable.
        """
        context: Dict[str, Any] = {
            "related_assets": [],
            "related_findings": [],
            "related_evidence": [],
            "trustgraph_available": False,
        }
        try:
            from trustgraph.knowledge_store import KnowledgeStore
            store = KnowledgeStore()
            context["trustgraph_available"] = True

            control = self.get_control(org_id, control_id)
            search_term = control.get("control_name", control_id) if control else control_id

            for core_id in (1, 2, 3):
                try:
                    results = store.search(core_id=core_id, query_text=search_term, limit=10)
                    for entity in results:
                        if entity.org_id not in ("default", org_id):
                            continue
                        entry = {"id": entity.entity_id, "name": entity.name, "type": entity.entity_type}
                        etype = entity.entity_type.lower()
                        if etype in ("asset", "service", "host"):
                            context["related_assets"].append(entry)
                        elif etype in ("finding", "vulnerability", "cve"):
                            context["related_findings"].append(entry)
                        elif etype in ("evidence", "document", "artifact"):
                            context["related_evidence"].append(entry)
                except Exception:
                    pass

            neighbors = store.get_neighbors(entity_id=control_id, depth=1)
            for n in neighbors:
                if n.org_id not in ("default", org_id):
                    continue
                entry = {"id": n.entity_id, "name": n.name, "type": n.entity_type}
                etype = n.entity_type.lower()
                if etype in ("asset", "service", "host"):
                    if entry not in context["related_assets"]:
                        context["related_assets"].append(entry)
                elif etype in ("finding", "vulnerability", "cve"):
                    if entry not in context["related_findings"]:
                        context["related_findings"].append(entry)
                elif etype in ("evidence", "document", "artifact"):
                    if entry not in context["related_evidence"]:
                        context["related_evidence"].append(entry)
        except Exception:
            pass
        return context

    def get_mapping_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate mapping statistics for an org.

        Returns:
            total_controls, by_framework, by_status,
            implementation_rate (% of implemented + partial),
            total_mappings, controls_with_evidence.
        """
        with self._conn() as conn:
            total_controls: int = conn.execute(
                "SELECT COUNT(*) FROM compliance_controls WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            # Per-framework counts
            fw_rows = conn.execute(
                """
                SELECT framework, COUNT(*) as cnt
                FROM compliance_controls WHERE org_id = ?
                GROUP BY framework
                """,
                (org_id,),
            ).fetchall()
            by_framework = {r["framework"]: r["cnt"] for r in fw_rows}

            # Per-status counts
            st_rows = conn.execute(
                """
                SELECT control_status, COUNT(*) as cnt
                FROM compliance_controls WHERE org_id = ?
                GROUP BY control_status
                """,
                (org_id,),
            ).fetchall()
            by_status = {r["control_status"]: r["cnt"] for r in st_rows}

            # Implementation rate: (implemented + partial) / total
            implemented = by_status.get("implemented", 0) + by_status.get("partial", 0)
            implementation_rate = (
                round(implemented / total_controls * 100, 2)
                if total_controls > 0
                else 0.0
            )

            total_mappings: int = conn.execute(
                "SELECT COUNT(*) FROM control_mappings WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            controls_with_evidence: int = conn.execute(
                """
                SELECT COUNT(*) FROM compliance_controls
                WHERE org_id = ? AND evidence_count > 0
                """,
                (org_id,),
            ).fetchone()[0]

        return {
            "total_controls": total_controls,
            "by_framework": by_framework,
            "by_status": by_status,
            "implementation_rate": implementation_rate,
            "total_mappings": total_mappings,
            "controls_with_evidence": controls_with_evidence,
        }
