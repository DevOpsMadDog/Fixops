"""Security Registry Engine — ALDECI.

Manages a centralized registry of security artifacts: policies, standards,
procedures, guidelines, controls, frameworks, tools, and runbooks.

Capabilities:
  - Artifact lifecycle: register, list, get, update status
  - Review workflow: record review, list reviews (approval sets artifact active)
  - Cross-references: add references between artifacts
  - Stats: totals, active/deprecated, by_type, by_status, pending_review, approval_rate

Compliance: NIST SP 800-53 PM-9, ISO 27001 A.5, CIS Control 3
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_registry.db"
)

_VALID_ARTIFACT_TYPES = {
    "policy",
    "standard",
    "procedure",
    "guideline",
    "control",
    "framework",
    "tool",
    "runbook",
}

_VALID_ARTIFACT_STATUSES = {
    "draft",
    "active",
    "deprecated",
    "under_review",
    "archived",
}

_VALID_REVIEW_OUTCOMES = {
    "approved",
    "rejected",
    "approved_with_changes",
    "deferred",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SecurityRegistryEngine:
    """SQLite WAL-backed Security Registry engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/security_registry.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path if db_path is not None else _DEFAULT_DB
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
                CREATE TABLE IF NOT EXISTS registry_artifacts (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    artifact_name    TEXT NOT NULL,
                    artifact_type    TEXT NOT NULL DEFAULT 'policy',
                    version          TEXT NOT NULL DEFAULT '1.0',
                    artifact_status  TEXT NOT NULL DEFAULT 'draft',
                    description      TEXT NOT NULL DEFAULT '',
                    owner            TEXT NOT NULL DEFAULT '',
                    review_date      DATETIME,
                    next_review_date DATETIME,
                    reviewer         TEXT NOT NULL DEFAULT '',
                    download_url     TEXT NOT NULL DEFAULT '',
                    tag_list         TEXT NOT NULL DEFAULT '',
                    created_at       DATETIME,
                    updated_at       DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_registry_artifacts_org
                    ON registry_artifacts (org_id, artifact_type, artifact_status, created_at DESC);

                CREATE TABLE IF NOT EXISTS artifact_reviews (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    artifact_id      TEXT NOT NULL,
                    review_date      DATETIME,
                    reviewer         TEXT NOT NULL,
                    review_outcome   TEXT NOT NULL,
                    comments         TEXT NOT NULL DEFAULT '',
                    next_review_date DATETIME,
                    created_at       DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_artifact_reviews_org
                    ON artifact_reviews (org_id, artifact_id, review_outcome, created_at DESC);

                CREATE TABLE IF NOT EXISTS artifact_references (
                    id                    TEXT PRIMARY KEY,
                    org_id                TEXT NOT NULL,
                    artifact_id           TEXT NOT NULL,
                    referenced_artifact_id TEXT NOT NULL,
                    reference_type        TEXT NOT NULL DEFAULT 'related',
                    notes                 TEXT NOT NULL DEFAULT '',
                    created_at            DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_artifact_references_org
                    ON artifact_references (org_id, artifact_id, created_at DESC);
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
    def _split_tags(tag_list_str: str) -> List[str]:
        """Split a comma-joined tag string into a list, filtering empties."""
        if not tag_list_str:
            return []
        return [t.strip() for t in tag_list_str.split(",") if t.strip()]

    def _artifact_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Convert a registry_artifacts row to dict with tags as list."""
        d = self._row(row)
        d["tag_list"] = self._split_tags(d.get("tag_list") or "")
        return d

    # ------------------------------------------------------------------
    # Artifacts
    # ------------------------------------------------------------------

    def register_artifact(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new security artifact."""
        artifact_name = (data.get("artifact_name") or "").strip()
        if not artifact_name:
            raise ValueError("artifact_name is required.")

        artifact_type = data.get("artifact_type", "policy")
        if artifact_type not in _VALID_ARTIFACT_TYPES:
            raise ValueError(
                f"Invalid artifact_type: {artifact_type!r}. "
                f"Must be one of {sorted(_VALID_ARTIFACT_TYPES)}"
            )

        artifact_status = data.get("artifact_status", "draft")
        if artifact_status not in _VALID_ARTIFACT_STATUSES:
            artifact_status = "draft"

        # tag_list: accept list or comma-string, store as comma-joined
        raw_tags = data.get("tag_list", [])
        if isinstance(raw_tags, list):
            tag_list_str = ",".join(str(t).strip() for t in raw_tags if str(t).strip())
        else:
            tag_list_str = str(raw_tags)

        now = _now_iso()
        record_db: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "artifact_name": artifact_name,
            "artifact_type": artifact_type,
            "version": data.get("version", "1.0"),
            "artifact_status": artifact_status,
            "description": data.get("description", ""),
            "owner": data.get("owner", ""),
            "review_date": data.get("review_date", None),
            "next_review_date": data.get("next_review_date", None),
            "reviewer": data.get("reviewer", ""),
            "download_url": data.get("download_url", ""),
            "tag_list": tag_list_str,
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO registry_artifacts
                       (id, org_id, artifact_name, artifact_type, version, artifact_status,
                        description, owner, review_date, next_review_date, reviewer,
                        download_url, tag_list, created_at, updated_at)
                       VALUES (:id, :org_id, :artifact_name, :artifact_type, :version,
                               :artifact_status, :description, :owner, :review_date,
                               :next_review_date, :reviewer, :download_url, :tag_list,
                               :created_at, :updated_at)""",
                    record_db,
                )

        result = dict(record_db)
        result["tag_list"] = self._split_tags(tag_list_str)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "security_registry", "org_id": org_id, "source_engine": "security_registry"})
            except Exception:
                pass

        return result

    def list_artifacts(
        self,
        org_id: str,
        artifact_type: Optional[str] = None,
        artifact_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List artifacts with optional type/status filters."""
        sql = "SELECT * FROM registry_artifacts WHERE org_id = ?"
        params: list = [org_id]
        if artifact_type:
            sql += " AND artifact_type = ?"
            params.append(artifact_type)
        if artifact_status:
            sql += " AND artifact_status = ?"
            params.append(artifact_status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._artifact_to_dict(r) for r in rows]

    def get_artifact(self, org_id: str, artifact_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single artifact by ID. Returns None if not found or wrong org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM registry_artifacts WHERE org_id = ? AND id = ?",
                (org_id, artifact_id),
            ).fetchone()
        return self._artifact_to_dict(row) if row else None

    def update_artifact_status(
        self, org_id: str, artifact_id: str, new_status: str
    ) -> Dict[str, Any]:
        """Update the status of an artifact. Raises KeyError if not found."""
        if new_status not in _VALID_ARTIFACT_STATUSES:
            raise ValueError(
                f"Invalid artifact_status: {new_status!r}. "
                f"Must be one of {sorted(_VALID_ARTIFACT_STATUSES)}"
            )
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                result = conn.execute(
                    "UPDATE registry_artifacts SET artifact_status = ?, updated_at = ? "
                    "WHERE org_id = ? AND id = ?",
                    (new_status, now, org_id, artifact_id),
                )
                if result.rowcount == 0:
                    raise KeyError(
                        f"Artifact '{artifact_id}' not found in org '{org_id}'."
                    )
                row = conn.execute(
                    "SELECT * FROM registry_artifacts WHERE org_id = ? AND id = ?",
                    (org_id, artifact_id),
                ).fetchone()
        return self._artifact_to_dict(row)

    # ------------------------------------------------------------------
    # Reviews
    # ------------------------------------------------------------------

    def record_review(
        self, org_id: str, artifact_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Record a review for an artifact. If approved, sets artifact to active."""
        review_outcome = (data.get("review_outcome") or "").strip()
        if review_outcome not in _VALID_REVIEW_OUTCOMES:
            raise ValueError(
                f"Invalid review_outcome: {review_outcome!r}. "
                f"Must be one of {sorted(_VALID_REVIEW_OUTCOMES)}"
            )

        reviewer = (data.get("reviewer") or "").strip()
        if not reviewer:
            raise ValueError("reviewer is required.")

        now = _now_iso()
        review_date = data.get("review_date", now)
        next_review_date = data.get("next_review_date", None)

        review_record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "artifact_id": artifact_id,
            "review_date": review_date,
            "reviewer": reviewer,
            "review_outcome": review_outcome,
            "comments": data.get("comments", ""),
            "next_review_date": next_review_date,
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO artifact_reviews
                       (id, org_id, artifact_id, review_date, reviewer, review_outcome,
                        comments, next_review_date, created_at)
                       VALUES (:id, :org_id, :artifact_id, :review_date, :reviewer,
                               :review_outcome, :comments, :next_review_date, :created_at)""",
                    review_record,
                )

                # Update artifact: reviewer, review_date, next_review_date
                new_status_sql = (
                    ", artifact_status = 'active'" if review_outcome == "approved" else ""
                )
                conn.execute(
                    f"""UPDATE registry_artifactsSET reviewer = ?, review_date = ?, next_review_date = ?,
                            updated_at = ?{new_status_sql}
                        WHERE org_id = ? AND id = ?""",  # nosec B608
                    (reviewer, review_date, next_review_date, now, org_id, artifact_id),
                )

        return review_record

    def list_reviews(
        self,
        org_id: str,
        artifact_id: Optional[str] = None,
        review_outcome: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List reviews with optional filters."""
        sql = "SELECT * FROM artifact_reviews WHERE org_id = ?"
        params: list = [org_id]
        if artifact_id:
            sql += " AND artifact_id = ?"
            params.append(artifact_id)
        if review_outcome:
            sql += " AND review_outcome = ?"
            params.append(review_outcome)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # References
    # ------------------------------------------------------------------

    def add_reference(
        self, org_id: str, artifact_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a cross-reference between two artifacts. Both must exist in org."""
        referenced_artifact_id = (data.get("referenced_artifact_id") or "").strip()
        if not referenced_artifact_id:
            raise ValueError("referenced_artifact_id is required.")

        with self._lock:
            with self._conn() as conn:
                # Validate source artifact
                src_row = conn.execute(
                    "SELECT id FROM registry_artifacts WHERE org_id = ? AND id = ?",
                    (org_id, artifact_id),
                ).fetchone()
                if not src_row:
                    raise KeyError(
                        f"Artifact '{artifact_id}' not found in org '{org_id}'."
                    )

                # Validate referenced artifact
                ref_row = conn.execute(
                    "SELECT id FROM registry_artifacts WHERE org_id = ? AND id = ?",
                    (org_id, referenced_artifact_id),
                ).fetchone()
                if not ref_row:
                    raise KeyError(
                        f"Referenced artifact '{referenced_artifact_id}' not found "
                        f"in org '{org_id}'."
                    )

                now = _now_iso()
                record: Dict[str, Any] = {
                    "id": str(uuid.uuid4()),
                    "org_id": org_id,
                    "artifact_id": artifact_id,
                    "referenced_artifact_id": referenced_artifact_id,
                    "reference_type": data.get("reference_type", "related"),
                    "notes": data.get("notes", ""),
                    "created_at": now,
                }
                conn.execute(
                    """INSERT INTO artifact_references
                       (id, org_id, artifact_id, referenced_artifact_id,
                        reference_type, notes, created_at)
                       VALUES (:id, :org_id, :artifact_id, :referenced_artifact_id,
                               :reference_type, :notes, :created_at)""",
                    record,
                )
        return record

    def list_references(
        self, org_id: str, artifact_id: str
    ) -> List[Dict[str, Any]]:
        """List all references for an artifact."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM artifact_references "
                "WHERE org_id = ? AND artifact_id = ? "
                "ORDER BY created_at DESC",
                (org_id, artifact_id),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_registry_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated registry statistics for an org."""
        now = _now_iso()
        with self._conn() as conn:
            total_artifacts = conn.execute(
                "SELECT COUNT(*) FROM registry_artifacts WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            active_artifacts = conn.execute(
                "SELECT COUNT(*) FROM registry_artifacts "
                "WHERE org_id = ? AND artifact_status = 'active'",
                (org_id,),
            ).fetchone()[0]

            deprecated_artifacts = conn.execute(
                "SELECT COUNT(*) FROM registry_artifacts "
                "WHERE org_id = ? AND artifact_status = 'deprecated'",
                (org_id,),
            ).fetchone()[0]

            by_type_rows = conn.execute(
                "SELECT artifact_type, COUNT(*) AS cnt FROM registry_artifacts "
                "WHERE org_id = ? GROUP BY artifact_type",
                (org_id,),
            ).fetchall()

            by_status_rows = conn.execute(
                "SELECT artifact_status, COUNT(*) AS cnt FROM registry_artifacts "
                "WHERE org_id = ? GROUP BY artifact_status",
                (org_id,),
            ).fetchall()

            # Pending review: next_review_date < now AND status = active
            pending_review = conn.execute(
                "SELECT COUNT(*) FROM registry_artifacts "
                "WHERE org_id = ? AND artifact_status = 'active' "
                "AND next_review_date IS NOT NULL AND next_review_date < ?",
                (org_id, now),
            ).fetchone()[0]

            total_reviews = conn.execute(
                "SELECT COUNT(*) FROM artifact_reviews WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            approved_reviews = conn.execute(
                "SELECT COUNT(*) FROM artifact_reviews "
                "WHERE org_id = ? AND review_outcome = 'approved'",
                (org_id,),
            ).fetchone()[0]

        approval_rate = (
            round((approved_reviews / total_reviews) * 100.0, 2)
            if total_reviews > 0
            else 0.0
        )

        return {
            "total_artifacts": total_artifacts,
            "active_artifacts": active_artifacts,
            "deprecated_artifacts": deprecated_artifacts,
            "by_type": {r["artifact_type"]: r["cnt"] for r in by_type_rows},
            "by_status": {r["artifact_status"]: r["cnt"] for r in by_status_rows},
            "pending_review": pending_review,
            "total_reviews": total_reviews,
            "approval_rate": approval_rate,
        }
