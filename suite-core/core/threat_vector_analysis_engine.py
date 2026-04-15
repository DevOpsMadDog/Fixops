"""Threat Vector Analysis Engine — ALDECI.

Tracks attack vectors by type (network, email, supply_chain, etc.),
associates indicators (IPs, domains, hashes, etc.) with each vector,
and manages mitigation plans through their lifecycle.

Compliance: NIST CSF ID.RA-3, ISO/IEC 27001 A.6.1.2, MITRE ATT&CK
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "threat_vector_analysis.db"
)

_VALID_VECTOR_TYPES = {
    "network", "email", "supply_chain", "insider",
    "physical", "social_engineering", "zero_day", "credential_stuffing",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_INDICATOR_TYPES = {"ip", "domain", "url", "hash", "email", "file"}
_VALID_MITIGATION_STATUSES = {"planned", "in_progress", "completed", "deferred"}


class ThreatVectorAnalysisEngine:
    """SQLite WAL-backed Threat Vector Analysis engine.

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
                CREATE TABLE IF NOT EXISTS threat_vectors (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    vector_type      TEXT NOT NULL DEFAULT 'network',
                    name             TEXT NOT NULL DEFAULT '',
                    severity         TEXT NOT NULL DEFAULT 'medium',
                    description      TEXT NOT NULL DEFAULT '',
                    frequency_score  REAL NOT NULL DEFAULT 50,
                    impact_score     REAL NOT NULL DEFAULT 50,
                    risk_score       REAL NOT NULL DEFAULT 50,
                    indicator_count  INTEGER NOT NULL DEFAULT 0,
                    mitigation_count INTEGER NOT NULL DEFAULT 0,
                    first_observed   DATETIME,
                    last_observed    DATETIME,
                    status           TEXT NOT NULL DEFAULT 'active',
                    created_at       DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tv_org
                    ON threat_vectors (org_id);
                CREATE INDEX IF NOT EXISTS idx_tv_org_type
                    ON threat_vectors (org_id, vector_type);
                CREATE INDEX IF NOT EXISTS idx_tv_org_severity
                    ON threat_vectors (org_id, severity);

                CREATE TABLE IF NOT EXISTS vector_indicators (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    vector_id      TEXT NOT NULL,
                    indicator_type TEXT NOT NULL DEFAULT 'ip',
                    value          TEXT NOT NULL DEFAULT '',
                    confidence     REAL NOT NULL DEFAULT 50,
                    source         TEXT NOT NULL DEFAULT '',
                    added_at       DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_vi_org_vector
                    ON vector_indicators (org_id, vector_id);
                CREATE INDEX IF NOT EXISTS idx_vi_org_type
                    ON vector_indicators (org_id, indicator_type);

                CREATE TABLE IF NOT EXISTS vector_mitigations (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    vector_id         TEXT NOT NULL,
                    title             TEXT NOT NULL DEFAULT '',
                    description       TEXT NOT NULL DEFAULT '',
                    mitigation_status TEXT NOT NULL DEFAULT 'planned',
                    assigned_to       TEXT NOT NULL DEFAULT '',
                    due_date          TEXT NOT NULL DEFAULT '',
                    completed_at      DATETIME,
                    created_at        DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_vm_org_vector
                    ON vector_mitigations (org_id, vector_id);
                CREATE INDEX IF NOT EXISTS idx_vm_org_status
                    ON vector_mitigations (org_id, mitigation_status);
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
    # Threat Vectors
    # ------------------------------------------------------------------

    def record_vector(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a new threat vector.

        Required: name, vector_type, severity
        Defaults: frequency_score=50, impact_score=50
        risk_score = (frequency_score + impact_score) / 2
        """
        name = data.get("name", "")
        if not name:
            raise ValueError("'name' is required")

        vector_type = data.get("vector_type", "network")
        if vector_type not in _VALID_VECTOR_TYPES:
            raise ValueError(
                f"Invalid vector_type '{vector_type}'. Valid: {sorted(_VALID_VECTOR_TYPES)}"
            )

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{severity}'. Valid: {sorted(_VALID_SEVERITIES)}"
            )

        frequency_score = float(data.get("frequency_score", 50))
        impact_score = float(data.get("impact_score", 50))
        risk_score = (frequency_score + impact_score) / 2.0

        now = self._now()
        vector_id = str(uuid.uuid4())

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO threat_vectors
                        (id, org_id, vector_type, name, severity, description,
                         frequency_score, impact_score, risk_score,
                         indicator_count, mitigation_count,
                         first_observed, last_observed, status, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        vector_id,
                        org_id,
                        vector_type,
                        name,
                        severity,
                        data.get("description", ""),
                        frequency_score,
                        impact_score,
                        risk_score,
                        0,
                        0,
                        data.get("first_observed", now),
                        data.get("last_observed", now),
                        "active",
                        now,
                    ),
                )

        return self.get_vector(org_id, vector_id)  # type: ignore[return-value]

    def list_vectors(
        self,
        org_id: str,
        vector_type: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List threat vectors with optional filters, newest first."""
        query = "SELECT * FROM threat_vectors WHERE org_id = ?"
        params: List[Any] = [org_id]

        if vector_type:
            query += " AND vector_type = ?"
            params.append(vector_type)
        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_vector(self, org_id: str, vector_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single threat vector by ID (org-scoped)."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM threat_vectors WHERE id = ? AND org_id = ?",
                (vector_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Indicators
    # ------------------------------------------------------------------

    def add_indicator(
        self, org_id: str, vector_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add an indicator to a threat vector.

        Required: indicator_type, value
        Increments vector.indicator_count.
        """
        indicator_type = data.get("indicator_type", "ip")
        if indicator_type not in _VALID_INDICATOR_TYPES:
            raise ValueError(
                f"Invalid indicator_type '{indicator_type}'. "
                f"Valid: {sorted(_VALID_INDICATOR_TYPES)}"
            )

        value = data.get("value", "")
        if not value:
            raise ValueError("'value' is required")

        indicator_id = str(uuid.uuid4())
        now = self._now()
        confidence = float(data.get("confidence", 50))

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO vector_indicators
                        (id, org_id, vector_id, indicator_type, value,
                         confidence, source, added_at)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        indicator_id,
                        org_id,
                        vector_id,
                        indicator_type,
                        value,
                        confidence,
                        data.get("source", ""),
                        now,
                    ),
                )
                conn.execute(
                    """
                    UPDATE threat_vectors
                    SET indicator_count = indicator_count + 1
                    WHERE id = ? AND org_id = ?
                    """,
                    (vector_id, org_id),
                )

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM vector_indicators WHERE id = ?", (indicator_id,)
            ).fetchone()
        return self._row(row)

    def list_indicators(
        self,
        org_id: str,
        vector_id: Optional[str] = None,
        indicator_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List indicators with optional filters."""
        query = "SELECT * FROM vector_indicators WHERE org_id = ?"
        params: List[Any] = [org_id]

        if vector_id:
            query += " AND vector_id = ?"
            params.append(vector_id)
        if indicator_type:
            query += " AND indicator_type = ?"
            params.append(indicator_type)

        query += " ORDER BY added_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Mitigations
    # ------------------------------------------------------------------

    def create_mitigation(
        self, org_id: str, vector_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a mitigation plan for a threat vector.

        Required: title
        Increments vector.mitigation_count.
        """
        title = data.get("title", "")
        if not title:
            raise ValueError("'title' is required")

        mitigation_status = data.get("mitigation_status", "planned")
        if mitigation_status not in _VALID_MITIGATION_STATUSES:
            raise ValueError(
                f"Invalid mitigation_status '{mitigation_status}'. "
                f"Valid: {sorted(_VALID_MITIGATION_STATUSES)}"
            )

        mitigation_id = str(uuid.uuid4())
        now = self._now()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO vector_mitigations
                        (id, org_id, vector_id, title, description,
                         mitigation_status, assigned_to, due_date,
                         completed_at, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        mitigation_id,
                        org_id,
                        vector_id,
                        title,
                        data.get("description", ""),
                        mitigation_status,
                        data.get("assigned_to", ""),
                        data.get("due_date", ""),
                        data.get("completed_at", None),
                        now,
                    ),
                )
                conn.execute(
                    """
                    UPDATE threat_vectors
                    SET mitigation_count = mitigation_count + 1
                    WHERE id = ? AND org_id = ?
                    """,
                    (vector_id, org_id),
                )

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM vector_mitigations WHERE id = ?", (mitigation_id,)
            ).fetchone()
        return self._row(row)

    def list_mitigations(
        self,
        org_id: str,
        vector_id: Optional[str] = None,
        mitigation_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List mitigations with optional filters."""
        query = "SELECT * FROM vector_mitigations WHERE org_id = ?"
        params: List[Any] = [org_id]

        if vector_id:
            query += " AND vector_id = ?"
            params.append(vector_id)
        if mitigation_status:
            query += " AND mitigation_status = ?"
            params.append(mitigation_status)

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_vector_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate stats for the org."""
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM threat_vectors WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            active_vectors = conn.execute(
                "SELECT COUNT(*) FROM threat_vectors WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]

            critical_vectors = conn.execute(
                "SELECT COUNT(*) FROM threat_vectors WHERE org_id = ? AND severity = 'critical'",
                (org_id,),
            ).fetchone()[0]

            total_indicators = conn.execute(
                "SELECT COUNT(*) FROM vector_indicators WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            open_mitigations = conn.execute(
                """
                SELECT COUNT(*) FROM vector_mitigations
                WHERE org_id = ? AND mitigation_status IN ('planned', 'in_progress')
                """,
                (org_id,),
            ).fetchone()[0]

            avg_risk_row = conn.execute(
                "SELECT AVG(risk_score) FROM threat_vectors WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            avg_risk_score = round(float(avg_risk_row), 2) if avg_risk_row else 0.0

            type_rows = conn.execute(
                """
                SELECT vector_type, COUNT(*) as cnt
                FROM threat_vectors WHERE org_id = ?
                GROUP BY vector_type
                """,
                (org_id,),
            ).fetchall()
            by_vector_type = {r["vector_type"]: r["cnt"] for r in type_rows}

        return {
            "total_vectors": total,
            "active_vectors": active_vectors,
            "critical_vectors": critical_vectors,
            "total_indicators": total_indicators,
            "open_mitigations": open_mitigations,
            "avg_risk_score": avg_risk_score,
            "by_vector_type": by_vector_type,
        }
