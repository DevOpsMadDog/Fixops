"""Security Posture Maturity Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

CMMI-style security maturity assessment across domains:
  - Record capability maturity assessments (level 1..5)
  - Build roadmap items with planned→in_progress→completed lifecycle
  - Take point-in-time snapshots (overall_level = avg across assessments)
  - Domain breakdown, overdue review detection

Compliance: CMMI, NIST CSF, ISO 27001, CIS Controls v8
"""
from __future__ import annotations

import json
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_posture_maturity.db"
)

VALID_DOMAINS = frozenset({
    "identity", "network", "endpoint", "data", "application",
    "cloud", "physical", "governance", "risk", "compliance",
})
VALID_PRIORITIES = frozenset({"critical", "high", "medium", "low"})
VALID_EFFORTS = frozenset({"low", "medium", "high", "very-high"})
VALID_ROADMAP_STATUSES = frozenset({"planned", "in_progress", "completed"})

_ROADMAP_TRANSITIONS = {
    "planned": "in_progress",
    "in_progress": "completed",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class SecurityPostureMaturityEngine:
    """SQLite WAL-backed CMMI-style Security Posture Maturity engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/security_posture_maturity.db
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
                CREATE TABLE IF NOT EXISTS maturity_assessments (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    domain          TEXT NOT NULL DEFAULT '',
                    capability      TEXT NOT NULL DEFAULT '',
                    maturity_level  INTEGER NOT NULL DEFAULT 1,
                    max_level       INTEGER NOT NULL DEFAULT 5,
                    evidence        TEXT NOT NULL DEFAULT '',
                    assessor        TEXT NOT NULL DEFAULT '',
                    assessed_at     TEXT NOT NULL,
                    next_review     TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ma_org_domain
                    ON maturity_assessments (org_id, domain);

                CREATE TABLE IF NOT EXISTS maturity_roadmap (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    domain          TEXT NOT NULL DEFAULT '',
                    capability      TEXT NOT NULL DEFAULT '',
                    current_level   INTEGER NOT NULL DEFAULT 1,
                    target_level    INTEGER NOT NULL DEFAULT 3,
                    priority        TEXT NOT NULL DEFAULT 'medium',
                    effort          TEXT NOT NULL DEFAULT 'medium',
                    timeline        TEXT NOT NULL DEFAULT '',
                    owner           TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'planned',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_mr_org_status
                    ON maturity_roadmap (org_id, status);

                CREATE TABLE IF NOT EXISTS maturity_snapshots (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    overall_level   REAL NOT NULL DEFAULT 0.0,
                    domain_scores   TEXT NOT NULL DEFAULT '{}',
                    snapshot_date   TEXT NOT NULL,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ms_org_date
                    ON maturity_snapshots (org_id, snapshot_date);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    def record_assessment(
        self,
        org_id: str,
        domain: str,
        capability: str,
        maturity_level: int,
        max_level: int = 5,
        evidence: str = "",
        assessor: str = "",
        next_review: str = "",
    ) -> Dict[str, Any]:
        """Record a new capability maturity assessment. Clamps maturity_level to 1..max_level."""
        if domain not in VALID_DOMAINS:
            raise ValueError(f"domain must be one of {sorted(VALID_DOMAINS)}")
        if not capability:
            raise ValueError("capability is required")
        max_level = max(1, int(max_level))
        maturity_level = max(1, min(int(maturity_level), max_level))

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "domain": domain,
            "capability": capability,
            "maturity_level": maturity_level,
            "max_level": max_level,
            "evidence": evidence,
            "assessor": assessor,
            "assessed_at": now,
            "next_review": next_review,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO maturity_assessments
                       (id, org_id, domain, capability, maturity_level, max_level,
                        evidence, assessor, assessed_at, next_review, created_at)
                       VALUES (:id, :org_id, :domain, :capability, :maturity_level,
                               :max_level, :evidence, :assessor, :assessed_at,
                               :next_review, :created_at)""",
                    record,
                )
        _logger.info("assessment recorded id=%s org=%s domain=%s level=%d",
                     record["id"], org_id, domain, maturity_level)
        return record

    def update_level(
        self,
        assessment_id: str,
        org_id: str,
        maturity_level: int,
        evidence: str = "",
    ) -> Dict[str, Any]:
        """Update maturity_level and evidence for an existing assessment."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM maturity_assessments WHERE id=? AND org_id=?",
                    (assessment_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"assessment {assessment_id!r} not found")
                max_level = row["max_level"]
                maturity_level = max(1, min(int(maturity_level), max_level))
                conn.execute(
                    """UPDATE maturity_assessments
                       SET maturity_level=?, evidence=?, assessed_at=?
                       WHERE id=? AND org_id=?""",
                    (maturity_level, evidence, now, assessment_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM maturity_assessments WHERE id=?",
                    (assessment_id,),
                ).fetchone()
        return self._row(updated)

    def get_overdue_reviews(self, org_id: str) -> List[Dict[str, Any]]:
        """Return assessments where next_review is set and earlier than now."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """SELECT * FROM maturity_assessments
                       WHERE org_id=? AND next_review != '' AND next_review < ?
                       ORDER BY next_review""",
                    (org_id, now),
                ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Roadmap
    # ------------------------------------------------------------------

    def create_roadmap_item(
        self,
        org_id: str,
        domain: str,
        capability: str,
        current_level: int,
        target_level: int,
        priority: str = "medium",
        effort: str = "medium",
        timeline: str = "",
        owner: str = "",
    ) -> Dict[str, Any]:
        """Create a roadmap item with status=planned."""
        if domain not in VALID_DOMAINS:
            raise ValueError(f"domain must be one of {sorted(VALID_DOMAINS)}")
        if priority not in VALID_PRIORITIES:
            raise ValueError(f"priority must be one of {sorted(VALID_PRIORITIES)}")
        if effort not in VALID_EFFORTS:
            raise ValueError(f"effort must be one of {sorted(VALID_EFFORTS)}")

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "domain": domain,
            "capability": capability,
            "current_level": int(current_level),
            "target_level": int(target_level),
            "priority": priority,
            "effort": effort,
            "timeline": timeline,
            "owner": owner,
            "status": "planned",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO maturity_roadmap
                       (id, org_id, domain, capability, current_level, target_level,
                        priority, effort, timeline, owner, status, created_at)
                       VALUES (:id, :org_id, :domain, :capability, :current_level,
                               :target_level, :priority, :effort, :timeline,
                               :owner, :status, :created_at)""",
                    record,
                )
        return record

    def advance_roadmap_item(self, item_id: str, org_id: str) -> Dict[str, Any]:
        """Advance roadmap status: planned→in_progress→completed."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM maturity_roadmap WHERE id=? AND org_id=?",
                    (item_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"roadmap item {item_id!r} not found")
                current_status = row["status"]
                next_status = _ROADMAP_TRANSITIONS.get(current_status)
                if next_status is None:
                    raise ValueError(f"Cannot advance from status '{current_status}'")
                conn.execute(
                    "UPDATE maturity_roadmap SET status=? WHERE id=? AND org_id=?",
                    (next_status, item_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM maturity_roadmap WHERE id=?", (item_id,)
                ).fetchone()
        return self._row(updated)

    def get_roadmap(self, org_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return roadmap items, optionally filtered by status."""
        with self._lock:
            with self._conn() as conn:
                if status:
                    rows = conn.execute(
                        "SELECT * FROM maturity_roadmap WHERE org_id=? AND status=? ORDER BY created_at",
                        (org_id, status),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM maturity_roadmap WHERE org_id=? ORDER BY created_at",
                        (org_id,),
                    ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Snapshots
    # ------------------------------------------------------------------

    def take_snapshot(self, org_id: str) -> Dict[str, Any]:
        """Compute and persist a maturity snapshot.

        overall_level = avg(maturity_level) across all org assessments.
        domain_scores = {domain: avg_level} grouped by domain.
        """
        with self._lock:
            with self._conn() as conn:
                # Overall average
                overall_row = conn.execute(
                    "SELECT AVG(maturity_level) AS avg_level FROM maturity_assessments WHERE org_id=?",
                    (org_id,),
                ).fetchone()
                overall_level = overall_row["avg_level"] or 0.0

                # Per-domain averages
                domain_rows = conn.execute(
                    """SELECT domain, AVG(maturity_level) AS avg_level
                       FROM maturity_assessments
                       WHERE org_id=?
                       GROUP BY domain""",
                    (org_id,),
                ).fetchall()
                domain_scores = {r["domain"]: round(r["avg_level"], 3) for r in domain_rows}

                now = _now_iso()
                record: Dict[str, Any] = {
                    "id": str(uuid.uuid4()),
                    "org_id": org_id,
                    "overall_level": round(overall_level, 3),
                    "domain_scores": json.dumps(domain_scores),
                    "snapshot_date": _today(),
                    "created_at": now,
                }
                conn.execute(
                    """INSERT INTO maturity_snapshots
                       (id, org_id, overall_level, domain_scores, snapshot_date, created_at)
                       VALUES (:id, :org_id, :overall_level, :domain_scores, :snapshot_date, :created_at)""",
                    record,
                )

        result = dict(record)
        result["domain_scores"] = domain_scores
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("RISK_ASSESSED", {"entity_type": "security_posture_maturity", "org_id": org_id, "source_engine": "security_posture_maturity"})
            except Exception:
                pass

        return result

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_maturity_overview(self, org_id: str) -> Dict[str, Any]:
        """Latest snapshot + all assessments + all roadmap items."""
        with self._lock:
            with self._conn() as conn:
                snap = conn.execute(
                    "SELECT * FROM maturity_snapshots WHERE org_id=? ORDER BY snapshot_date DESC, created_at DESC LIMIT 1",
                    (org_id,),
                ).fetchone()
                assessments = conn.execute(
                    "SELECT * FROM maturity_assessments WHERE org_id=? ORDER BY domain, capability",
                    (org_id,),
                ).fetchall()
                roadmap = conn.execute(
                    "SELECT * FROM maturity_roadmap WHERE org_id=? ORDER BY priority, created_at",
                    (org_id,),
                ).fetchall()

        snap_dict = None
        if snap:
            snap_dict = self._row(snap)
            try:
                snap_dict["domain_scores"] = json.loads(snap_dict.get("domain_scores", "{}"))
            except (ValueError, TypeError):
                snap_dict["domain_scores"] = {}

        return {
            "latest_snapshot": snap_dict,
            "assessments": [self._row(r) for r in assessments],
            "roadmap": [self._row(r) for r in roadmap],
        }

    def get_domain_breakdown(self, org_id: str) -> List[Dict[str, Any]]:
        """Per domain: avg_level, capability_count, assessments list."""
        with self._lock:
            with self._conn() as conn:
                domain_rows = conn.execute(
                    """SELECT domain,
                              AVG(maturity_level) AS avg_level,
                              COUNT(*) AS capability_count
                       FROM maturity_assessments
                       WHERE org_id=?
                       GROUP BY domain
                       ORDER BY domain""",
                    (org_id,),
                ).fetchall()

                result = []
                for dr in domain_rows:
                    domain = dr["domain"]
                    assessments = conn.execute(
                        "SELECT * FROM maturity_assessments WHERE org_id=? AND domain=? ORDER BY capability",
                        (org_id, domain),
                    ).fetchall()
                    result.append({
                        "domain": domain,
                        "avg_level": round(dr["avg_level"], 3),
                        "capability_count": dr["capability_count"],
                        "assessments": [self._row(a) for a in assessments],
                    })
        return result
