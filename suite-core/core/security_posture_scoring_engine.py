"""Security Posture Scoring Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Control registration, weighted posture score calculation, snapshot history, and gap analysis.
Compliance: NIST CSF, ISO/IEC 27001, CIS Controls v8
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_posture_scoring.db"
)

_VALID_DOMAINS = {
    "identity", "network", "endpoint", "cloud", "application", "data", "governance"
}
_VALID_CONTROL_STATUSES = {
    "implemented", "partial", "not_implemented", "compensating"
}

# Score multipliers per status
_STATUS_WEIGHT: Dict[str, float] = {
    "implemented": 1.0,
    "partial": 0.5,
    "compensating": 0.75,
    "not_implemented": 0.0,
}


def _score_level(score: float) -> str:
    if score >= 80:
        return "excellent"
    if score >= 60:
        return "good"
    if score >= 40:
        return "fair"
    return "poor"


class SecurityPostureScoringEngine:
    """SQLite WAL-backed Security Posture Scoring engine.

    Thread-safe via RLock.  Multi-tenant via org_id.
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
                CREATE TABLE IF NOT EXISTS sps_controls (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    name           TEXT NOT NULL DEFAULT '',
                    domain         TEXT NOT NULL DEFAULT 'governance',
                    description    TEXT NOT NULL DEFAULT '',
                    weight         REAL NOT NULL DEFAULT 1.0,
                    control_status TEXT NOT NULL DEFAULT 'not_implemented',
                    evidence_url   TEXT NOT NULL DEFAULT '',
                    last_assessed  DATETIME,
                    created_at     DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_sps_controls_org
                    ON sps_controls (org_id, domain, control_status);

                CREATE TABLE IF NOT EXISTS sps_snapshots (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    domain        TEXT NOT NULL DEFAULT 'all',
                    score         REAL NOT NULL DEFAULT 0.0,
                    score_level   TEXT NOT NULL DEFAULT 'poor',
                    control_count INTEGER NOT NULL DEFAULT 0,
                    snapshot_at   DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_sps_snapshots_org
                    ON sps_snapshots (org_id, domain, snapshot_at);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Controls
    # ------------------------------------------------------------------

    def register_control(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new security control.

        Required: name
        Optional: domain, description, weight, control_status, evidence_url, last_assessed
        """
        name = data.get("name", "")
        if not name:
            raise ValueError("name is required")

        domain = data.get("domain", "governance")
        if domain not in _VALID_DOMAINS:
            raise ValueError(f"domain must be one of {_VALID_DOMAINS}")

        control_status = data.get("control_status", "not_implemented")
        if control_status not in _VALID_CONTROL_STATUSES:
            raise ValueError(f"control_status must be one of {_VALID_CONTROL_STATUSES}")

        control_id = str(uuid.uuid4())
        now = self._now()
        row = {
            "id": control_id,
            "org_id": org_id,
            "name": name,
            "domain": domain,
            "description": data.get("description", ""),
            "weight": float(data.get("weight", 1.0)),
            "control_status": control_status,
            "evidence_url": data.get("evidence_url", ""),
            "last_assessed": data.get("last_assessed"),
            "created_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO sps_controls
                    (id, org_id, name, domain, description, weight,
                     control_status, evidence_url, last_assessed, created_at)
                VALUES
                    (:id, :org_id, :name, :domain, :description, :weight,
                     :control_status, :evidence_url, :last_assessed, :created_at)
                """,
                row,
            )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("RISK_ASSESSED", {"entity_type": "security_posture_scoring", "org_id": org_id, "source_engine": "security_posture_scoring"})
            except Exception:
                pass

        return dict(row)

    def list_controls(
        self,
        org_id: str,
        domain: Optional[str] = None,
        control_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List controls with optional domain/status filters."""
        query = "SELECT * FROM sps_controls WHERE org_id = ?"
        params: list = [org_id]
        if domain is not None:
            query += " AND domain = ?"
            params.append(domain)
        if control_status is not None:
            query += " AND control_status = ?"
            params.append(control_status)
        query += " ORDER BY created_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_control(self, org_id: str, control_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single control by ID with org isolation."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM sps_controls WHERE id = ? AND org_id = ?",
                (control_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    def update_control_status(
        self,
        org_id: str,
        control_id: str,
        control_status: str,
        evidence_url: str = "",
    ) -> Dict[str, Any]:
        """Update a control's status (and optionally evidence_url).

        Raises ValueError on invalid status.
        Raises KeyError if control not found for org.
        """
        if control_status not in _VALID_CONTROL_STATUSES:
            raise ValueError(f"control_status must be one of {_VALID_CONTROL_STATUSES}")

        now = self._now()
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                UPDATE sps_controls
                SET control_status = ?, evidence_url = ?, last_assessed = ?
                WHERE id = ? AND org_id = ?
                """,
                (control_status, evidence_url, now, control_id, org_id),
            )
            row = conn.execute(
                "SELECT * FROM sps_controls WHERE id = ? AND org_id = ?",
                (control_id, org_id),
            ).fetchone()

        if not row:
            raise KeyError(f"Control {control_id} not found for org {org_id}")
        return self._row(row)

    # ------------------------------------------------------------------
    # TrustGraph context
    # ------------------------------------------------------------------

    def get_trustgraph_context(self, org_id: str, entity_id: str) -> Dict[str, Any]:
        """Query TrustGraph for cross-domain context to enrich posture scoring.

        Returns related assets, findings, and incidents for a given entity.
        Degrades gracefully when TrustGraph is unavailable.
        """
        context: Dict[str, Any] = {
            "related_assets": [],
            "related_findings": [],
            "related_incidents": [],
            "trustgraph_available": False,
        }
        try:
            from trustgraph.knowledge_store import KnowledgeStore
            store = KnowledgeStore()
            context["trustgraph_available"] = True

            for core_id in (1, 2, 3):
                try:
                    results = store.search(core_id=core_id, query_text=entity_id, limit=10)
                    for entity in results:
                        if entity.org_id not in ("default", org_id):
                            continue
                        entry = {"id": entity.entity_id, "name": entity.name, "type": entity.entity_type}
                        etype = entity.entity_type.lower()
                        if etype in ("asset", "service", "host"):
                            context["related_assets"].append(entry)
                        elif etype in ("finding", "vulnerability", "cve"):
                            context["related_findings"].append(entry)
                        elif etype in ("incident", "breach", "alert"):
                            context["related_incidents"].append(entry)
                except Exception:
                    pass

            neighbors = store.get_neighbors(entity_id=entity_id, depth=1)
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
                elif etype in ("incident", "breach", "alert"):
                    if entry not in context["related_incidents"]:
                        context["related_incidents"].append(entry)
        except Exception:
            pass
        return context

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def calculate_posture_score(
        self, org_id: str, domain: Optional[str] = None
    ) -> Dict[str, Any]:
        """Compute weighted posture score and persist a snapshot.

        Returns: {org_id, domain, score, score_level, control_count, snapshot_at}
        """
        domain_label = domain if domain else "all"

        with self._lock, self._conn() as conn:
            query = "SELECT control_status, weight FROM sps_controls WHERE org_id = ?"
            params: list = [org_id]
            if domain:
                query += " AND domain = ?"
                params.append(domain)
            rows = conn.execute(query, params).fetchall()

            total_weighted_actual = 0.0
            total_weight = 0.0
            for r in rows:
                w = r["weight"]
                multiplier = _STATUS_WEIGHT.get(r["control_status"], 0.0)
                total_weighted_actual += multiplier * w
                total_weight += w

            if total_weight > 0:
                score = round((total_weighted_actual / total_weight) * 100, 2)
            else:
                score = 0.0

            level = _score_level(score)
            control_count = len(rows)
            now = self._now()

            snap_id = str(uuid.uuid4())
            conn.execute(
                """
                INSERT INTO sps_snapshots
                    (id, org_id, domain, score, score_level, control_count, snapshot_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (snap_id, org_id, domain_label, score, level, control_count, now),
            )

        return {
            "org_id": org_id,
            "domain": domain_label,
            "score": score,
            "score_level": level,
            "control_count": control_count,
            "snapshot_at": now,
        }

    def get_posture_history(
        self,
        org_id: str,
        domain: Optional[str] = None,
        limit: int = 30,
    ) -> List[Dict[str, Any]]:
        """Retrieve posture snapshots ordered by snapshot_at DESC."""
        query = "SELECT * FROM sps_snapshots WHERE org_id = ?"
        params: list = [org_id]
        if domain is not None:
            query += " AND domain = ?"
            params.append(domain)
        query += " ORDER BY snapshot_at DESC LIMIT ?"
        params.append(limit)
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_posture_stats(self, org_id: str) -> Dict[str, Any]:
        """Return overall score, per-domain scores, and control gap counts."""
        with self._lock, self._conn() as conn:
            all_rows = conn.execute(
                "SELECT domain, control_status, weight FROM sps_controls WHERE org_id = ?",
                (org_id,),
            ).fetchall()

            total_controls = len(all_rows)
            implemented_count = sum(1 for r in all_rows if r["control_status"] == "implemented")
            gaps_count = sum(1 for r in all_rows if r["control_status"] == "not_implemented")

            # Overall weighted score (all domains)
            tw_actual = 0.0
            tw_total = 0.0
            for r in all_rows:
                w = r["weight"]
                multiplier = _STATUS_WEIGHT.get(r["control_status"], 0.0)
                tw_actual += multiplier * w
                tw_total += w
            overall_score = round((tw_actual / tw_total) * 100, 2) if tw_total > 0 else 0.0

            # Per-domain scores
            domain_data: Dict[str, Dict[str, float]] = {}
            for r in all_rows:
                d = r["domain"]
                if d not in domain_data:
                    domain_data[d] = {"actual": 0.0, "total": 0.0}
                w = r["weight"]
                domain_data[d]["actual"] += _STATUS_WEIGHT.get(r["control_status"], 0.0) * w
                domain_data[d]["total"] += w

            by_domain = {
                d: round((v["actual"] / v["total"]) * 100, 2) if v["total"] > 0 else 0.0
                for d, v in domain_data.items()
            }

        return {
            "org_id": org_id,
            "overall_score": overall_score,
            "by_domain": by_domain,
            "total_controls": total_controls,
            "implemented_count": implemented_count,
            "gaps_count": gaps_count,
        }
