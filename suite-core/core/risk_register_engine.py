"""Risk Register Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Manages organizational risk records with full lifecycle tracking:
  - Risk creation with auto-computed risk_score and risk_level
  - Filtering by category, level, and status
  - Treatment plans per risk
  - Aggregated stats with top risk identification

Compliance: ISO 31000, NIST RMF, SOC2 CC3.2
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "risk_register_engine.db"
)

_VALID_RISK_CATEGORIES = {
    "strategic", "operational", "compliance", "technical",
    "financial", "reputational", "third_party",
}
_VALID_LIKELIHOODS = {"certain", "likely", "possible", "unlikely", "rare"}
_VALID_IMPACTS = {"catastrophic", "major", "moderate", "minor", "negligible"}
_VALID_STATUSES = {"identified", "assessed", "treated", "accepted", "closed"}
_VALID_TREATMENT_TYPES = {"mitigate", "transfer", "accept", "avoid"}

_LIKELIHOOD_VALUES: Dict[str, int] = {
    "certain": 5, "likely": 4, "possible": 3, "unlikely": 2, "rare": 1,
}
_IMPACT_VALUES: Dict[str, int] = {
    "catastrophic": 5, "major": 4, "moderate": 3, "minor": 2, "negligible": 1,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _compute_risk_level(score: int) -> str:
    if score >= 20:
        return "critical"
    if score >= 12:
        return "high"
    if score >= 6:
        return "medium"
    return "low"


class RiskRegisterEngine:
    """SQLite WAL-backed Risk Register engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/risk_register_engine.db
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
                CREATE TABLE IF NOT EXISTS rr_risks (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    name           TEXT NOT NULL DEFAULT '',
                    risk_category  TEXT NOT NULL DEFAULT 'operational',
                    description    TEXT NOT NULL DEFAULT '',
                    likelihood     TEXT NOT NULL DEFAULT 'possible',
                    impact         TEXT NOT NULL DEFAULT 'moderate',
                    risk_score     INTEGER NOT NULL DEFAULT 0,
                    risk_level     TEXT NOT NULL DEFAULT 'low',
                    owner          TEXT NOT NULL DEFAULT '',
                    status         TEXT NOT NULL DEFAULT 'identified',
                    treatment_plan TEXT NOT NULL DEFAULT '',
                    created_at     DATETIME,
                    updated_at     DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_rr_risks_org
                    ON rr_risks (org_id, risk_category, risk_level, status);

                CREATE TABLE IF NOT EXISTS rr_treatments (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    risk_id        TEXT NOT NULL,
                    treatment_type TEXT NOT NULL DEFAULT 'mitigate',
                    description    TEXT NOT NULL DEFAULT '',
                    cost_estimate  REAL NOT NULL DEFAULT 0.0,
                    timeline_days  INTEGER NOT NULL DEFAULT 0,
                    owner          TEXT NOT NULL DEFAULT '',
                    status         TEXT NOT NULL DEFAULT 'planned',
                    created_at     DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_rr_treatments_org
                    ON rr_treatments (org_id, risk_id);
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
    # Risks
    # ------------------------------------------------------------------

    def create_risk(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new risk record with auto-computed score and level."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        risk_category = data.get("risk_category", "operational")
        if risk_category not in _VALID_RISK_CATEGORIES:
            raise ValueError(
                f"Invalid risk_category '{risk_category}'. "
                f"Must be one of {sorted(_VALID_RISK_CATEGORIES)}"
            )

        likelihood = data.get("likelihood", "possible")
        if likelihood not in _VALID_LIKELIHOODS:
            raise ValueError(
                f"Invalid likelihood '{likelihood}'. "
                f"Must be one of {sorted(_VALID_LIKELIHOODS)}"
            )

        impact = data.get("impact", "moderate")
        if impact not in _VALID_IMPACTS:
            raise ValueError(
                f"Invalid impact '{impact}'. "
                f"Must be one of {sorted(_VALID_IMPACTS)}"
            )

        risk_score = _LIKELIHOOD_VALUES[likelihood] * _IMPACT_VALUES[impact]
        risk_level = _compute_risk_level(risk_score)
        now = _now_iso()

        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "risk_category": risk_category,
            "description": data.get("description", ""),
            "likelihood": likelihood,
            "impact": impact,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "owner": data.get("owner", ""),
            "status": "identified",
            "treatment_plan": "",
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO rr_risks
                       (id, org_id, name, risk_category, description, likelihood,
                        impact, risk_score, risk_level, owner, status,
                        treatment_plan, created_at, updated_at)
                       VALUES (:id, :org_id, :name, :risk_category, :description,
                               :likelihood, :impact, :risk_score, :risk_level,
                               :owner, :status, :treatment_plan, :created_at, :updated_at)""",
                    record,
                )
        if _get_tg_bus is not None:
            try:
                _get_tg_bus().emit("RISK_ASSESSED", {
                    "org_id": org_id,
                    "entity": "risk_register",
                    "risk_id": record["id"],
                    "name": name,
                    "risk_category": risk_category,
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                })
            except Exception:
                pass
        return record

    def list_risks(
        self,
        org_id: str,
        risk_category: Optional[str] = None,
        risk_level: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List risks with optional filters."""
        sql = "SELECT * FROM rr_risks WHERE org_id = ?"
        params: List[Any] = [org_id]
        if risk_category:
            sql += " AND risk_category = ?"
            params.append(risk_category)
        if risk_level:
            sql += " AND risk_level = ?"
            params.append(risk_level)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY risk_score DESC, created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_risk(self, org_id: str, risk_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single risk by ID within the org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM rr_risks WHERE org_id = ? AND id = ?",
                (org_id, risk_id),
            ).fetchone()
        return self._row(row) if row else None

    def update_risk_status(
        self,
        org_id: str,
        risk_id: str,
        status: str,
        treatment_plan: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Update status (and optionally treatment_plan) for a risk."""
        if status not in _VALID_STATUSES:
            raise ValueError(
                f"Invalid status '{status}'. "
                f"Must be one of {sorted(_VALID_STATUSES)}"
            )
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """UPDATE rr_risks
                       SET status = ?, treatment_plan = ?, updated_at = ?
                       WHERE org_id = ? AND id = ?""",
                    (status, treatment_plan, now, org_id, risk_id),
                )
        return self.get_risk(org_id, risk_id)

    # ------------------------------------------------------------------
    # Treatments
    # ------------------------------------------------------------------

    def add_risk_treatment(
        self,
        org_id: str,
        risk_id: str,
        treatment_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Add a treatment record for a risk."""
        treatment_type = treatment_data.get("treatment_type", "mitigate")
        if treatment_type not in _VALID_TREATMENT_TYPES:
            raise ValueError(
                f"Invalid treatment_type '{treatment_type}'. "
                f"Must be one of {sorted(_VALID_TREATMENT_TYPES)}"
            )

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "risk_id": risk_id,
            "treatment_type": treatment_type,
            "description": treatment_data.get("description", ""),
            "cost_estimate": float(treatment_data.get("cost_estimate", 0.0)),
            "timeline_days": int(treatment_data.get("timeline_days", 0)),
            "owner": treatment_data.get("owner", ""),
            "status": "planned",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO rr_treatments
                       (id, org_id, risk_id, treatment_type, description,
                        cost_estimate, timeline_days, owner, status, created_at)
                       VALUES (:id, :org_id, :risk_id, :treatment_type, :description,
                               :cost_estimate, :timeline_days, :owner, :status, :created_at)""",
                    record,
                )
        return record

    def list_treatments(
        self,
        org_id: str,
        risk_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List treatments, optionally filtered by risk_id."""
        sql = "SELECT * FROM rr_treatments WHERE org_id = ?"
        params: List[Any] = [org_id]
        if risk_id:
            sql += " AND risk_id = ?"
            params.append(risk_id)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_risk_context(self, org_id: str, risk_id: str) -> Dict[str, Any]:
        """Query TrustGraph for cross-domain context about a risk.

        Returns related findings, affected assets, and historical risk trends.
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

            risk = self.get_risk(org_id, risk_id)
            search_term = risk.get("name", risk_id) if risk else risk_id

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
                        elif etype in ("incident", "breach"):
                            context["related_incidents"].append(entry)
                except Exception:
                    pass

            neighbors = store.get_neighbors(entity_id=risk_id, depth=1)
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
                elif etype in ("incident", "breach"):
                    if entry not in context["related_incidents"]:
                        context["related_incidents"].append(entry)
        except Exception:
            pass
        return context

    def get_risk_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated risk statistics for an org."""
        with self._conn() as conn:
            total_risks = conn.execute(
                "SELECT COUNT(*) FROM rr_risks WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            critical_risks = conn.execute(
                "SELECT COUNT(*) FROM rr_risks WHERE org_id = ? AND risk_level = 'critical'",
                (org_id,),
            ).fetchone()[0]

            high_risks = conn.execute(
                "SELECT COUNT(*) FROM rr_risks WHERE org_id = ? AND risk_level = 'high'",
                (org_id,),
            ).fetchone()[0]

            open_risks = conn.execute(
                "SELECT COUNT(*) FROM rr_risks WHERE org_id = ? "
                "AND status NOT IN ('closed', 'accepted')",
                (org_id,),
            ).fetchone()[0]

            cat_rows = conn.execute(
                "SELECT risk_category, COUNT(*) as cnt FROM rr_risks "
                "WHERE org_id = ? GROUP BY risk_category",
                (org_id,),
            ).fetchall()
            by_category = {r["risk_category"]: r["cnt"] for r in cat_rows}

            avg_row = conn.execute(
                "SELECT AVG(risk_score) as avg_score FROM rr_risks WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            avg_risk_score = (
                round(avg_row["avg_score"], 2)
                if avg_row and avg_row["avg_score"] is not None
                else None
            )

            top_row = conn.execute(
                "SELECT name, risk_score FROM rr_risks WHERE org_id = ? "
                "ORDER BY risk_score DESC LIMIT 1",
                (org_id,),
            ).fetchone()
            top_risk = (
                {"name": top_row["name"], "score": top_row["risk_score"]}
                if top_row
                else None
            )

        return {
            "total_risks": total_risks,
            "critical_risks": critical_risks,
            "high_risks": high_risks,
            "open_risks": open_risks,
            "by_category": by_category,
            "avg_risk_score": avg_risk_score,
            "top_risk": top_risk,
        }
