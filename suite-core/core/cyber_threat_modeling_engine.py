"""Cyber Threat Modeling Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Attack tree-based threat modeling with FAIR risk scoring and threat actor profiles.

Tables:
  threat_models  — Threat model metadata and aggregate risk score
  attack_trees   — Attack tree nodes with likelihood/impact risk matrix
  threat_actors  — Threat actor profiles per model
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "cyber_threat_modeling.db"
)

_VALID_MODEL_TYPES = {
    "application", "infrastructure", "cloud", "iot", "supply_chain", "data_flow",
}
_VALID_LIKELIHOODS = {"critical", "high", "medium", "low"}
_VALID_IMPACTS = {"critical", "high", "medium", "low"}
_VALID_ACTOR_TYPES = {
    "nation_state", "criminal", "insider", "hacktivist", "competitor", "researcher",
}
_VALID_CAPABILITIES = {"sophisticated", "moderate", "basic"}

# Risk matrix: (likelihood, impact) -> risk_level
_RISK_MATRIX: Dict[tuple, str] = {
    ("critical", "critical"): "critical",
    ("critical", "high"): "critical",
    ("critical", "medium"): "high",
    ("critical", "low"): "high",
    ("high", "critical"): "critical",
    ("high", "high"): "high",
    ("high", "medium"): "high",
    ("high", "low"): "medium",
    ("medium", "critical"): "high",
    ("medium", "high"): "high",
    ("medium", "medium"): "medium",
    ("medium", "low"): "low",
    ("low", "critical"): "high",
    ("low", "high"): "medium",
    ("low", "medium"): "low",
    ("low", "low"): "low",
}

_RISK_NUMERIC: Dict[str, float] = {
    "critical": 4.0,
    "high": 3.0,
    "medium": 2.0,
    "low": 1.0,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _risk_level_from_matrix(likelihood: str, impact: str) -> str:
    return _RISK_MATRIX.get((likelihood, impact), "medium")


class CyberThreatModelingEngine:
    """SQLite WAL-backed Cyber Threat Modeling engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/cyber_threat_modeling.db
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
                CREATE TABLE IF NOT EXISTS threat_models (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    model_name       TEXT NOT NULL DEFAULT '',
                    system_name      TEXT NOT NULL DEFAULT '',
                    model_type       TEXT NOT NULL DEFAULT 'application',
                    scope            TEXT NOT NULL DEFAULT '',
                    threat_count     INTEGER NOT NULL DEFAULT 0,
                    mitigated_count  INTEGER NOT NULL DEFAULT 0,
                    risk_score       REAL NOT NULL DEFAULT 0.0,
                    status           TEXT NOT NULL DEFAULT 'draft',
                    created_by       TEXT NOT NULL DEFAULT '',
                    reviewed_by      TEXT NOT NULL DEFAULT '',
                    created_at       TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_ctm_models_org
                    ON threat_models (org_id, status, model_type);

                CREATE TABLE IF NOT EXISTS attack_trees (
                    id             TEXT PRIMARY KEY,
                    model_id       TEXT NOT NULL,
                    org_id         TEXT NOT NULL,
                    root_goal      TEXT NOT NULL DEFAULT '',
                    attack_vector  TEXT NOT NULL DEFAULT '',
                    likelihood     TEXT NOT NULL DEFAULT 'medium',
                    impact         TEXT NOT NULL DEFAULT 'medium',
                    risk_level     TEXT NOT NULL DEFAULT 'medium',
                    path_steps     TEXT NOT NULL DEFAULT '[]',
                    mitigation     TEXT NOT NULL DEFAULT '',
                    mitigated      INTEGER NOT NULL DEFAULT 0,
                    created_at     TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_ctm_trees_model
                    ON attack_trees (model_id, org_id, mitigated);

                CREATE TABLE IF NOT EXISTS threat_actors (
                    id             TEXT PRIMARY KEY,
                    model_id       TEXT NOT NULL,
                    org_id         TEXT NOT NULL,
                    actor_name     TEXT NOT NULL DEFAULT '',
                    actor_type     TEXT NOT NULL DEFAULT 'criminal',
                    motivation     TEXT NOT NULL DEFAULT '',
                    capability     TEXT NOT NULL DEFAULT 'moderate',
                    target_assets  TEXT NOT NULL DEFAULT '[]',
                    tactics        TEXT NOT NULL DEFAULT '[]',
                    created_at     TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_ctm_actors_model
                    ON threat_actors (model_id, org_id);

                CREATE TABLE IF NOT EXISTS design_doc_links (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    doc_ingest_id  TEXT NOT NULL,
                    model_id       TEXT NOT NULL,
                    linked_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ctm_doc_links_org
                    ON design_doc_links (org_id, model_id);
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
    # Internal helpers
    # ------------------------------------------------------------------

    def _recompute_model_risk(self, conn: sqlite3.Connection, model_id: str, org_id: str) -> None:
        """Recompute risk_score as avg numeric score of unmitigated trees."""
        rows = conn.execute(
            "SELECT risk_level FROM attack_trees WHERE model_id = ? AND org_id = ? AND mitigated = 0",
            (model_id, org_id),
        ).fetchall()
        if not rows:
            risk_score = 0.0
        else:
            total = sum(_RISK_NUMERIC.get(r["risk_level"], 2.0) for r in rows)
            risk_score = total / len(rows)

        conn.execute(
            "UPDATE threat_models SET risk_score = ? WHERE id = ? AND org_id = ?",
            (risk_score, model_id, org_id),
        )

    # ------------------------------------------------------------------
    # Threat Models
    # ------------------------------------------------------------------

    def create_model(
        self,
        org_id: str,
        model_name: str,
        system_name: str,
        model_type: str,
        scope: str,
        created_by: str,
    ) -> Dict[str, Any]:
        """Create a new threat model."""
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "model_name": model_name,
            "system_name": system_name,
            "model_type": model_type,
            "scope": scope,
            "threat_count": 0,
            "mitigated_count": 0,
            "risk_score": 0.0,
            "status": "draft",
            "created_by": created_by,
            "reviewed_by": "",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO threat_models
                       (id, org_id, model_name, system_name, model_type, scope,
                        threat_count, mitigated_count, risk_score, status,
                        created_by, reviewed_by, created_at)
                       VALUES (:id, :org_id, :model_name, :system_name, :model_type, :scope,
                               :threat_count, :mitigated_count, :risk_score, :status,
                               :created_by, :reviewed_by, :created_at)""",
                    record,
                )
        return record

    # ------------------------------------------------------------------
    # Attack Trees
    # ------------------------------------------------------------------

    def add_attack_tree(
        self,
        model_id: str,
        org_id: str,
        root_goal: str,
        attack_vector: str,
        likelihood: str,
        impact: str,
        path_steps: List[str],
    ) -> Dict[str, Any]:
        """Add an attack tree node to a model; increment threat_count; recompute risk_score."""
        risk_level = _risk_level_from_matrix(likelihood, impact)
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "model_id": model_id,
            "org_id": org_id,
            "root_goal": root_goal,
            "attack_vector": attack_vector,
            "likelihood": likelihood,
            "impact": impact,
            "risk_level": risk_level,
            "path_steps": json.dumps(path_steps if isinstance(path_steps, list) else list(path_steps)),
            "mitigation": "",
            "mitigated": 0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO attack_trees
                       (id, model_id, org_id, root_goal, attack_vector, likelihood,
                        impact, risk_level, path_steps, mitigation, mitigated, created_at)
                       VALUES (:id, :model_id, :org_id, :root_goal, :attack_vector, :likelihood,
                               :impact, :risk_level, :path_steps, :mitigation, :mitigated, :created_at)""",
                    record,
                )
                conn.execute(
                    "UPDATE threat_models SET threat_count = threat_count + 1 WHERE id = ? AND org_id = ?",
                    (model_id, org_id),
                )
                self._recompute_model_risk(conn, model_id, org_id)

        record["path_steps"] = path_steps
        return record

    def mitigate_tree(
        self,
        tree_id: str,
        model_id: str,
        org_id: str,
        mitigation: str,
    ) -> Optional[Dict[str, Any]]:
        """Mark an attack tree as mitigated (idempotent). Recompute model risk_score."""
        with self._lock:
            with self._conn() as conn:
                tree_row = conn.execute(
                    "SELECT * FROM attack_trees WHERE id = ? AND model_id = ? AND org_id = ?",
                    (tree_id, model_id, org_id),
                ).fetchone()
                if not tree_row:
                    return None

                already_mitigated = bool(tree_row["mitigated"])

                conn.execute(
                    "UPDATE attack_trees SET mitigated = 1, mitigation = ? WHERE id = ? AND model_id = ? AND org_id = ?",
                    (mitigation, tree_id, model_id, org_id),
                )

                # Only increment mitigated_count if not already mitigated
                if not already_mitigated:
                    conn.execute(
                        "UPDATE threat_models SET mitigated_count = mitigated_count + 1 WHERE id = ? AND org_id = ?",
                        (model_id, org_id),
                    )

                self._recompute_model_risk(conn, model_id, org_id)

                updated = conn.execute(
                    "SELECT * FROM attack_trees WHERE id = ?", (tree_id,)
                ).fetchone()

        if not updated:
            return None
        result = self._row(updated)
        try:
            result["path_steps"] = json.loads(result["path_steps"])
        except (TypeError, ValueError):
            result["path_steps"] = []
        return result

    # ------------------------------------------------------------------
    # Threat Actors
    # ------------------------------------------------------------------

    def add_threat_actor(
        self,
        model_id: str,
        org_id: str,
        actor_name: str,
        actor_type: str,
        motivation: str,
        capability: str,
        target_assets: List[str],
        tactics: List[str],
    ) -> Dict[str, Any]:
        """Add a threat actor profile to a model."""
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "model_id": model_id,
            "org_id": org_id,
            "actor_name": actor_name,
            "actor_type": actor_type,
            "motivation": motivation,
            "capability": capability,
            "target_assets": json.dumps(target_assets if isinstance(target_assets, list) else list(target_assets)),
            "tactics": json.dumps(tactics if isinstance(tactics, list) else list(tactics)),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO threat_actors
                       (id, model_id, org_id, actor_name, actor_type, motivation,
                        capability, target_assets, tactics, created_at)
                       VALUES (:id, :model_id, :org_id, :actor_name, :actor_type, :motivation,
                               :capability, :target_assets, :tactics, :created_at)""",
                    record,
                )
        record["target_assets"] = target_assets
        record["tactics"] = tactics
        return record

    # ------------------------------------------------------------------
    # Model lifecycle
    # ------------------------------------------------------------------

    def finalize_model(
        self,
        model_id: str,
        org_id: str,
        reviewed_by: str,
    ) -> Optional[Dict[str, Any]]:
        """Finalize a threat model (status=finalized, reviewed_by stored)."""
        with self._lock:
            with self._conn() as conn:
                updated = conn.execute(
                    "UPDATE threat_models SET status = 'finalized', reviewed_by = ? WHERE id = ? AND org_id = ?",
                    (reviewed_by, model_id, org_id),
                ).rowcount
                if updated == 0:
                    return None
                row = conn.execute(
                    "SELECT * FROM threat_models WHERE id = ? AND org_id = ?",
                    (model_id, org_id),
                ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_model_detail(self, model_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Return model with its attack trees and threat actors."""
        with self._conn() as conn:
            model_row = conn.execute(
                "SELECT * FROM threat_models WHERE id = ? AND org_id = ?",
                (model_id, org_id),
            ).fetchone()
            if not model_row:
                return None
            model = self._row(model_row)

            tree_rows = conn.execute(
                "SELECT * FROM attack_trees WHERE model_id = ? AND org_id = ? ORDER BY risk_level, created_at",
                (model_id, org_id),
            ).fetchall()
            trees = []
            for t in tree_rows:
                td = self._row(t)
                try:
                    td["path_steps"] = json.loads(td["path_steps"])
                except (TypeError, ValueError):
                    td["path_steps"] = []
                trees.append(td)
            model["attack_trees"] = trees

            actor_rows = conn.execute(
                "SELECT * FROM threat_actors WHERE model_id = ? AND org_id = ?",
                (model_id, org_id),
            ).fetchall()
            actors = []
            for a in actor_rows:
                ad = self._row(a)
                try:
                    ad["target_assets"] = json.loads(ad["target_assets"])
                except (TypeError, ValueError):
                    ad["target_assets"] = []
                try:
                    ad["tactics"] = json.loads(ad["tactics"])
                except (TypeError, ValueError):
                    ad["tactics"] = []
                actors.append(ad)
            model["threat_actors"] = actors

        return model

    def get_unmitigated_threats(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all unmitigated attack trees with their model_name via JOIN."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT at.*, tm.model_name
                   FROM attack_trees at
                   JOIN threat_models tm ON at.model_id = tm.id
                   WHERE at.org_id = ? AND at.mitigated = 0
                   ORDER BY at.risk_level, at.created_at""",
                (org_id,),
            ).fetchall()
        results = []
        for r in rows:
            d = self._row(r)
            try:
                d["path_steps"] = json.loads(d["path_steps"])
            except (TypeError, ValueError):
                d["path_steps"] = []
            results.append(d)
        return results

    # ------------------------------------------------------------------
    # GAP-056: Design-doc traceability link
    # ------------------------------------------------------------------

    def link_design_doc_to_model(
        self,
        org_id: str,
        doc_ingest_id: str,
        model_id: str,
    ) -> Dict[str, Any]:
        """Link a design-doc ingest to an existing cyber threat model.

        Idempotent: repeated calls with the same (org_id, doc_ingest_id, model_id)
        return the existing link unchanged.  Validates that the target model
        exists and belongs to the org before writing.
        """
        if not org_id:
            raise ValueError("org_id is required")
        if not doc_ingest_id:
            raise ValueError("doc_ingest_id is required")
        if not model_id:
            raise ValueError("model_id is required")

        with self._lock:
            with self._conn() as conn:
                model_row = conn.execute(
                    "SELECT id FROM threat_models WHERE id = ? AND org_id = ?",
                    (model_id, org_id),
                ).fetchone()
                if not model_row:
                    raise ValueError(
                        f"Model '{model_id}' not found for org '{org_id}'"
                    )

                existing = conn.execute(
                    "SELECT * FROM design_doc_links "
                    "WHERE org_id = ? AND doc_ingest_id = ? AND model_id = ?",
                    (org_id, doc_ingest_id, model_id),
                ).fetchone()
                if existing:
                    return self._row(existing)

                link_id = str(uuid.uuid4())
                now = _now_iso()
                conn.execute(
                    """INSERT INTO design_doc_links
                       (id, org_id, doc_ingest_id, model_id, linked_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (link_id, org_id, doc_ingest_id, model_id, now),
                )
                conn.commit()
        return {
            "id": link_id,
            "org_id": org_id,
            "doc_ingest_id": doc_ingest_id,
            "model_id": model_id,
            "linked_at": now,
        }

    def list_doc_links(
        self, org_id: str, model_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Return design-doc links for traceability queries."""
        if not org_id:
            raise ValueError("org_id is required")
        with self._conn() as conn:
            if model_id:
                rows = conn.execute(
                    "SELECT * FROM design_doc_links "
                    "WHERE org_id = ? AND model_id = ? ORDER BY linked_at DESC",
                    (org_id, model_id),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM design_doc_links "
                    "WHERE org_id = ? ORDER BY linked_at DESC",
                    (org_id,),
                ).fetchall()
        return [self._row(r) for r in rows]

    def get_model_summary(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate summary across all models for the org."""
        with self._conn() as conn:
            model_rows = conn.execute(
                "SELECT * FROM threat_models WHERE org_id = ?",
                (org_id,),
            ).fetchall()
            total_models = len(model_rows)
            by_type: Dict[str, int] = {}
            critical_models = 0
            total_risk = 0.0
            for m in model_rows:
                mt = m["model_type"]
                by_type[mt] = by_type.get(mt, 0) + 1
                rs = float(m["risk_score"])
                total_risk += rs
                if rs >= 3.5:
                    critical_models += 1

            avg_risk_score = total_risk / total_models if total_models else 0.0

            total_threats = conn.execute(
                "SELECT COUNT(*) FROM attack_trees WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]
            unmitigated_count = conn.execute(
                "SELECT COUNT(*) FROM attack_trees WHERE org_id = ? AND mitigated = 0",
                (org_id,),
            ).fetchone()[0]

        return {
            "total_models": total_models,
            "by_type": by_type,
            "total_threats": total_threats,
            "unmitigated_count": unmitigated_count,
            "avg_risk_score": round(avg_risk_score, 4),
            "critical_models": critical_models,
        }
