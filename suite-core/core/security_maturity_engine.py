"""Security Maturity Engine — ALDECI.

CMMI-based security maturity assessment supporting NIST CSF, ISO 27001,
CIS Controls, and custom frameworks.

Capabilities:
  - Multi-framework assessment creation (NIST CSF, CIS Controls, ISO 27001, CMMI, custom)
  - Domain-level scoring with automatic maturity level computation
  - Control tracking with implementation status
  - Target setting and gap analysis
  - Roadmap generation ordered by gap size

Compliance: CMMI, NIST CSF, ISO 27001, CIS Controls v8
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

_DATA_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_FRAMEWORKS = {"cmmi", "nist_csf", "iso27001", "cis_controls", "custom"}
_VALID_STATUSES = {"draft", "in_progress", "completed"}
_VALID_IMPL_STATUSES = {"not_implemented", "partial", "implemented", "optimized"}
_VALID_EFFORTS = {"low", "medium", "high", "very_high"}

# Framework-specific domains auto-created on assessment creation
_FRAMEWORK_DOMAINS: Dict[str, List[Dict[str, str]]] = {
    "nist_csf": [
        {"domain_name": "identify", "domain_code": "ID"},
        {"domain_name": "protect", "domain_code": "PR"},
        {"domain_name": "detect", "domain_code": "DE"},
        {"domain_name": "respond", "domain_code": "RS"},
        {"domain_name": "recover", "domain_code": "RC"},
    ],
    "cis_controls": [
        {"domain_name": "ig1", "domain_code": "IG1"},
        {"domain_name": "ig2", "domain_code": "IG2"},
        {"domain_name": "ig3", "domain_code": "IG3"},
    ],
    "iso27001": [
        {"domain_name": "information_security_policies", "domain_code": "A.5"},
        {"domain_name": "organization_of_information_security", "domain_code": "A.6"},
        {"domain_name": "human_resource_security", "domain_code": "A.7"},
        {"domain_name": "asset_management", "domain_code": "A.8"},
        {"domain_name": "access_control", "domain_code": "A.9"},
        {"domain_name": "cryptography", "domain_code": "A.10"},
        {"domain_name": "physical_environmental_security", "domain_code": "A.11"},
        {"domain_name": "operations_security", "domain_code": "A.12"},
        {"domain_name": "communications_security", "domain_code": "A.13"},
        {"domain_name": "system_acquisition_development", "domain_code": "A.14"},
        {"domain_name": "supplier_relationships", "domain_code": "A.15"},
        {"domain_name": "information_security_incident_management", "domain_code": "A.16"},
        {"domain_name": "business_continuity_management", "domain_code": "A.17"},
        {"domain_name": "compliance", "domain_code": "A.18"},
    ],
    "cmmi": [
        {"domain_name": "process_management", "domain_code": "PM"},
        {"domain_name": "project_management", "domain_code": "PJM"},
        {"domain_name": "engineering", "domain_code": "ENG"},
        {"domain_name": "support", "domain_code": "SUP"},
    ],
    "custom": [],
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SecurityMaturityEngine:
    """SQLite WAL-backed Security Maturity engine.

    Thread-safe via RLock. Multi-tenant via org_id — each org gets its own DB.
    """

    _instances: Dict[str, "SecurityMaturityEngine"] = {}
    _instances_lock = threading.Lock()

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    @classmethod
    def for_org(cls, org_id: str) -> "SecurityMaturityEngine":
        with cls._instances_lock:
            if org_id not in cls._instances:
                db_path = str(_DATA_DIR / f"{org_id}_security_maturity.db")
                cls._instances[org_id] = cls(db_path)
            return cls._instances[org_id]

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
                    name            TEXT NOT NULL,
                    framework       TEXT NOT NULL DEFAULT 'nist_csf',
                    status          TEXT NOT NULL DEFAULT 'draft',
                    overall_score   REAL NOT NULL DEFAULT 0.0,
                    overall_level   INTEGER NOT NULL DEFAULT 1,
                    assessor_id     TEXT NOT NULL DEFAULT '',
                    start_date      TEXT NOT NULL DEFAULT '',
                    completed_date  TEXT,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ma_org_status
                    ON maturity_assessments (org_id, status);

                CREATE TABLE IF NOT EXISTS maturity_domains (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    assessment_id   TEXT NOT NULL,
                    domain_name     TEXT NOT NULL,
                    domain_code     TEXT NOT NULL DEFAULT '',
                    score           REAL NOT NULL DEFAULT 0.0,
                    level           INTEGER NOT NULL DEFAULT 1,
                    evidence        TEXT NOT NULL DEFAULT '',
                    gaps            TEXT NOT NULL DEFAULT '',
                    recommendations TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_md_org_assessment
                    ON maturity_domains (org_id, assessment_id);

                CREATE TABLE IF NOT EXISTS maturity_controls (
                    id                    TEXT PRIMARY KEY,
                    org_id                TEXT NOT NULL,
                    domain_id             TEXT NOT NULL,
                    control_id            TEXT NOT NULL DEFAULT '',
                    control_name          TEXT NOT NULL,
                    implementation_status TEXT NOT NULL DEFAULT 'not_implemented',
                    evidence              TEXT NOT NULL DEFAULT '',
                    score                 REAL NOT NULL DEFAULT 0.0,
                    weight                REAL NOT NULL DEFAULT 1.0,
                    created_at            TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_mc_org_domain
                    ON maturity_controls (org_id, domain_id);

                CREATE TABLE IF NOT EXISTS maturity_targets (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    domain_name     TEXT NOT NULL,
                    current_level   INTEGER NOT NULL DEFAULT 1,
                    target_level    INTEGER NOT NULL DEFAULT 3,
                    target_date     TEXT NOT NULL DEFAULT '',
                    effort_estimate TEXT NOT NULL DEFAULT 'medium',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_mt_org
                    ON maturity_targets (org_id);
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
    # Level computation
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_level(score: float) -> int:
        """Map 0-100 score to maturity level 1-5."""
        if score < 20:
            return 1
        if score < 40:
            return 2
        if score < 60:
            return 3
        if score < 80:
            return 4
        return 5

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    def create_assessment(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new maturity assessment with framework-appropriate domains."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")
        framework = data.get("framework", "nist_csf")
        if framework not in _VALID_FRAMEWORKS:
            raise ValueError(f"Invalid framework: {framework}. Must be one of {_VALID_FRAMEWORKS}")

        now = _now_iso()
        assessment = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "framework": framework,
            "status": "draft",
            "overall_score": 0.0,
            "overall_level": 1,
            "assessor_id": data.get("assessor_id", ""),
            "start_date": data.get("start_date", now[:10]),
            "completed_date": None,
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO maturity_assessments
                       (id, org_id, name, framework, status, overall_score, overall_level,
                        assessor_id, start_date, completed_date, created_at)
                       VALUES (:id, :org_id, :name, :framework, :status, :overall_score,
                               :overall_level, :assessor_id, :start_date, :completed_date, :created_at)""",
                    assessment,
                )

            # Auto-create framework-appropriate domains
            domain_templates = _FRAMEWORK_DOMAINS.get(framework, [])
            for tmpl in domain_templates:
                domain = {
                    "id": str(uuid.uuid4()),
                    "org_id": org_id,
                    "assessment_id": assessment["id"],
                    "domain_name": tmpl["domain_name"],
                    "domain_code": tmpl["domain_code"],
                    "score": 0.0,
                    "level": 1,
                    "evidence": "",
                    "gaps": "",
                    "recommendations": "",
                    "created_at": now,
                }
                with self._conn() as conn:
                    conn.execute(
                        """INSERT INTO maturity_domains
                           (id, org_id, assessment_id, domain_name, domain_code,
                            score, level, evidence, gaps, recommendations, created_at)
                           VALUES (:id, :org_id, :assessment_id, :domain_name, :domain_code,
                                   :score, :level, :evidence, :gaps, :recommendations, :created_at)""",
                        domain,
                    )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "security_maturity", "org_id": org_id, "source_engine": "security_maturity"})
            except Exception:
                pass

        return assessment

    def list_assessments(
        self, org_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM maturity_assessments WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_assessment(self, org_id: str, assessment_id: str) -> Optional[Dict[str, Any]]:
        """Return assessment with its domains."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM maturity_assessments WHERE org_id = ? AND id = ?",
                (org_id, assessment_id),
            ).fetchone()
            if not row:
                return None
            result = self._row(row)
            domains = [
                self._row(r)
                for r in conn.execute(
                    "SELECT * FROM maturity_domains WHERE org_id = ? AND assessment_id = ? ORDER BY domain_name",
                    (org_id, assessment_id),
                ).fetchall()
            ]
        result["domains"] = domains
        return result

    def add_domain_score(
        self, org_id: str, domain_id: str, data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Score a domain. Computes level from score."""
        score = float(data.get("score", 0.0))
        score = max(0.0, min(100.0, score))
        level = self._compute_level(score)
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """UPDATE maturity_domains
                       SET score = ?, level = ?, evidence = ?, gaps = ?, recommendations = ?
                       WHERE org_id = ? AND id = ?""",
                    (
                        score,
                        level,
                        data.get("evidence", ""),
                        data.get("gaps", ""),
                        data.get("recommendations", ""),
                        org_id,
                        domain_id,
                    ),
                )
                if cur.rowcount == 0:
                    return None
                row = conn.execute(
                    "SELECT * FROM maturity_domains WHERE org_id = ? AND id = ?",
                    (org_id, domain_id),
                ).fetchone()
        return self._row(row) if row else None

    def add_control(
        self, org_id: str, domain_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a control with implementation status to a domain."""
        control_name = (data.get("control_name") or "").strip()
        if not control_name:
            raise ValueError("control_name is required.")
        impl_status = data.get("implementation_status", "not_implemented")
        if impl_status not in _VALID_IMPL_STATUSES:
            raise ValueError(f"Invalid implementation_status: {impl_status}")

        # Derive score from implementation status
        status_scores = {
            "not_implemented": 0.0,
            "partial": 33.0,
            "implemented": 75.0,
            "optimized": 100.0,
        }
        score = float(data.get("score", status_scores[impl_status]))

        now = _now_iso()
        control = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "domain_id": domain_id,
            "control_id": data.get("control_id", ""),
            "control_name": control_name,
            "implementation_status": impl_status,
            "evidence": data.get("evidence", ""),
            "score": score,
            "weight": float(data.get("weight", 1.0)),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO maturity_controls
                       (id, org_id, domain_id, control_id, control_name,
                        implementation_status, evidence, score, weight, created_at)
                       VALUES (:id, :org_id, :domain_id, :control_id, :control_name,
                               :implementation_status, :evidence, :score, :weight, :created_at)""",
                    control,
                )
        return control

    def list_controls(self, org_id: str, domain_id: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            return [
                self._row(r)
                for r in conn.execute(
                    "SELECT * FROM maturity_controls WHERE org_id = ? AND domain_id = ? ORDER BY created_at",
                    (org_id, domain_id),
                ).fetchall()
            ]

    def complete_assessment(
        self, org_id: str, assessment_id: str
    ) -> Optional[Dict[str, Any]]:
        """Compute overall_score as average of domain scores, set status=completed."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT score FROM maturity_domains WHERE org_id = ? AND assessment_id = ?",
                    (org_id, assessment_id),
                ).fetchall()
                if not rows:
                    overall_score = 0.0
                else:
                    overall_score = sum(r["score"] for r in rows) / len(rows)
                overall_level = self._compute_level(overall_score)
                now = _now_iso()
                cur = conn.execute(
                    """UPDATE maturity_assessments
                       SET status = 'completed', overall_score = ?, overall_level = ?, completed_date = ?
                       WHERE org_id = ? AND id = ?""",
                    (overall_score, overall_level, now, org_id, assessment_id),
                )
                if cur.rowcount == 0:
                    return None
                row = conn.execute(
                    "SELECT * FROM maturity_assessments WHERE org_id = ? AND id = ?",
                    (org_id, assessment_id),
                ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Targets
    # ------------------------------------------------------------------

    def set_target(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Set a maturity target for a domain."""
        domain_name = (data.get("domain_name") or "").strip()
        if not domain_name:
            raise ValueError("domain_name is required.")
        effort = data.get("effort_estimate", "medium")
        if effort not in _VALID_EFFORTS:
            raise ValueError(f"Invalid effort_estimate: {effort}")

        now = _now_iso()
        target = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "domain_name": domain_name,
            "current_level": int(data.get("current_level", 1)),
            "target_level": int(data.get("target_level", 3)),
            "target_date": data.get("target_date", ""),
            "effort_estimate": effort,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO maturity_targets
                       (id, org_id, domain_name, current_level, target_level,
                        target_date, effort_estimate, created_at)
                       VALUES (:id, :org_id, :domain_name, :current_level, :target_level,
                               :target_date, :effort_estimate, :created_at)""",
                    target,
                )
        return target

    def list_targets(self, org_id: str) -> List[Dict[str, Any]]:
        """List all targets with gap analysis."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM maturity_targets WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        results = []
        for row in rows:
            t = self._row(row)
            t["gap"] = t["target_level"] - t["current_level"]
            results.append(t)
        return results

    # ------------------------------------------------------------------
    # Stats & Roadmap
    # ------------------------------------------------------------------

    def get_maturity_stats(self, org_id: str) -> Dict[str, Any]:
        with self._conn() as conn:
            completed = conn.execute(
                "SELECT COUNT(*) FROM maturity_assessments WHERE org_id = ? AND status = 'completed'",
                (org_id,),
            ).fetchone()[0]

            avg_row = conn.execute(
                "SELECT AVG(overall_score) FROM maturity_assessments WHERE org_id = ? AND status = 'completed'",
                (org_id,),
            ).fetchone()
            avg_score = avg_row[0] if avg_row[0] is not None else 0.0

            by_fw_rows = conn.execute(
                "SELECT framework, COUNT(*) as cnt FROM maturity_assessments WHERE org_id = ? GROUP BY framework",
                (org_id,),
            ).fetchall()
            by_framework = {r["framework"]: r["cnt"] for r in by_fw_rows}

            target_rows = conn.execute(
                "SELECT * FROM maturity_targets WHERE org_id = ?",
                (org_id,),
            ).fetchall()

        domains_at_target = 0
        domains_below_target = 0
        highest_gap = 0
        highest_gap_domain = ""
        for t in target_rows:
            gap = t["target_level"] - t["current_level"]
            if gap <= 0:
                domains_at_target += 1
            else:
                domains_below_target += 1
                if gap > highest_gap:
                    highest_gap = gap
                    highest_gap_domain = t["domain_name"]

        return {
            "assessments_completed": completed,
            "avg_maturity_score": round(avg_score, 2),
            "by_framework": by_framework,
            "domains_at_target": domains_at_target,
            "domains_below_target": domains_below_target,
            "highest_gap_domain": highest_gap_domain,
        }

    def get_roadmap(self, org_id: str) -> List[Dict[str, Any]]:
        """Return domains ordered by gap size (largest gap first) with effort estimates."""
        targets = self.list_targets(org_id)
        # Sort by gap descending
        targets_with_gap = [t for t in targets if t.get("gap", 0) > 0]
        targets_with_gap.sort(key=lambda t: t.get("gap", 0), reverse=True)
        return targets_with_gap
