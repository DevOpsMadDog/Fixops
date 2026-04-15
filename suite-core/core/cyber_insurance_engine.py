"""Cyber Insurance Engine — ALDECI.

Tracks insurance policies, coverage assessments, claims, and risk questionnaires
to support cyber insurance procurement, renewal, and claims management.

Compliance: NIST CSF RC.RP, ISO/IEC 27001 A.16, SOC 2 CC9.2
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

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "cyber_insurance.db"
)

_VALID_COVERAGE_TYPES = {"first_party", "third_party", "both"}
_VALID_POLICY_STATUSES = {"active", "expired", "pending"}
_VALID_CLAIM_STATUSES = {"filed", "under_review", "approved", "denied", "settled"}
_VALID_INCIDENT_TYPES = {
    "ransomware", "data_breach", "business_interruption",
    "social_engineering", "network_failure",
}


class CyberInsuranceEngine:
    """SQLite WAL-backed Cyber Insurance tracking engine.

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
                CREATE TABLE IF NOT EXISTS insurance_policies (
                    policy_id        TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    carrier          TEXT NOT NULL DEFAULT '',
                    policy_number    TEXT NOT NULL DEFAULT '',
                    coverage_type    TEXT NOT NULL DEFAULT 'both',
                    coverage_limit   REAL NOT NULL DEFAULT 0,
                    deductible       REAL NOT NULL DEFAULT 0,
                    premium_annual   REAL NOT NULL DEFAULT 0,
                    effective_date   TEXT NOT NULL DEFAULT '',
                    expiry_date      TEXT NOT NULL DEFAULT '',
                    status           TEXT NOT NULL DEFAULT 'active',
                    covered_events   TEXT NOT NULL DEFAULT '[]',
                    created_at       TEXT NOT NULL,
                    updated_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ins_pol_org
                    ON insurance_policies (org_id, status);

                CREATE TABLE IF NOT EXISTS coverage_assessments (
                    assessment_id              TEXT PRIMARY KEY,
                    org_id                     TEXT NOT NULL,
                    policy_id                  TEXT NOT NULL,
                    overall_score              INTEGER NOT NULL DEFAULT 0,
                    mfa_score                  INTEGER NOT NULL DEFAULT 0,
                    backup_score               INTEGER NOT NULL DEFAULT 0,
                    incident_response_score    INTEGER NOT NULL DEFAULT 0,
                    patch_score                INTEGER NOT NULL DEFAULT 0,
                    training_score             INTEGER NOT NULL DEFAULT 0,
                    recommendations            TEXT NOT NULL DEFAULT '[]',
                    assessed_at                TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_assess_org
                    ON coverage_assessments (org_id, policy_id);

                CREATE TABLE IF NOT EXISTS claims (
                    claim_id          TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    policy_id         TEXT NOT NULL,
                    incident_type     TEXT NOT NULL DEFAULT '',
                    incident_date     TEXT NOT NULL DEFAULT '',
                    estimated_loss    REAL NOT NULL DEFAULT 0,
                    status            TEXT NOT NULL DEFAULT 'filed',
                    adjuster          TEXT NOT NULL DEFAULT '',
                    settlement_amount REAL,
                    filed_at          TEXT NOT NULL,
                    updated_at        TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_claims_org
                    ON claims (org_id, status);

                CREATE TABLE IF NOT EXISTS risk_questionnaires (
                    questionnaire_id TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    policy_id        TEXT NOT NULL,
                    responses        TEXT NOT NULL DEFAULT '{}',
                    score            INTEGER NOT NULL DEFAULT 0,
                    completed_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_quest_org
                    ON risk_questionnaires (org_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def add_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a cyber insurance policy. Returns the full policy record."""
        policy_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        coverage_type = data.get("coverage_type", "both")
        if coverage_type not in _VALID_COVERAGE_TYPES:
            coverage_type = "both"

        status = data.get("status", "active")
        if status not in _VALID_POLICY_STATUSES:
            status = "active"

        covered_events = data.get("covered_events", [])
        if not isinstance(covered_events, list):
            covered_events = []

        coverage_limit = float(data.get("coverage_limit", 0))
        deductible = float(data.get("deductible", 0))
        premium_annual = float(data.get("premium_annual", 0))

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO insurance_policies
                        (policy_id, org_id, carrier, policy_number, coverage_type,
                         coverage_limit, deductible, premium_annual, effective_date,
                         expiry_date, status, covered_events, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        policy_id, org_id,
                        data.get("carrier", ""),
                        data.get("policy_number", ""),
                        coverage_type,
                        coverage_limit, deductible, premium_annual,
                        data.get("effective_date", ""),
                        data.get("expiry_date", ""),
                        status,
                        json.dumps(covered_events),
                        now, now,
                    ),
                )

        return {
            "policy_id": policy_id,
            "org_id": org_id,
            "carrier": data.get("carrier", ""),
            "policy_number": data.get("policy_number", ""),
            "coverage_type": coverage_type,
            "coverage_limit": coverage_limit,
            "deductible": deductible,
            "premium_annual": premium_annual,
            "effective_date": data.get("effective_date", ""),
            "expiry_date": data.get("expiry_date", ""),
            "status": status,
            "covered_events": covered_events,
            "created_at": now,
            "updated_at": now,
        }

    def _policy_row_dict(self, row: Any) -> Dict[str, Any]:
        d = dict(row)
        d["covered_events"] = json.loads(d.get("covered_events") or "[]")
        d["coverage_limit"] = float(d.get("coverage_limit", 0))
        d["deductible"] = float(d.get("deductible", 0))
        d["premium_annual"] = float(d.get("premium_annual", 0))
        return d

    def list_policies(self, org_id: str) -> List[Dict[str, Any]]:
        """List all insurance policies for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM insurance_policies WHERE org_id=? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [self._policy_row_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    def create_assessment(
        self,
        org_id: str,
        policy_id: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Create a coverage assessment for a policy. Returns the full assessment record."""
        assessment_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        mfa_score = max(0, min(100, int(data.get("mfa_score", 0))))
        backup_score = max(0, min(100, int(data.get("backup_score", 0))))
        ir_score = max(0, min(100, int(data.get("incident_response_score", 0))))
        patch_score = max(0, min(100, int(data.get("patch_score", 0))))
        training_score = max(0, min(100, int(data.get("training_score", 0))))

        # Overall score is average of sub-scores
        overall_score = int(
            data.get(
                "overall_score",
                round((mfa_score + backup_score + ir_score + patch_score + training_score) / 5),
            )
        )
        overall_score = max(0, min(100, overall_score))

        recommendations = data.get("recommendations", [])
        if not isinstance(recommendations, list):
            recommendations = []

        assessed_at = data.get("assessed_at", now)

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO coverage_assessments
                        (assessment_id, org_id, policy_id, overall_score, mfa_score,
                         backup_score, incident_response_score, patch_score,
                         training_score, recommendations, assessed_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        assessment_id, org_id, policy_id,
                        overall_score, mfa_score, backup_score,
                        ir_score, patch_score, training_score,
                        json.dumps(recommendations), assessed_at,
                    ),
                )

        return {
            "assessment_id": assessment_id,
            "org_id": org_id,
            "policy_id": policy_id,
            "overall_score": overall_score,
            "mfa_score": mfa_score,
            "backup_score": backup_score,
            "incident_response_score": ir_score,
            "patch_score": patch_score,
            "training_score": training_score,
            "recommendations": recommendations,
            "assessed_at": assessed_at,
        }

    def _assessment_row_dict(self, row: Any) -> Dict[str, Any]:
        d = dict(row)
        d["recommendations"] = json.loads(d.get("recommendations") or "[]")
        return d

    def list_assessments(self, org_id: str) -> List[Dict[str, Any]]:
        """List all coverage assessments for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM coverage_assessments WHERE org_id=? ORDER BY assessed_at DESC",
                (org_id,),
            ).fetchall()
        return [self._assessment_row_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Claims
    # ------------------------------------------------------------------

    def file_claim(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """File a new insurance claim. Returns the full claim record."""
        claim_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        incident_type = data.get("incident_type", "")
        estimated_loss = float(data.get("estimated_loss", 0))
        incident_date = data.get("incident_date", now)

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO claims
                        (claim_id, org_id, policy_id, incident_type, incident_date,
                         estimated_loss, status, adjuster, settlement_amount, filed_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        claim_id, org_id,
                        data.get("policy_id", ""),
                        incident_type, incident_date,
                        estimated_loss,
                        "filed",
                        data.get("adjuster", ""),
                        None,
                        now, now,
                    ),
                )

        return {
            "claim_id": claim_id,
            "org_id": org_id,
            "policy_id": data.get("policy_id", ""),
            "incident_type": incident_type,
            "incident_date": incident_date,
            "estimated_loss": estimated_loss,
            "status": "filed",
            "adjuster": data.get("adjuster", ""),
            "settlement_amount": None,
            "filed_at": now,
            "updated_at": now,
        }

    def _claim_row_dict(self, row: Any) -> Dict[str, Any]:
        d = dict(row)
        d["estimated_loss"] = float(d.get("estimated_loss", 0))
        if d.get("settlement_amount") is not None:
            d["settlement_amount"] = float(d["settlement_amount"])
        return d

    def list_claims(
        self,
        org_id: str,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List insurance claims for an org."""
        query = "SELECT * FROM claims WHERE org_id=?"
        params: list = [org_id]
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY filed_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._claim_row_dict(r) for r in rows]

    def update_claim(
        self,
        org_id: str,
        claim_id: str,
        status: str,
        settlement_amount: Optional[float] = None,
    ) -> bool:
        """Update claim status and optionally set settlement amount. Returns True if updated."""
        if status not in _VALID_CLAIM_STATUSES:
            return False

        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """
                    UPDATE claims SET status=?, settlement_amount=?, updated_at=?
                    WHERE claim_id=? AND org_id=?
                    """,
                    (status, settlement_amount, now, claim_id, org_id),
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_insurance_stats(self, org_id: str) -> Dict[str, Any]:
        """Return summary statistics for cyber insurance portfolio."""
        with self._conn() as conn:
            active_policies = conn.execute(
                "SELECT COUNT(*) FROM insurance_policies WHERE org_id=? AND status='active'",
                (org_id,),
            ).fetchone()[0]

            total_coverage_row = conn.execute(
                "SELECT SUM(coverage_limit) FROM insurance_policies WHERE org_id=? AND status='active'",
                (org_id,),
            ).fetchone()
            total_coverage = float(total_coverage_row[0] or 0)

            avg_premium_row = conn.execute(
                "SELECT AVG(premium_annual) FROM insurance_policies WHERE org_id=? AND status='active'",
                (org_id,),
            ).fetchone()
            avg_premium = round(float(avg_premium_row[0] or 0), 2)

            open_claims = conn.execute(
                "SELECT COUNT(*) FROM claims WHERE org_id=? AND status IN ('filed','under_review')",
                (org_id,),
            ).fetchone()[0]

            total_settled_row = conn.execute(
                "SELECT SUM(settlement_amount) FROM claims WHERE org_id=? AND status='settled'",
                (org_id,),
            ).fetchone()
            total_settled = float(total_settled_row[0] or 0)

            # Coverage gap: total estimated losses on open claims vs total coverage
            open_loss_row = conn.execute(
                "SELECT SUM(estimated_loss) FROM claims WHERE org_id=? AND status IN ('filed','under_review','approved')",
                (org_id,),
            ).fetchone()
            open_loss = float(open_loss_row[0] or 0)
            gap = max(0.0, open_loss - total_coverage)

        return {
            "total_coverage": total_coverage,
            "active_policies": active_policies,
            "open_claims": open_claims,
            "total_settled": total_settled,
            "avg_premium": avg_premium,
            "coverage_gap_analysis": {
                "open_claims_estimated_loss": open_loss,
                "total_active_coverage": total_coverage,
                "gap": gap,
                "adequately_covered": gap == 0,
            },
        }
