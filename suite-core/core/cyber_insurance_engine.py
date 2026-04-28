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

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


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
        self._v2_initialized: bool = False
        self._v2_lock = threading.Lock()
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

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "cyber_insurance", "org_id": org_id, "source_engine": "cyber_insurance"})
            except Exception:
                pass

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

    # ------------------------------------------------------------------
    # Extended schema (v2) — policies_v2, claims_v2, coverage_gaps, risk_assessments
    # Added to the same DB; existing tables above are preserved for backward compat.
    # ------------------------------------------------------------------

    def _ensure_v2_schema(self) -> None:
        """Lazily create v2 tables if they don't exist yet."""
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS policies_v2 (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    policy_name          TEXT NOT NULL,
                    insurer              TEXT NOT NULL DEFAULT '',
                    policy_number        TEXT NOT NULL DEFAULT '',
                    policy_type          TEXT NOT NULL DEFAULT 'combined',
                    coverage_limit_usd   REAL NOT NULL DEFAULT 0.0,
                    deductible_usd       REAL NOT NULL DEFAULT 0.0,
                    premium_annual_usd   REAL NOT NULL DEFAULT 0.0,
                    coverage_types       TEXT NOT NULL DEFAULT '[]',
                    effective_date       TEXT NOT NULL DEFAULT '',
                    expiry_date          TEXT NOT NULL DEFAULT '',
                    status               TEXT NOT NULL DEFAULT 'pending',
                    risk_score           REAL NOT NULL DEFAULT 0.0,
                    tier                 TEXT NOT NULL DEFAULT 'bronze',
                    created_at           TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pol2_org_status
                    ON policies_v2 (org_id, status);

                CREATE TABLE IF NOT EXISTS claims_v2 (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    policy_id            TEXT NOT NULL,
                    incident_type        TEXT NOT NULL DEFAULT 'data_breach',
                    incident_date        TEXT NOT NULL DEFAULT '',
                    claim_date           TEXT NOT NULL DEFAULT '',
                    claim_amount_usd     REAL NOT NULL DEFAULT 0.0,
                    settled_amount_usd   REAL NOT NULL DEFAULT 0.0,
                    status               TEXT NOT NULL DEFAULT 'submitted',
                    adjuster_name        TEXT NOT NULL DEFAULT '',
                    incident_description TEXT NOT NULL DEFAULT '',
                    related_incident_id  TEXT NOT NULL DEFAULT '',
                    settled_date         TEXT,
                    created_at           TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_claim2_org_policy
                    ON claims_v2 (org_id, policy_id, status);

                CREATE TABLE IF NOT EXISTS coverage_gaps (
                    id                     TEXT PRIMARY KEY,
                    org_id                 TEXT NOT NULL,
                    gap_type               TEXT NOT NULL DEFAULT 'exclusion',
                    severity               TEXT NOT NULL DEFAULT 'medium',
                    description            TEXT NOT NULL DEFAULT '',
                    estimated_exposure_usd REAL NOT NULL DEFAULT 0.0,
                    recommendation         TEXT NOT NULL DEFAULT '',
                    created_at             TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_gap_org_severity
                    ON coverage_gaps (org_id, severity);

                CREATE TABLE IF NOT EXISTS risk_assessments (
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    policy_id               TEXT NOT NULL DEFAULT '',
                    assessment_type         TEXT NOT NULL DEFAULT 'quarterly',
                    overall_risk_score      REAL NOT NULL DEFAULT 0.0,
                    security_posture_score  REAL NOT NULL DEFAULT 0.0,
                    incident_history_score  REAL NOT NULL DEFAULT 0.0,
                    control_effectiveness   REAL NOT NULL DEFAULT 0.0,
                    recommendations         TEXT NOT NULL DEFAULT '[]',
                    created_at              TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ra_org_policy
                    ON risk_assessments (org_id, policy_id, created_at DESC);
                """
            )


    def _get_v2(self) -> None:
        if not self._v2_initialized:
            with self._v2_lock:
                if not self._v2_initialized:
                    self._ensure_v2_schema()
                    self._v2_initialized = True

    # --------------- Tier helper ---------------

    @staticmethod
    def _compute_tier(coverage_limit: float) -> str:
        if coverage_limit < 1_000_000:
            return "bronze"
        if coverage_limit < 5_000_000:
            return "silver"
        if coverage_limit < 20_000_000:
            return "gold"
        return "platinum"

    @staticmethod
    def _days_until(date_str: str) -> Optional[int]:
        if not date_str:
            return None
        try:
            expiry = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            # make naive datetimes timezone-aware for comparison
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            return (expiry - now).days
        except Exception:
            return None

    @staticmethod
    def _deserialize_row(d: Dict[str, Any]) -> Dict[str, Any]:
        for field in ("coverage_types", "recommendations"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except Exception:
                    pass
        return d

    # --------------- policies_v2 ---------------

    def add_policy_v2(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a v2 policy with tier assignment and all required fields."""
        self._get_v2()
        policy_name = (data.get("policy_name") or "").strip()
        if not policy_name:
            raise ValueError("policy_name is required.")

        _valid_types = {"first_party", "third_party", "combined"}
        policy_type = data.get("policy_type", "combined")
        if policy_type not in _valid_types:
            raise ValueError(f"Invalid policy_type: {policy_type}")

        coverage_limit = float(data.get("coverage_limit_usd", 0.0))
        tier = self._compute_tier(coverage_limit)
        now = datetime.now(timezone.utc).isoformat()

        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "policy_name": policy_name,
            "insurer": data.get("insurer", ""),
            "policy_number": data.get("policy_number", ""),
            "policy_type": policy_type,
            "coverage_limit_usd": coverage_limit,
            "deductible_usd": float(data.get("deductible_usd", 0.0)),
            "premium_annual_usd": float(data.get("premium_annual_usd", 0.0)),
            "coverage_types": json.dumps(data.get("coverage_types", [])),
            "effective_date": data.get("effective_date", ""),
            "expiry_date": data.get("expiry_date", ""),
            "status": data.get("status", "pending"),
            "risk_score": float(data.get("risk_score", 0.0)),
            "tier": tier,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO policies_v2
                       (id, org_id, policy_name, insurer, policy_number, policy_type,
                        coverage_limit_usd, deductible_usd, premium_annual_usd,
                        coverage_types, effective_date, expiry_date, status,
                        risk_score, tier, created_at)
                       VALUES (:id, :org_id, :policy_name, :insurer, :policy_number,
                               :policy_type, :coverage_limit_usd, :deductible_usd,
                               :premium_annual_usd, :coverage_types, :effective_date,
                               :expiry_date, :status, :risk_score, :tier, :created_at)""",
                    record,
                )
        result = dict(record)
        result["coverage_types"] = data.get("coverage_types", [])
        result["days_until_expiry"] = self._days_until(result.get("expiry_date", ""))
        return result

    def list_policies_v2(
        self, org_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List v2 policies with days_until_expiry computed."""
        self._get_v2()
        sql = "SELECT * FROM policies_v2 WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = [self._deserialize_row(dict(r)) for r in conn.execute(sql, params).fetchall()]
        for row in rows:
            row["days_until_expiry"] = self._days_until(row.get("expiry_date", ""))
        return rows

    def get_policy_v2(self, org_id: str, policy_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a v2 policy with its claims summary."""
        self._get_v2()
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM policies_v2 WHERE org_id = ? AND id = ?",
                (org_id, policy_id),
            ).fetchone()
            if not row:
                return None
            result = self._deserialize_row(dict(row))
            result["days_until_expiry"] = self._days_until(result.get("expiry_date", ""))
            result["claims_count"] = conn.execute(
                "SELECT COUNT(*) FROM claims_v2 WHERE org_id = ? AND policy_id = ?",
                (org_id, policy_id),
            ).fetchone()[0]
            result["total_claimed_usd"] = conn.execute(
                "SELECT COALESCE(SUM(claim_amount_usd), 0.0) FROM claims_v2 WHERE org_id = ? AND policy_id = ?",
                (org_id, policy_id),
            ).fetchone()[0]
        return result

    # --------------- claims_v2 ---------------

    def file_claim_v2(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """File a new v2 claim."""
        self._get_v2()
        policy_id = (data.get("policy_id") or "").strip()
        if not policy_id:
            raise ValueError("policy_id is required.")

        _valid_incident = {"ransomware", "data_breach", "ddos", "fraud", "regulatory"}
        incident_type = data.get("incident_type", "data_breach")
        if incident_type not in _valid_incident:
            raise ValueError(f"Invalid incident_type: {incident_type}")

        now = datetime.now(timezone.utc).isoformat()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "policy_id": policy_id,
            "incident_type": incident_type,
            "incident_date": data.get("incident_date", now),
            "claim_date": data.get("claim_date", now),
            "claim_amount_usd": float(data.get("claim_amount_usd", 0.0)),
            "settled_amount_usd": 0.0,
            "status": "submitted",
            "adjuster_name": data.get("adjuster_name", ""),
            "incident_description": data.get("incident_description", ""),
            "related_incident_id": data.get("related_incident_id", ""),
            "settled_date": None,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO claims_v2
                       (id, org_id, policy_id, incident_type, incident_date, claim_date,
                        claim_amount_usd, settled_amount_usd, status, adjuster_name,
                        incident_description, related_incident_id, settled_date, created_at)
                       VALUES (:id, :org_id, :policy_id, :incident_type, :incident_date,
                               :claim_date, :claim_amount_usd, :settled_amount_usd, :status,
                               :adjuster_name, :incident_description, :related_incident_id,
                               :settled_date, :created_at)""",
                    record,
                )
        return record

    def update_claim_v2(
        self,
        org_id: str,
        claim_id: str,
        status: str,
        settled_amount: Optional[float] = None,
    ) -> bool:
        """Update v2 claim status."""
        self._get_v2()
        _valid = {"submitted", "under_review", "approved", "denied", "settled", "withdrawn"}
        if status not in _valid:
            raise ValueError(f"Invalid status: {status}")
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                if status == "settled" and settled_amount is not None:
                    cur = conn.execute(
                        """UPDATE claims_v2 SET status = ?, settled_amount_usd = ?, settled_date = ?
                           WHERE org_id = ? AND id = ?""",
                        (status, settled_amount, now, org_id, claim_id),
                    )
                else:
                    cur = conn.execute(
                        "UPDATE claims_v2 SET status = ? WHERE org_id = ? AND id = ?",
                        (status, org_id, claim_id),
                    )
                return cur.rowcount > 0

    def list_claims_v2(
        self,
        org_id: str,
        policy_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List v2 claims."""
        self._get_v2()
        sql = "SELECT * FROM claims_v2 WHERE org_id = ?"
        params: list = [org_id]
        if policy_id:
            sql += " AND policy_id = ?"
            params.append(policy_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]

    # --------------- coverage_gaps ---------------

    def add_coverage_gap(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a coverage gap."""
        self._get_v2()
        _valid_gap = {"uncovered_attack_vector", "low_limit", "high_deductible", "exclusion", "sublimit"}
        _valid_sev = {"critical", "high", "medium", "low"}
        gap_type = data.get("gap_type", "exclusion")
        if gap_type not in _valid_gap:
            raise ValueError(f"Invalid gap_type: {gap_type}")
        severity = data.get("severity", "medium")
        if severity not in _valid_sev:
            raise ValueError(f"Invalid severity: {severity}")

        now = datetime.now(timezone.utc).isoformat()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "gap_type": gap_type,
            "severity": severity,
            "description": data.get("description", ""),
            "estimated_exposure_usd": float(data.get("estimated_exposure_usd", 0.0)),
            "recommendation": data.get("recommendation", ""),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO coverage_gaps
                       (id, org_id, gap_type, severity, description,
                        estimated_exposure_usd, recommendation, created_at)
                       VALUES (:id, :org_id, :gap_type, :severity, :description,
                               :estimated_exposure_usd, :recommendation, :created_at)""",
                    record,
                )
        return record

    def list_coverage_gaps(
        self, org_id: str, severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List coverage gaps sorted by severity (critical first)."""
        self._get_v2()
        _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sql = "SELECT * FROM coverage_gaps WHERE org_id = ?"
        params: list = [org_id]
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
        rows.sort(key=lambda r: _sev_order.get(r.get("severity", "low"), 4))
        return rows

    # --------------- risk_assessments ---------------

    def create_risk_assessment(
        self, org_id: str, policy_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a risk assessment for a policy."""
        self._get_v2()
        _valid_types = {"renewal", "quarterly", "incident_triggered"}
        assessment_type = data.get("assessment_type", "quarterly")
        if assessment_type not in _valid_types:
            raise ValueError(f"Invalid assessment_type: {assessment_type}")

        now = datetime.now(timezone.utc).isoformat()
        recs = data.get("recommendations", [])
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "policy_id": policy_id,
            "assessment_type": assessment_type,
            "overall_risk_score": float(data.get("overall_risk_score", 0.0)),
            "security_posture_score": float(data.get("security_posture_score", 0.0)),
            "incident_history_score": float(data.get("incident_history_score", 0.0)),
            "control_effectiveness": float(data.get("control_effectiveness", 0.0)),
            "recommendations": json.dumps(recs),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO risk_assessments
                       (id, org_id, policy_id, assessment_type, overall_risk_score,
                        security_posture_score, incident_history_score,
                        control_effectiveness, recommendations, created_at)
                       VALUES (:id, :org_id, :policy_id, :assessment_type,
                               :overall_risk_score, :security_posture_score,
                               :incident_history_score, :control_effectiveness,
                               :recommendations, :created_at)""",
                    record,
                )
        result = dict(record)
        result["recommendations"] = recs
        return result

    # --------------- v2 stats ---------------

    def get_insurance_stats_v2(self, org_id: str) -> Dict[str, Any]:
        """Extended insurance stats with expiring_soon, settlement_rate, avg_risk_score."""
        self._get_v2()
        from datetime import timedelta
        ninety_days_out = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()

        with self._conn() as conn:
            active_policies = conn.execute(
                "SELECT COUNT(*) FROM policies_v2 WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]
            total_coverage = conn.execute(
                "SELECT COALESCE(SUM(coverage_limit_usd), 0.0) FROM policies_v2 WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]
            total_premium = conn.execute(
                "SELECT COALESCE(SUM(premium_annual_usd), 0.0) FROM policies_v2 WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]
            open_claims = conn.execute(
                "SELECT COUNT(*) FROM claims_v2 WHERE org_id = ? AND status IN ('submitted','under_review','approved')",
                (org_id,),
            ).fetchone()[0]
            total_claimed = conn.execute(
                "SELECT COALESCE(SUM(claim_amount_usd), 0.0) FROM claims_v2 WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]
            settled_count = conn.execute(
                "SELECT COUNT(*) FROM claims_v2 WHERE org_id = ? AND status = 'settled'",
                (org_id,),
            ).fetchone()[0]
            total_claims_count = conn.execute(
                "SELECT COUNT(*) FROM claims_v2 WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]
            coverage_gaps_count = conn.execute(
                "SELECT COUNT(*) FROM coverage_gaps WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]
            expiring_soon = conn.execute(
                """SELECT COUNT(*) FROM policies_v2
                   WHERE org_id = ? AND status = 'active'
                     AND expiry_date != '' AND expiry_date <= ?""",
                (org_id, ninety_days_out),
            ).fetchone()[0]
            avg_risk_score = conn.execute(
                "SELECT COALESCE(AVG(overall_risk_score), 0.0) FROM risk_assessments WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

        settlement_rate = (
            round(settled_count / total_claims_count, 4) if total_claims_count else 0.0
        )
        return {
            "active_policies": active_policies,
            "total_coverage_limit": total_coverage,
            "total_premium": total_premium,
            "open_claims": open_claims,
            "total_claimed": total_claimed,
            "settlement_rate": settlement_rate,
            "coverage_gaps": coverage_gaps_count,
            "expiring_soon": expiring_soon,
            "avg_risk_score": round(avg_risk_score, 4),
        }
