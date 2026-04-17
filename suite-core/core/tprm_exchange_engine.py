"""TPRM Exchange Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Third-party risk management exchange: vendor profiles, assessments, data sharing.
  - Vendor registration with criticality-based risk_tier mapping
  - Assessment lifecycle (in_progress → completed) with risk_tier recompute
  - Incident reporting and resolution
  - Summary analytics: overdue assessments, critical vendors, tier breakdown
  - Full org_id isolation for multi-tenant deployments

Compliance: NIST CSF ID.SC, ISO 27036, DORA Third-Party Risk
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "tprm_exchange_engine.db"
)

_VALID_VENDOR_CATEGORIES = {
    "cloud_provider", "saas", "hardware", "consulting",
    "data_processor", "logistics", "financial", "legal",
}
_VALID_CRITICALITIES = {"critical", "high", "medium", "low"}
_VALID_ASSESSMENT_TYPES = {"initial", "annual", "triggered", "spot_check"}
_VALID_INCIDENT_TYPES = {
    "data_breach", "service_outage", "compliance_violation",
    "security_vulnerability", "fraud",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_RISK_TIERS = {"tier-1", "tier-2", "tier-3", "tier-4"}

_CRITICALITY_TO_TIER: Dict[str, str] = {
    "critical": "tier-1",
    "high": "tier-2",
    "medium": "tier-3",
    "low": "tier-4",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _score_to_tier(score: float) -> str:
    """Compute risk_tier from assessment score (lower score = higher risk)."""
    if score < 40:
        return "tier-1"
    if score < 60:
        return "tier-2"
    if score < 80:
        return "tier-3"
    return "tier-4"


class TPRMExchangeEngine:
    """SQLite WAL-backed TPRM Exchange engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/tprm_exchange_engine.db
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
                CREATE TABLE IF NOT EXISTS vendor_profiles (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    vendor_name          TEXT NOT NULL DEFAULT '',
                    vendor_category      TEXT NOT NULL DEFAULT 'saas',
                    criticality          TEXT NOT NULL DEFAULT 'medium',
                    data_shared          TEXT NOT NULL DEFAULT '[]',
                    contract_start       TEXT NOT NULL DEFAULT '',
                    contract_end         TEXT NOT NULL DEFAULT '',
                    annual_spend         REAL NOT NULL DEFAULT 0.0,
                    primary_contact      TEXT NOT NULL DEFAULT '',
                    last_assessment_date TEXT NOT NULL DEFAULT '',
                    risk_score           REAL NOT NULL DEFAULT 0.0,
                    risk_tier            TEXT NOT NULL DEFAULT 'tier-3',
                    status               TEXT NOT NULL DEFAULT 'active',
                    created_at           TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tprm_vendors_org
                    ON vendor_profiles (org_id, risk_tier, status);

                CREATE TABLE IF NOT EXISTS tprm_assessments (
                    id               TEXT PRIMARY KEY,
                    vendor_id        TEXT NOT NULL,
                    org_id           TEXT NOT NULL,
                    assessment_type  TEXT NOT NULL DEFAULT 'annual',
                    assessor         TEXT NOT NULL DEFAULT '',
                    score            REAL NOT NULL DEFAULT 0.0,
                    findings_count   INTEGER NOT NULL DEFAULT 0,
                    critical_findings INTEGER NOT NULL DEFAULT 0,
                    status           TEXT NOT NULL DEFAULT 'in_progress',
                    due_date         TEXT NOT NULL DEFAULT '',
                    completed_date   TEXT NOT NULL DEFAULT '',
                    next_assessment  TEXT NOT NULL DEFAULT '',
                    created_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tprm_assessments_org
                    ON tprm_assessments (org_id, vendor_id, status);

                CREATE TABLE IF NOT EXISTS vendor_incidents (
                    id          TEXT PRIMARY KEY,
                    vendor_id   TEXT NOT NULL,
                    org_id      TEXT NOT NULL,
                    incident_type TEXT NOT NULL DEFAULT 'service_outage',
                    severity    TEXT NOT NULL DEFAULT 'medium',
                    description TEXT NOT NULL DEFAULT '',
                    impact      TEXT NOT NULL DEFAULT '',
                    reported_at TEXT NOT NULL DEFAULT '',
                    resolved_at TEXT NOT NULL DEFAULT '',
                    status      TEXT NOT NULL DEFAULT 'open',
                    created_at  TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tprm_incidents_org
                    ON vendor_incidents (org_id, vendor_id, status);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Vendor management
    # ------------------------------------------------------------------

    def register_vendor(
        self,
        org_id: str,
        vendor_name: str,
        vendor_category: str = "saas",
        criticality: str = "medium",
        data_shared: Optional[List[str]] = None,
        contract_start: str = "",
        contract_end: str = "",
        annual_spend: float = 0.0,
        primary_contact: str = "",
    ) -> Dict[str, Any]:
        """Register a new vendor with criticality-based risk_tier."""
        if vendor_category not in _VALID_VENDOR_CATEGORIES:
            raise ValueError(f"Invalid vendor_category: {vendor_category}")
        if criticality not in _VALID_CRITICALITIES:
            raise ValueError(f"Invalid criticality: {criticality}")

        vendor_id = str(uuid.uuid4())
        now = _now_iso()
        data_shared_json = json.dumps(data_shared or [])
        risk_tier = _CRITICALITY_TO_TIER[criticality]

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO vendor_profiles
                        (id, org_id, vendor_name, vendor_category, criticality,
                         data_shared, contract_start, contract_end, annual_spend,
                         primary_contact, last_assessment_date, risk_score,
                         risk_tier, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', 0.0, ?, 'active', ?)
                    """,
                    (vendor_id, org_id, vendor_name, vendor_category, criticality,
                     data_shared_json, contract_start, contract_end, annual_spend,
                     primary_contact, risk_tier, now),
                )
        return self._get_vendor_by_id(vendor_id, org_id)

    def _get_vendor_by_id(self, vendor_id: str, org_id: str) -> Dict[str, Any]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM vendor_profiles WHERE id=? AND org_id=?",
                (vendor_id, org_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Vendor {vendor_id} not found")
        return self._row_to_vendor(row)

    def _row_to_vendor(self, row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["data_shared"] = json.loads(d.get("data_shared", "[]"))
        return d

    # ------------------------------------------------------------------
    # Assessment management
    # ------------------------------------------------------------------

    def create_assessment(
        self,
        vendor_id: str,
        org_id: str,
        assessment_type: str = "annual",
        assessor: str = "",
        due_date: str = "",
    ) -> Dict[str, Any]:
        """Create a new assessment for a vendor (status=in_progress)."""
        if assessment_type not in _VALID_ASSESSMENT_TYPES:
            raise ValueError(f"Invalid assessment_type: {assessment_type}")

        # Verify vendor exists in org
        self._get_vendor_by_id(vendor_id, org_id)

        assessment_id = str(uuid.uuid4())
        now = _now_iso()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO tprm_assessments
                        (id, vendor_id, org_id, assessment_type, assessor, score,
                         findings_count, critical_findings, status, due_date,
                         completed_date, next_assessment, created_at)
                    VALUES (?, ?, ?, ?, ?, 0.0, 0, 0, 'in_progress', ?, '', '', ?)
                    """,
                    (assessment_id, vendor_id, org_id, assessment_type, assessor,
                     due_date, now),
                )
        return self._get_assessment_by_id(assessment_id, org_id)

    def _get_assessment_by_id(self, assessment_id: str, org_id: str) -> Dict[str, Any]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM tprm_assessments WHERE id=? AND org_id=?",
                (assessment_id, org_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Assessment {assessment_id} not found")
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "tprm_exchange_engine", "org_id": org_id, "source_engine": "tprm_exchange_engine"})
            except Exception:
                pass
        return dict(row)

    def complete_assessment(
        self,
        assessment_id: str,
        org_id: str,
        score: float,
        findings_count: int = 0,
        critical_findings: int = 0,
        next_assessment: str = "",
    ) -> Dict[str, Any]:
        """Complete an assessment, update vendor risk_score and risk_tier."""
        score = max(0.0, min(100.0, float(score)))
        now = _now_iso()

        with self._lock:
            with self._conn() as conn:
                # Fetch assessment to get vendor_id
                ass_row = conn.execute(
                    "SELECT * FROM tprm_assessments WHERE id=? AND org_id=?",
                    (assessment_id, org_id),
                ).fetchone()
                if not ass_row:
                    raise ValueError(f"Assessment {assessment_id} not found for org {org_id}")

                vendor_id = ass_row["vendor_id"]
                new_tier = _score_to_tier(score)

                # Update assessment
                conn.execute(
                    """
                    UPDATE tprm_assessments
                       SET status='completed', score=?, findings_count=?,
                           critical_findings=?, completed_date=?, next_assessment=?
                     WHERE id=? AND org_id=?
                    """,
                    (score, findings_count, critical_findings, now,
                     next_assessment, assessment_id, org_id),
                )

                # Update vendor last_assessment_date, risk_score, risk_tier
                conn.execute(
                    """
                    UPDATE vendor_profiles
                       SET last_assessment_date=?, risk_score=?, risk_tier=?
                     WHERE id=? AND org_id=?
                    """,
                    (now, score, new_tier, vendor_id, org_id),
                )

        return self._get_assessment_by_id(assessment_id, org_id)

    # ------------------------------------------------------------------
    # Incident management
    # ------------------------------------------------------------------

    def report_incident(
        self,
        vendor_id: str,
        org_id: str,
        incident_type: str = "service_outage",
        severity: str = "medium",
        description: str = "",
        impact: str = "",
    ) -> Dict[str, Any]:
        """Report a vendor incident."""
        if incident_type not in _VALID_INCIDENT_TYPES:
            raise ValueError(f"Invalid incident_type: {incident_type}")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")

        # Verify vendor exists in org
        self._get_vendor_by_id(vendor_id, org_id)

        incident_id = str(uuid.uuid4())
        now = _now_iso()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO vendor_incidents
                        (id, vendor_id, org_id, incident_type, severity, description,
                         impact, reported_at, resolved_at, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', 'open', ?)
                    """,
                    (incident_id, vendor_id, org_id, incident_type, severity,
                     description, impact, now, now),
                )
        return self._get_incident_by_id(incident_id, org_id)

    def _get_incident_by_id(self, incident_id: str, org_id: str) -> Dict[str, Any]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM vendor_incidents WHERE id=? AND org_id=?",
                (incident_id, org_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Incident {incident_id} not found")
        return dict(row)

    def resolve_incident(self, incident_id: str, org_id: str) -> Dict[str, Any]:
        """Resolve a vendor incident."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """
                    UPDATE vendor_incidents
                       SET status='resolved', resolved_at=?
                     WHERE id=? AND org_id=?
                    """,
                    (now, incident_id, org_id),
                )
                if cur.rowcount == 0:
                    raise ValueError(f"Incident {incident_id} not found for org {org_id}")
        return self._get_incident_by_id(incident_id, org_id)

    # ------------------------------------------------------------------
    # Detail view
    # ------------------------------------------------------------------

    def get_vendor_detail(self, vendor_id: str, org_id: str) -> Dict[str, Any]:
        """Return vendor profile with all its assessments and incidents."""
        vendor = self._get_vendor_by_id(vendor_id, org_id)

        with self._conn() as conn:
            assessments = conn.execute(
                "SELECT * FROM tprm_assessments WHERE vendor_id=? AND org_id=? ORDER BY created_at DESC",
                (vendor_id, org_id),
            ).fetchall()
            incidents = conn.execute(
                "SELECT * FROM vendor_incidents WHERE vendor_id=? AND org_id=? ORDER BY created_at DESC",
                (vendor_id, org_id),
            ).fetchall()

        vendor["assessments"] = [dict(r) for r in assessments]
        vendor["incidents"] = [dict(r) for r in incidents]
        return vendor

    # ------------------------------------------------------------------
    # Analytics
    # ------------------------------------------------------------------

    def get_tprm_summary(self, org_id: str) -> Dict[str, Any]:
        """Return TPRM summary: totals, tier breakdown, category breakdown, overdue, incidents."""
        now = _now_iso()
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) AS c FROM vendor_profiles WHERE org_id=? AND status='active'",
                (org_id,),
            ).fetchone()["c"]

            tier_rows = conn.execute(
                """
                SELECT risk_tier, COUNT(*) AS c
                  FROM vendor_profiles WHERE org_id=? AND status='active'
                 GROUP BY risk_tier
                """,
                (org_id,),
            ).fetchall()
            by_tier = {r["risk_tier"]: r["c"] for r in tier_rows}

            cat_rows = conn.execute(
                """
                SELECT vendor_category, COUNT(*) AS c
                  FROM vendor_profiles WHERE org_id=? AND status='active'
                 GROUP BY vendor_category
                """,
                (org_id,),
            ).fetchall()
            by_category = {r["vendor_category"]: r["c"] for r in cat_rows}

            overdue = conn.execute(
                """
                SELECT COUNT(*) AS c FROM tprm_assessments
                 WHERE org_id=? AND status='in_progress' AND due_date < ? AND due_date != ''
                """,
                (org_id, now),
            ).fetchone()["c"]

            open_incidents = conn.execute(
                "SELECT COUNT(*) AS c FROM vendor_incidents WHERE org_id=? AND status='open'",
                (org_id,),
            ).fetchone()["c"]

            critical_vendors = conn.execute(
                "SELECT COUNT(*) AS c FROM vendor_profiles WHERE org_id=? AND risk_tier='tier-1' AND status='active'",
                (org_id,),
            ).fetchone()["c"]

        return {
            "org_id": org_id,
            "total_vendors": total,
            "by_tier": by_tier,
            "by_category": by_category,
            "overdue_assessments": overdue,
            "open_incidents": open_incidents,
            "critical_vendors": critical_vendors,
        }

    def get_overdue_assessments(self, org_id: str) -> List[Dict[str, Any]]:
        """Return assessments past due_date that are still in_progress."""
        now = _now_iso()
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM tprm_assessments
                 WHERE org_id=? AND status='in_progress' AND due_date < ? AND due_date != ''
                 ORDER BY due_date
                """,
                (org_id, now),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_high_risk_vendors(self, org_id: str) -> List[Dict[str, Any]]:
        """Return tier-1 and tier-2 vendors ordered by risk_score ascending (highest risk first)."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM vendor_profiles
                 WHERE org_id=? AND risk_tier IN ('tier-1', 'tier-2') AND status='active'
                 ORDER BY risk_score ASC
                """,
                (org_id,),
            ).fetchall()
        return [self._row_to_vendor(r) for r in rows]
