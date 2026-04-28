"""Third Party Vendor Engine — ALDECI.

Manages vendor registration, security assessments, and incident tracking.

Capabilities:
  - Vendor registry with risk rating and contract status
  - Security assessment lifecycle (questionnaire, pentest, audit, self-attestation)
  - Automatic risk_score recalculation and risk_rating update on assessment
  - Incident tracking per vendor
  - Stats aggregation per org (unassessed, critical, avg risk score)

Compliance: ISO 27001 A.15, NIST SP 800-161 (Supply Chain Risk Management)
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / ".fixops_data" / "third_party_vendor.db")

_VALID_VENDOR_CATEGORIES = {"software", "hardware", "services", "cloud", "consulting", "staffing", "logistics"}
_VALID_RISK_RATINGS = {"critical", "high", "medium", "low", "unrated"}
_VALID_ASSESSMENT_TYPES = {"security_questionnaire", "penetration_test", "audit", "self_attestation", "third_party_audit"}
_VALID_CONTRACT_STATUSES = {"active", "expired", "terminated", "pending", "under_review"}
_VALID_DATA_ACCESS_LEVELS = {"none", "public", "internal", "confidential", "critical"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _risk_rating_from_score(score: float) -> str:
    """Derive risk_rating from risk_score."""
    if score <= 25:
        return "low"
    elif score <= 50:
        return "medium"
    elif score <= 75:
        return "high"
    else:
        return "critical"


class ThirdPartyVendorEngine:
    """SQLite WAL-backed Third Party Vendor engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Database stored at .fixops_data/third_party_vendor.db
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # DB bootstrap
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS tpv_vendors (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    name              TEXT NOT NULL DEFAULT '',
                    vendor_category   TEXT NOT NULL DEFAULT 'software',
                    website           TEXT NOT NULL DEFAULT '',
                    primary_contact   TEXT NOT NULL DEFAULT '',
                    data_access_level TEXT NOT NULL DEFAULT 'public',
                    risk_rating       TEXT NOT NULL DEFAULT 'unrated',
                    contract_status   TEXT NOT NULL DEFAULT 'active',
                    last_assessed     DATETIME,
                    risk_score        REAL NOT NULL DEFAULT 50.0,
                    created_at        DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_tpv_vendors_org
                    ON tpv_vendors(org_id, vendor_category, risk_rating, contract_status);

                CREATE TABLE IF NOT EXISTS tpv_assessments (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    vendor_id        TEXT NOT NULL,
                    assessment_type  TEXT NOT NULL DEFAULT 'security_questionnaire',
                    assessor         TEXT NOT NULL DEFAULT '',
                    score            REAL NOT NULL DEFAULT 0.0,
                    findings_count   INTEGER NOT NULL DEFAULT 0,
                    critical_findings INTEGER NOT NULL DEFAULT 0,
                    passed           INTEGER NOT NULL DEFAULT 0,
                    assessment_date  DATETIME,
                    next_review_date DATETIME,
                    notes            TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_tpv_assessments_org
                    ON tpv_assessments(org_id, vendor_id, assessment_type);

                CREATE TABLE IF NOT EXISTS tpv_incidents (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    vendor_id   TEXT NOT NULL,
                    title       TEXT NOT NULL DEFAULT '',
                    severity    TEXT NOT NULL DEFAULT 'medium',
                    description TEXT NOT NULL DEFAULT '',
                    impact      TEXT NOT NULL DEFAULT '',
                    status      TEXT NOT NULL DEFAULT 'open',
                    reported_at DATETIME,
                    resolved_at DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_tpv_incidents_org
                    ON tpv_incidents(org_id, vendor_id, severity, status);
            """)

    @staticmethod
    def _row(row) -> dict:
        return dict(row)

    # ------------------------------------------------------------------
    # Vendor CRUD
    # ------------------------------------------------------------------

    def register_vendor(self, org_id: str, data: dict) -> dict:
        """Register a new third-party vendor."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required")
        vendor_category = (data.get("vendor_category") or "").strip().lower()
        if vendor_category not in _VALID_VENDOR_CATEGORIES:
            raise ValueError(f"vendor_category must be one of {sorted(_VALID_VENDOR_CATEGORIES)}")
        data_access_level = (data.get("data_access_level") or "public").strip().lower()
        if data_access_level not in _VALID_DATA_ACCESS_LEVELS:
            raise ValueError(f"data_access_level must be one of {sorted(_VALID_DATA_ACCESS_LEVELS)}")

        vendor_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": vendor_id,
            "org_id": org_id,
            "name": name,
            "vendor_category": vendor_category,
            "website": (data.get("website") or "").strip(),
            "primary_contact": (data.get("primary_contact") or "").strip(),
            "data_access_level": data_access_level,
            "risk_rating": "unrated",
            "contract_status": (data.get("contract_status") or "active").strip().lower(),
            "last_assessed": None,
            "risk_score": 50.0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO tpv_vendors
                       (id, org_id, name, vendor_category, website, primary_contact,
                        data_access_level, risk_rating, contract_status, last_assessed,
                        risk_score, created_at)
                       VALUES (:id, :org_id, :name, :vendor_category, :website, :primary_contact,
                               :data_access_level, :risk_rating, :contract_status, :last_assessed,
                               :risk_score, :created_at)""",
                    row,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "third_party_vendor", "org_id": org_id, "source_engine": "third_party_vendor"})
            except Exception:
                pass

        return row

    def list_vendors(
        self,
        org_id: str,
        vendor_category: Optional[str] = None,
        risk_rating: Optional[str] = None,
        contract_status: Optional[str] = None,
    ) -> List[dict]:
        """List vendors with optional filters."""
        sql = "SELECT * FROM tpv_vendors WHERE org_id=?"
        params: list = [org_id]
        if vendor_category:
            sql += " AND vendor_category=?"
            params.append(vendor_category)
        if risk_rating:
            sql += " AND risk_rating=?"
            params.append(risk_rating)
        if contract_status:
            sql += " AND contract_status=?"
            params.append(contract_status)
        sql += " ORDER BY risk_score DESC, name"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_vendor(self, org_id: str, vendor_id: str) -> Optional[dict]:
        """Get a single vendor by ID."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM tpv_vendors WHERE id=? AND org_id=?",
                    (vendor_id, org_id),
                ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    def conduct_assessment(self, org_id: str, vendor_id: str, assessment_data: dict) -> dict:
        """Conduct a security assessment for a vendor.

        Recalculates vendor risk_score = 100 - score + (critical_findings * 10),
        clamped to 0-100. Auto-updates risk_rating based on new risk_score.
        """
        assessment_type = (assessment_data.get("assessment_type") or "security_questionnaire").strip().lower()
        if assessment_type not in _VALID_ASSESSMENT_TYPES:
            raise ValueError(f"assessment_type must be one of {sorted(_VALID_ASSESSMENT_TYPES)}")

        score = float(assessment_data.get("score") or 0.0)
        findings_count = int(assessment_data.get("findings_count") or 0)
        critical_findings = int(assessment_data.get("critical_findings") or 0)
        passed = int(bool(assessment_data.get("passed")))

        assessment_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": assessment_id,
            "org_id": org_id,
            "vendor_id": vendor_id,
            "assessment_type": assessment_type,
            "assessor": (assessment_data.get("assessor") or "").strip(),
            "score": score,
            "findings_count": findings_count,
            "critical_findings": critical_findings,
            "passed": passed,
            "assessment_date": assessment_data.get("assessment_date") or now,
            "next_review_date": assessment_data.get("next_review_date") or None,
            "notes": (assessment_data.get("notes") or "").strip(),
        }

        # Recalculate risk_score and risk_rating
        raw_risk_score = 100.0 - score + (critical_findings * 10)
        new_risk_score = max(0.0, min(100.0, raw_risk_score))
        new_risk_rating = _risk_rating_from_score(new_risk_score)

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO tpv_assessments
                       (id, org_id, vendor_id, assessment_type, assessor, score,
                        findings_count, critical_findings, passed, assessment_date,
                        next_review_date, notes)
                       VALUES (:id, :org_id, :vendor_id, :assessment_type, :assessor, :score,
                               :findings_count, :critical_findings, :passed, :assessment_date,
                               :next_review_date, :notes)""",
                    row,
                )
                # Update vendor last_assessed, risk_score, risk_rating
                conn.execute(
                    """UPDATE tpv_vendors
                       SET last_assessed=?, risk_score=?, risk_rating=?
                       WHERE id=? AND org_id=?""",
                    (now, new_risk_score, new_risk_rating, vendor_id, org_id),
                )
        return row

    def list_assessments(
        self,
        org_id: str,
        vendor_id: Optional[str] = None,
        assessment_type: Optional[str] = None,
    ) -> List[dict]:
        """List assessments with optional filters."""
        sql = "SELECT * FROM tpv_assessments WHERE org_id=?"
        params: list = [org_id]
        if vendor_id:
            sql += " AND vendor_id=?"
            params.append(vendor_id)
        if assessment_type:
            sql += " AND assessment_type=?"
            params.append(assessment_type)
        sql += " ORDER BY assessment_date DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------

    def add_incident(self, org_id: str, vendor_id: str, incident_data: dict) -> dict:
        """Record a vendor-related security incident."""
        now = _now_iso()
        incident_id = str(uuid.uuid4())
        row = {
            "id": incident_id,
            "org_id": org_id,
            "vendor_id": vendor_id,
            "title": (incident_data.get("title") or "").strip(),
            "severity": (incident_data.get("severity") or "medium").strip().lower(),
            "description": (incident_data.get("description") or "").strip(),
            "impact": (incident_data.get("impact") or "").strip(),
            "status": "open",
            "reported_at": now,
            "resolved_at": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO tpv_incidents
                       (id, org_id, vendor_id, title, severity, description, impact,
                        status, reported_at, resolved_at)
                       VALUES (:id, :org_id, :vendor_id, :title, :severity, :description, :impact,
                               :status, :reported_at, :resolved_at)""",
                    row,
                )
        return row

    def list_incidents(
        self,
        org_id: str,
        vendor_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[dict]:
        """List incidents with optional filters."""
        sql = "SELECT * FROM tpv_incidents WHERE org_id=?"
        params: list = [org_id]
        if vendor_id:
            sql += " AND vendor_id=?"
            params.append(vendor_id)
        if severity:
            sql += " AND severity=?"
            params.append(severity)
        if status:
            sql += " AND status=?"
            params.append(status)
        sql += " ORDER BY reported_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_vendor_stats(self, org_id: str) -> dict:
        """Return aggregated third-party vendor statistics for the org."""
        with self._lock:
            with self._conn() as conn:
                total_vendors = conn.execute(
                    "SELECT COUNT(*) FROM tpv_vendors WHERE org_id=?", (org_id,)
                ).fetchone()[0]
                critical_vendors = conn.execute(
                    "SELECT COUNT(*) FROM tpv_vendors WHERE org_id=? AND risk_rating='critical'",
                    (org_id,),
                ).fetchone()[0]
                unassessed_vendors = conn.execute(
                    "SELECT COUNT(*) FROM tpv_vendors WHERE org_id=? AND last_assessed IS NULL",
                    (org_id,),
                ).fetchone()[0]
                avg_risk_row = conn.execute(
                    "SELECT AVG(risk_score) FROM tpv_vendors WHERE org_id=?", (org_id,)
                ).fetchone()
                avg_risk_score = round(float(avg_risk_row[0] or 0.0), 2)
                active_incidents = conn.execute(
                    "SELECT COUNT(*) FROM tpv_incidents WHERE org_id=? AND status='open'",
                    (org_id,),
                ).fetchone()[0]

                # By category
                cat_rows = conn.execute(
                    "SELECT vendor_category, COUNT(*) as cnt FROM tpv_vendors WHERE org_id=? GROUP BY vendor_category",
                    (org_id,),
                ).fetchall()
                by_category = {r["vendor_category"]: r["cnt"] for r in cat_rows}

                # By risk rating
                rating_rows = conn.execute(
                    "SELECT risk_rating, COUNT(*) as cnt FROM tpv_vendors WHERE org_id=? GROUP BY risk_rating",
                    (org_id,),
                ).fetchall()
                by_risk_rating = {r["risk_rating"]: r["cnt"] for r in rating_rows}

        return {
            "org_id": org_id,
            "total_vendors": total_vendors,
            "critical_vendors": critical_vendors,
            "unassessed_vendors": unassessed_vendors,
            "avg_risk_score": avg_risk_score,
            "active_incidents": active_incidents,
            "by_category": by_category,
            "by_risk_rating": by_risk_rating,
        }
