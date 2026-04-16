"""GDPR Compliance Engine — Processing activities and consent management for ALDECI.

Manages GDPR Article 30 processing activity records and consent lifecycle.

Features:
- Processing activity registration with lawful basis validation
- Consent recording per subject/purpose with expiry support
- Consent withdrawal with audit trail
- GDPR assessment: consent rate, compliance score, activity coverage
- Org-scoped isolation for multi-tenant deployments

Compliance: GDPR Art. 6 (lawful basis), Art. 7 (consent), Art. 13-14 (transparency),
            Art. 30 (records of processing), Art. 17 (right to erasure)
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

from pydantic import BaseModel, Field

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / ".fixops_data" / "gdpr_compliance.db")

_VALID_LAWFUL_BASES = {
    "consent", "contract", "legal_obligation", "vital_interests",
    "public_task", "legitimate_interests",
}


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class ProcessingActivityCreate(BaseModel):
    name: str
    purpose: str
    lawful_basis: str
    data_categories: List[str] = Field(default_factory=list)
    recipients: List[str] = Field(default_factory=list)
    retention_period: Optional[str] = None


class ConsentCreate(BaseModel):
    subject_id: str
    purpose: str
    expires_at: Optional[str] = None


class ConsentWithdrawRequest(BaseModel):
    reason: str = ""


# ============================================================================
# GDPR COMPLIANCE ENGINE
# ============================================================================


class GDPRComplianceEngine:
    """GDPR compliance engine — processing activities and consent lifecycle."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # DB INIT
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS gdpr_activities (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    name             TEXT NOT NULL,
                    purpose          TEXT NOT NULL,
                    lawful_basis     TEXT NOT NULL,
                    data_categories  TEXT NOT NULL DEFAULT '[]',
                    recipients       TEXT NOT NULL DEFAULT '[]',
                    retention_period TEXT,
                    status           TEXT NOT NULL DEFAULT 'active',
                    created_at       TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS gdpr_consents (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    subject_id      TEXT NOT NULL,
                    purpose         TEXT NOT NULL,
                    consented       INTEGER NOT NULL DEFAULT 1,
                    recorded_at     TEXT NOT NULL,
                    withdrawn_at    TEXT,
                    expires_at      TEXT,
                    withdraw_reason TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_gdpr_activities_org ON gdpr_activities(org_id);
                CREATE INDEX IF NOT EXISTS idx_gdpr_consents_org ON gdpr_consents(org_id);
                CREATE INDEX IF NOT EXISTS idx_gdpr_consents_subject ON gdpr_consents(subject_id);
            """)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # PROCESSING ACTIVITIES
    # ------------------------------------------------------------------

    def record_processing_activity(self, org_id: str, data: ProcessingActivityCreate) -> Dict[str, Any]:
        """Register a processing activity. Validates name, lawful_basis, and purpose."""
        if not data.name:
            raise ValueError("name is required")
        if not data.purpose:
            raise ValueError("purpose is required")
        if data.lawful_basis not in _VALID_LAWFUL_BASES:
            raise ValueError(
                f"Invalid lawful_basis '{data.lawful_basis}'. Must be one of {sorted(_VALID_LAWFUL_BASES)}"
            )

        activity_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO gdpr_activities
                   (id, org_id, name, purpose, lawful_basis, data_categories,
                    recipients, retention_period, status, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    activity_id, org_id, data.name, data.purpose, data.lawful_basis,
                    json.dumps(data.data_categories), json.dumps(data.recipients),
                    data.retention_period, "active", now,
                ),
            )
        _logger.info("gdpr.activity_recorded org=%s activity_id=%s", org_id, activity_id)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("CONTROL_ASSESSED", {"entity_type": "gdpr_compliance", "org_id": org_id, "source_engine": "gdpr_compliance"})
            except Exception:
                pass

        return self._get_activity(org_id, activity_id)

    def list_processing_activities(
        self,
        org_id: str,
        lawful_basis: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List processing activities for org, optionally filtered by lawful_basis or status."""
        query = "SELECT * FROM gdpr_activities WHERE org_id=?"
        params: List[Any] = [org_id]
        if lawful_basis:
            query += " AND lawful_basis=?"
            params.append(lawful_basis)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._deserialize_activity(dict(r)) for r in rows]

    def _get_activity(self, org_id: str, activity_id: str) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM gdpr_activities WHERE org_id=? AND id=?",
                (org_id, activity_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Activity {activity_id} not found for org {org_id}")
        return self._deserialize_activity(dict(row))

    @staticmethod
    def _deserialize_activity(row: Dict[str, Any]) -> Dict[str, Any]:
        for field in ("data_categories", "recipients"):
            if isinstance(row.get(field), str):
                try:
                    row[field] = json.loads(row[field])
                except (json.JSONDecodeError, TypeError):
                    row[field] = []
        return row

    # ------------------------------------------------------------------
    # CONSENT MANAGEMENT
    # ------------------------------------------------------------------

    def record_consent(self, org_id: str, data: ConsentCreate) -> Dict[str, Any]:
        """Record a consent entry for subject_id + purpose."""
        if not data.subject_id:
            raise ValueError("subject_id is required")
        if not data.purpose:
            raise ValueError("purpose is required")

        consent_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO gdpr_consents
                   (id, org_id, subject_id, purpose, consented, recorded_at, withdrawn_at, expires_at, withdraw_reason)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    consent_id, org_id, data.subject_id, data.purpose,
                    1, now, None, data.expires_at, None,
                ),
            )
        _logger.info("gdpr.consent_recorded org=%s consent_id=%s subject=%s", org_id, consent_id, data.subject_id)
        return self._get_consent(org_id, consent_id)

    def list_consents(
        self,
        org_id: str,
        subject_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List consents for org, optionally filtered by subject_id."""
        query = "SELECT * FROM gdpr_consents WHERE org_id=?"
        params: List[Any] = [org_id]
        if subject_id:
            query += " AND subject_id=?"
            params.append(subject_id)
        query += " ORDER BY recorded_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._deserialize_consent(dict(r)) for r in rows]

    def withdraw_consent(self, org_id: str, consent_id: str, reason: str = "") -> Dict[str, Any]:
        """Withdraw a consent record. Sets consented=False and withdrawn_at=now."""
        # Verify consent belongs to org
        self._get_consent(org_id, consent_id)

        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """UPDATE gdpr_consents
                   SET consented=0, withdrawn_at=?, withdraw_reason=?
                   WHERE org_id=? AND id=?""",
                (now, reason, org_id, consent_id),
            )
        _logger.info("gdpr.consent_withdrawn org=%s consent_id=%s", org_id, consent_id)
        return self._get_consent(org_id, consent_id)

    def _get_consent(self, org_id: str, consent_id: str) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM gdpr_consents WHERE org_id=? AND id=?",
                (org_id, consent_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Consent {consent_id} not found for org {org_id}")
        return self._deserialize_consent(dict(row))

    @staticmethod
    def _deserialize_consent(row: Dict[str, Any]) -> Dict[str, Any]:
        # Convert INTEGER 0/1 to bool for consented field
        if "consented" in row:
            row["consented"] = bool(row["consented"])
        return row

    # ------------------------------------------------------------------
    # GDPR ASSESSMENT
    # ------------------------------------------------------------------

    def run_gdpr_assessment(self, org_id: str) -> Dict[str, Any]:
        """Run GDPR compliance assessment for org_id.

        Returns metrics including consent_rate and compliance_score (0-100).
        compliance_score is based on having processing activities + consent coverage.
        """
        with self._connect() as conn:
            total_activities = conn.execute(
                "SELECT COUNT(*) FROM gdpr_activities WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            active_activities = conn.execute(
                "SELECT COUNT(*) FROM gdpr_activities WHERE org_id=? AND status='active'",
                (org_id,),
            ).fetchone()[0]

            basis_rows = conn.execute(
                "SELECT lawful_basis, COUNT(*) as cnt FROM gdpr_activities WHERE org_id=? GROUP BY lawful_basis",
                (org_id,),
            ).fetchall()
            activities_by_basis = {r["lawful_basis"]: r["cnt"] for r in basis_rows}

            total_consents = conn.execute(
                "SELECT COUNT(*) FROM gdpr_consents WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            active_consents = conn.execute(
                "SELECT COUNT(*) FROM gdpr_consents WHERE org_id=? AND consented=1",
                (org_id,),
            ).fetchone()[0]

            withdrawn_consents = conn.execute(
                "SELECT COUNT(*) FROM gdpr_consents WHERE org_id=? AND consented=0",
                (org_id,),
            ).fetchone()[0]

        # Consent rate: active / total * 100
        consent_rate = round(active_consents / total_consents * 100, 1) if total_consents > 0 else 0.0

        # Compliance score 0-100:
        # 50 points for having at least one active processing activity
        # 50 points for consent coverage (consent_rate / 100 * 50)
        score = 0.0
        if active_activities > 0:
            score += 50.0
        score += (consent_rate / 100.0) * 50.0
        compliance_score = round(min(score, 100.0), 1)

        return {
            "total_activities": total_activities,
            "active_activities": active_activities,
            "activities_by_basis": activities_by_basis,
            "total_consents": total_consents,
            "active_consents": active_consents,
            "withdrawn_consents": withdrawn_consents,
            "consent_rate": consent_rate,
            "compliance_score": compliance_score,
        }
